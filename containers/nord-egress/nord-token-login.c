#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define NORDVPN_PATH "/usr/bin/nordvpn"
#define SECRET_PATH "/run/secrets/nordvpn-token"
#define TOKEN_PROMPT "Enter access token: "
#define MAX_TOKEN_LENGTH 1024U
#define MAX_PREPROMPT_BYTES 65536U
#define PROMPT_TIMEOUT_MS 30000
#define LOGIN_TIMEOUT_MS 60000

enum login_wait_result {
    LOGIN_WAIT_SUCCESS = 0,
    LOGIN_WAIT_REAPED_FAILURE = 1,
    LOGIN_WAIT_UNREAPED_ERROR = -1,
};

static const char prompt[] = TOKEN_PROMPT;

static int64_t now_ms(void)
{
    struct timespec time_value;

    if (clock_gettime(CLOCK_MONOTONIC, &time_value) != 0) {
        return -1;
    }
    return (int64_t)time_value.tv_sec * 1000 + time_value.tv_nsec / 1000000;
}

static void wipe(void *memory, size_t length)
{
    volatile unsigned char *cursor = memory;

    while (length-- > 0U) {
        *cursor++ = 0U;
    }
}

static bool ascii_space(unsigned char value)
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n' ||
           value == '\v' || value == '\f';
}

static int validate_cli(int *descriptor)
{
    struct stat status;
    int fd = open(NORDVPN_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) || status.st_uid != 0 ||
        (status.st_mode & 0022) != 0 || (status.st_mode & 0111) == 0) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    *descriptor = fd;
    return 0;
}

static int read_secret(unsigned char token[MAX_TOKEN_LENGTH + 3U], size_t *token_length)
{
    struct stat status;
    size_t used = 0U;
    int fd = open(SECRET_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) || status.st_uid != 0 ||
        (status.st_mode & 0077) != 0 || status.st_size < 1 ||
        status.st_size > (off_t)(MAX_TOKEN_LENGTH + 2U)) {
        close(fd);
        errno = EPERM;
        return -1;
    }

    while (used < MAX_TOKEN_LENGTH + 3U) {
        ssize_t count = read(fd, token + used, MAX_TOKEN_LENGTH + 3U - used);

        if (count > 0) {
            used += (size_t)count;
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno != EINTR) {
            close(fd);
            return -1;
        }
    }
    close(fd);

    size_t start = 0U;
    while (start < used && ascii_space(token[start])) {
        ++start;
    }
    size_t end = used;
    while (end > start && ascii_space(token[end - 1U])) {
        --end;
    }
    size_t length = end - start;
    if (length == 0U || length > MAX_TOKEN_LENGTH) {
        errno = EINVAL;
        return -1;
    }
    for (size_t index = start; index < end; ++index) {
        unsigned char value = token[index];

        /* PTY controls are unsafe; let the pinned daemon validate the exact
         * future-proof printable token alphabet. */
        if (value < 0x21 || value > 0x7e) {
            errno = EINVAL;
            return -1;
        }
    }
    if (start != 0U) {
        memmove(token, token + start, length);
    }
    if (length < MAX_TOKEN_LENGTH + 3U) {
        wipe(token + length, MAX_TOKEN_LENGTH + 3U - length);
    }
    *token_length = length;
    return 0;
}

static int child_exited(pid_t child)
{
    siginfo_t information;

    memset(&information, 0, sizeof(information));
    if (waitid(P_PID, (id_t)child, &information, WEXITED | WNOHANG | WNOWAIT) != 0) {
        return errno == EINTR ? 0 : -1;
    }
    return information.si_pid == child ? 1 : 0;
}

static int wait_for_prompt(int master, pid_t child, int64_t deadline)
{
    unsigned char buffer[1024];
    size_t matched = 0U;
    size_t seen = 0U;

    while (now_ms() >= 0 && now_ms() < deadline && seen < MAX_PREPROMPT_BYTES) {
        struct pollfd poll_descriptor = {.fd = master, .events = POLLIN};
        int exited = child_exited(child);
        int ready;
        ssize_t count;

        if (exited != 0) {
            return -1;
        }
        ready = poll(&poll_descriptor, 1, 50);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (ready == 0) {
            continue;
        }
        count = read(master, buffer, sizeof(buffer));
        if (count < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (count == 0) {
            return -1;
        }
        for (ssize_t index = 0; index < count; ++index) {
            unsigned char value = buffer[index];

            ++seen;
            if (value == (unsigned char)prompt[matched]) {
                ++matched;
                if (matched == sizeof(prompt) - 1U) {
                    return 0;
                }
            } else {
                matched = value == (unsigned char)prompt[0] ? 1U : 0U;
            }
        }
    }
    errno = ETIMEDOUT;
    return -1;
}

static int wait_for_no_echo(int master, pid_t child, int64_t deadline)
{
    while (now_ms() >= 0 && now_ms() < deadline) {
        struct termios terminal;
        int exited = child_exited(child);

        if (exited != 0) {
            return -1;
        }
        if (tcgetattr(master, &terminal) == 0) {
            if ((terminal.c_lflag & (ECHO | ECHONL)) == 0) {
                return 0;
            }
        } else if (errno != EINTR) {
            return -1;
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
        (void)nanosleep(&pause, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int write_all(int descriptor, const unsigned char *data, size_t length,
                     int64_t deadline)
{
    size_t written = 0U;

    while (written < length && now_ms() >= 0 && now_ms() < deadline) {
        ssize_t count = write(descriptor, data + written, length - written);

        if (count > 0) {
            written += (size_t)count;
            continue;
        }
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            struct pollfd poll_descriptor = {.fd = descriptor, .events = POLLOUT};
            (void)poll(&poll_descriptor, 1, 50);
            continue;
        }
        return -1;
    }
    if (written != length) {
        errno = ETIMEDOUT;
        return -1;
    }
    return 0;
}

static int discard_and_wait(int master, pid_t child, int64_t deadline)
{
    unsigned char discard[2048];

    for (;;) {
        struct pollfd poll_descriptor = {.fd = master, .events = POLLIN};
        int status;
        pid_t completed;
        int ready;

        do {
            completed = waitpid(child, &status, WNOHANG);
        } while (completed < 0 && errno == EINTR);
        if (completed == child) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0
                       ? LOGIN_WAIT_SUCCESS
                       : LOGIN_WAIT_REAPED_FAILURE;
        }
        if (completed < 0 || now_ms() < 0 || now_ms() >= deadline) {
            errno = ETIMEDOUT;
            return LOGIN_WAIT_UNREAPED_ERROR;
        }
        ready = poll(&poll_descriptor, 1, 50);
        if (ready > 0) {
            while (read(master, discard, sizeof(discard)) > 0) {
            }
        } else if (ready < 0 && errno != EINTR) {
            return LOGIN_WAIT_UNREAPED_ERROR;
        }
    }
}

static void terminate_child(pid_t child)
{
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
}

int main(int argc, char **argv)
{
    int cli_descriptor;
    int master;
    pid_t child;
    pid_t parent;
    int flags;
    int64_t prompt_deadline;
    int64_t login_deadline;
    struct rlimit no_core = {.rlim_cur = 0, .rlim_max = 0};
    unsigned char token[MAX_TOKEN_LENGTH + 3U] = {0};
    size_t token_length = 0U;

    (void)argv;
    if (argc != 1 || geteuid() != 0) {
        fputs("nord-token-login: invalid invocation\n", stderr);
        return EXIT_FAILURE;
    }
    if (validate_cli(&cli_descriptor) != 0) {
        fputs("nord-token-login: invalid NordVPN CLI\n", stderr);
        return EXIT_FAILURE;
    }

    parent = getpid();
    child = forkpty(&master, NULL, NULL, NULL);
    if (child < 0) {
        close(cli_descriptor);
        fputs("nord-token-login: unable to start CLI\n", stderr);
        return EXIT_FAILURE;
    }
    if (child == 0) {
        char *child_argv[] = {"nordvpn", "login", "--token", NULL};
        char *child_env[] = {
            "HOME=/root", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8",
            "TERM=dumb", NULL,
        };

        (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != parent) {
            _exit(126);
        }
        (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        fexecve(cli_descriptor, child_argv, child_env);
        _exit(127);
    }
    close(cli_descriptor);

    flags = fcntl(master, F_GETFL, 0);
    if (flags < 0 || fcntl(master, F_SETFL, flags | O_NONBLOCK) != 0) {
        terminate_child(child);
        close(master);
        return EXIT_FAILURE;
    }

    prompt_deadline = now_ms() + PROMPT_TIMEOUT_MS;
    if (wait_for_prompt(master, child, prompt_deadline) != 0 ||
        wait_for_no_echo(master, child, prompt_deadline) != 0) {
        terminate_child(child);
        close(master);
        fputs("nord-token-login: secure token prompt unavailable\n", stderr);
        return EXIT_FAILURE;
    }
    if (setrlimit(RLIMIT_CORE, &no_core) != 0 ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        terminate_child(child);
        close(master);
        return EXIT_FAILURE;
    }
    if (read_secret(token, &token_length) != 0) {
        wipe(token, sizeof(token));
        terminate_child(child);
        close(master);
        fputs("nord-token-login: invalid token secret\n", stderr);
        return EXIT_FAILURE;
    }

    login_deadline = now_ms() + LOGIN_TIMEOUT_MS;
    int write_result = write_all(master, token, token_length, login_deadline);
    if (write_result == 0) {
        static const unsigned char newline = '\n';
        write_result = write_all(master, &newline, 1U, login_deadline);
    }
    wipe(token, sizeof(token));
    int wait_result = write_result == 0
                          ? discard_and_wait(master, child, login_deadline)
                          : LOGIN_WAIT_UNREAPED_ERROR;
    if (write_result != 0 || wait_result != LOGIN_WAIT_SUCCESS) {
        if (wait_result == LOGIN_WAIT_UNREAPED_ERROR) {
            terminate_child(child);
        }
        close(master);
        fputs("nord-token-login: token login failed\n", stderr);
        return EXIT_FAILURE;
    }

    close(master);
    return EXIT_SUCCESS;
}
