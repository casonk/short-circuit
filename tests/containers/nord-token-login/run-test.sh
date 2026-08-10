#!/bin/sh

set -eu

test_token='v1.Sample_TOKEN-+~AZ09'
install -d -o root -g root -m 0700 /run/secrets
printf '%s\n' "$test_token" > /run/secrets/nordvpn-token
chmod 0400 /run/secrets/nordvpn-token

/usr/local/sbin/nord-token-login > /tmp/broker.out 2>&1 &
broker_pid=$!

sleep 0.5
broker_cmd=$(tr '\000' ' ' < "/proc/$broker_pid/cmdline")
broker_env=$({ tr '\000' '\n' < "/proc/$broker_pid/environ"; } 2>/dev/null || true)
case "$broker_cmd" in
    *"$test_token"*)
        echo "token exposed in broker argv" >&2
        exit 1
        ;;
esac
case "$broker_env" in
    *"$test_token"*)
        echo "token exposed in broker environment" >&2
        exit 1
        ;;
esac

child_pid=$(pgrep -P "$broker_pid" -x nordvpn | head -n 1)
child_cmd=$(tr '\000' ' ' < "/proc/$child_pid/cmdline")
child_env=$({ tr '\000' '\n' < "/proc/$child_pid/environ"; } 2>/dev/null || true)
case "$child_cmd" in
    *"$test_token"*)
        echo "token exposed in CLI argv" >&2
        exit 1
        ;;
esac
case "$child_env" in
    *"$test_token"*)
        echo "token exposed in CLI environment" >&2
        exit 1
        ;;
esac

wait "$broker_pid"
if grep -F "$test_token" /tmp/broker.out >/dev/null; then
    echo "token escaped through broker output" >&2
    exit 1
fi

# Exercise the distinct already-reaped child-failure branch. The broker must
# report only a generic failure and must not hang or try to re-signal that PID.
failed_token='valid-printable-but-rejected'
printf '%s\n' "$failed_token" > /run/secrets/nordvpn-token
if /usr/local/sbin/nord-token-login > /tmp/rejected.out 2>&1; then
    echo "broker accepted a token rejected by the CLI" >&2
    exit 1
fi
if grep -F "$failed_token" /tmp/rejected.out >/dev/null; then
    echo "rejected token escaped through broker output" >&2
    exit 1
fi
echo "PTY token handoff passed"
