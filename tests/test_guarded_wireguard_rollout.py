from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "guarded_wireguard_rollout.sh"
PEER_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
PEER_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="


def _write_fake_bin(path: Path, name: str, body: str) -> None:
    target = path / name
    target.write_text(body, encoding="utf-8")
    target.chmod(0o755)


def _env(fake_bin: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "SHORT_CIRCUIT_TEST_ALLOW_NONROOT": "1",
            "SHORT_CIRCUIT_TEST_ALLOW_USER_STATE": "1",
        }
    )
    if extra:
        env.update(extra)
    return env


def _run(tmp_path: Path, args: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _metadata(state_root: Path, *, apply_epoch: int, timeout: int, peers: str) -> None:
    state_dir = state_root / "wg0"
    state_dir.mkdir(parents=True)
    (state_dir / "rollout.env").write_text(
        textwrap.dedent(
            f"""
            STATE_VERSION=1
            INTERFACE=wg0
            CONFIG_PATH={state_dir / 'active.conf'}
            STATE_ROOT={state_root}
            APPLY_EPOCH={apply_epoch}
            TIMEOUT_SECONDS={timeout}
            REQUIRE_ALL_PEERS=0
            REQUIRED_PEERS={peers!r}
            STATUS=pending
            """
        ).lstrip(),
        encoding="utf-8",
    )
    (state_dir / "rollout.env").chmod(0o600)


def test_apply_extracts_candidate_peers_and_arms_systemd_guard(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "commands.log"
    state_root = tmp_path / "state"
    active = tmp_path / "wg0.conf"
    candidate = tmp_path / "candidate.conf"
    active.write_text("old config\n", encoding="utf-8")
    candidate.write_text(
        textwrap.dedent(
            f"""
            [Interface]
            Address = 10.99.0.1/24

            [Peer]
            PublicKey = {PEER_A}
            AllowedIPs = 10.99.0.2/32
            """
        ).lstrip(),
        encoding="utf-8",
    )
    _write_fake_bin(fake_bin, "wg", "#!/usr/bin/env bash\nexit 0\n")
    # Freeze time so APPLY_EPOCH (captured at apply) and the later `date +%s`
    # read in remaining_timeout_seconds() land in the same second. Without this
    # the armed guard is `--on-active=<1800 minus elapsed>s`, and the exact
    # 1800s assertion below fails whenever a 1-second tick falls between them.
    _write_fake_bin(
        fake_bin,
        "date",
        '#!/usr/bin/env bash\n'
        'if [[ "$1" == "+%s" ]]; then echo 1700000000; else echo 20231114T000000; fi\n',
    )
    _write_fake_bin(
        fake_bin,
        "systemctl",
        f"#!/usr/bin/env bash\nprintf 'systemctl %s\\n' \"$*\" >> {log}\n",
    )
    _write_fake_bin(
        fake_bin,
        "systemd-run",
        f"#!/usr/bin/env bash\nprintf 'systemd-run %s\\n' \"$*\" >> {log}\n",
    )

    result = _run(
        tmp_path,
        [
            "--apply",
            "--candidate",
            str(candidate),
            "--config",
            str(active),
            "--state-root",
            str(state_root),
            "--timeout-seconds",
            "1800",
        ],
        env=_env(fake_bin),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert active.read_text(encoding="utf-8") == candidate.read_text(encoding="utf-8")
    metadata = (state_root / "wg0" / "rollout.env").read_text(encoding="utf-8")
    assert PEER_A in metadata
    assert "TIMEOUT_SECONDS=1800" in metadata
    command_log = log.read_text(encoding="utf-8")
    assert "systemctl restart wg-quick@wg0.service" in command_log
    assert "--on-active=1800s" in command_log
    assert "--unit=short-circuit-wg0-rollback-guard-" in command_log
    assert "--unit=short-circuit-wg0-rollback-guard " not in command_log


def test_apply_restores_previous_config_when_restart_fails(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "commands.log"
    state_root = tmp_path / "state"
    active = tmp_path / "wg0.conf"
    candidate = tmp_path / "candidate.conf"
    active.write_text("old config\n", encoding="utf-8")
    candidate.write_text(
        textwrap.dedent(
            f"""
            [Interface]
            Address = 10.99.0.1/24

            [Peer]
            PublicKey = {PEER_A}
            AllowedIPs = 10.99.0.2/32
            """
        ).lstrip(),
        encoding="utf-8",
    )
    _write_fake_bin(fake_bin, "wg", "#!/usr/bin/env bash\nexit 0\n")
    _write_fake_bin(
        fake_bin,
        "systemctl",
        f"""#!/usr/bin/env bash
count_file={tmp_path / 'restart_count'}
count=0
if [[ -f "${{count_file}}" ]]; then
  count=$(<"${{count_file}}")
fi
count=$((count + 1))
printf '%s' "${{count}}" > "${{count_file}}"
printf 'systemctl %s\n' "$*" >> {log}
if (( count == 1 )); then
  exit 1
fi
exit 0
""",
    )
    _write_fake_bin(
        fake_bin,
        "systemd-run",
        f"""#!/usr/bin/env bash
printf 'systemd-run %s\n' "$*" >> {log}
""",
    )

    result = _run(
        tmp_path,
        [
            "--apply",
            "--candidate",
            str(candidate),
            "--config",
            str(active),
            "--state-root",
            str(state_root),
        ],
        env=_env(fake_bin),
    )

    assert result.returncode == 1
    assert active.read_text(encoding="utf-8") == "old config\n"
    assert "failed-rolled-back" in (state_root / "wg0" / "rollout.env").read_text(
        encoding="utf-8"
    )
    assert "systemd-run" not in log.read_text(encoding="utf-8")


def test_apply_archives_completed_rollout_state_before_new_apply(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "commands.log"
    state_root = tmp_path / "state"
    state_dir = state_root / "wg0"
    _metadata(state_root, apply_epoch=100, timeout=1800, peers=PEER_A)
    metadata = state_dir / "rollout.env"
    metadata.write_text(
        metadata.read_text(encoding="utf-8").replace("STATUS=pending", "STATUS=rolled-back"),
        encoding="utf-8",
    )
    active = state_dir / "active.conf"
    candidate = tmp_path / "candidate.conf"
    active.write_text("old config\n", encoding="utf-8")
    (state_dir / "previous.conf").write_text("previous config\n", encoding="utf-8")
    (state_dir / "candidate.conf").write_text("old candidate\n", encoding="utf-8")
    candidate.write_text(
        textwrap.dedent(
            f"""
            [Interface]
            Address = 10.99.0.1/24

            [Peer]
            PublicKey = {PEER_B}
            AllowedIPs = 10.99.0.3/32
            """
        ).lstrip(),
        encoding="utf-8",
    )
    _write_fake_bin(fake_bin, "wg", "#!/usr/bin/env bash\nexit 0\n")
    _write_fake_bin(
        fake_bin,
        "systemctl",
        f"""#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> {log}
""",
    )
    _write_fake_bin(
        fake_bin,
        "systemd-run",
        f"""#!/usr/bin/env bash
printf 'systemd-run %s\n' "$*" >> {log}
""",
    )

    result = _run(
        tmp_path,
        [
            "--apply",
            "--candidate",
            str(candidate),
            "--config",
            str(active),
            "--state-root",
            str(state_root),
        ],
        env=_env(fake_bin),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert active.read_text(encoding="utf-8") == candidate.read_text(encoding="utf-8")
    assert "archived prior rolled-back rollout state" in result.stdout
    assert list((state_dir / "archive").glob("*-rolled-back/rollout.env"))
    assert PEER_B in (state_dir / "rollout.env").read_text(encoding="utf-8")


def test_arm_guard_schedules_existing_pending_rollout(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "commands.log"
    state_root = tmp_path / "state"
    _metadata(state_root, apply_epoch=9999999999, timeout=1800, peers=PEER_A)
    _write_fake_bin(fake_bin, "wg", "#!/usr/bin/env bash\nexit 0\n")
    _write_fake_bin(
        fake_bin,
        "systemd-run",
        f"""#!/usr/bin/env bash
printf 'systemd-run %s\n' "$*" >> {log}
""",
    )

    result = _run(tmp_path, ["--arm-guard", "--state-root", str(state_root)], env=_env(fake_bin))

    assert result.returncode == 0, result.stdout + result.stderr
    command_log = log.read_text(encoding="utf-8")
    assert "--unit=short-circuit-wg0-rollback-guard-9999999999" in command_log
    assert "--verify-or-rollback --interface wg0" in command_log
    assert "armed rollback guard" in result.stdout


def test_verify_marks_success_after_fresh_required_handshake(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    state_root = tmp_path / "state"
    _metadata(state_root, apply_epoch=100, timeout=1800, peers=PEER_A)
    _write_fake_bin(
        fake_bin,
        "wg",
        f"#!/usr/bin/env bash\nprintf '%s %s\\n' {PEER_A} 101\n",
    )

    result = _run(tmp_path, ["--verify", "--state-root", str(state_root)], env=_env(fake_bin))

    assert result.returncode == 0, result.stdout + result.stderr
    assert "rollout succeeded" in result.stdout
    assert "STATUS=succeeded" in (state_root / "wg0" / "rollout.env").read_text(
        encoding="utf-8"
    )


def test_verify_or_rollback_restores_previous_config_after_deadline(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "commands.log"
    state_root = tmp_path / "state"
    _metadata(state_root, apply_epoch=1, timeout=1, peers=PEER_A)
    state_dir = state_root / "wg0"
    active = state_dir / "active.conf"
    previous = state_dir / "previous.conf"
    active.write_text("candidate config\n", encoding="utf-8")
    previous.write_text("previous config\n", encoding="utf-8")
    previous.chmod(0o600)
    _write_fake_bin(
        fake_bin,
        "wg",
        f"#!/usr/bin/env bash\nprintf '%s %s\\n' {PEER_A} 0\n",
    )
    _write_fake_bin(
        fake_bin,
        "systemctl",
        f"#!/usr/bin/env bash\nprintf 'systemctl %s\\n' \"$*\" >> {log}\n",
    )

    result = _run(
        tmp_path,
        ["--verify-or-rollback", "--state-root", str(state_root)],
        env=_env(fake_bin),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert active.read_text(encoding="utf-8") == "previous config\n"
    assert "rollback applied" in result.stdout
    assert "STATUS=rolled-back" in (state_root / "wg0" / "rollout.env").read_text(
        encoding="utf-8"
    )
    assert "systemctl restart wg-quick@wg0.service" in log.read_text(encoding="utf-8")


def test_option_values_are_required(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    result = _run(tmp_path, ["--interface"], env=_env(fake_bin))

    assert result.returncode == 1
    assert "--interface requires a value" in result.stderr


# -- listen-port changes and the host firewall ------------------------------


def _config(port: int | None) -> str:
    listen = f"ListenPort = {port}\n" if port is not None else ""
    return (
        "[Interface]\n"
        "Address = 10.99.0.1/24\n"
        f"{listen}"
        "\n[Peer]\n"
        f"PublicKey = {PEER_A}\n"
        "AllowedIPs = 10.99.0.2/32\n"
    )


def _port_change_bin(tmp_path: Path, *, open_ports: str, fail_add: bool = False) -> tuple[Path, Path]:
    """Fake tools that log every call; firewall-cmd answers --query-port from a list."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "commands.log"
    log.write_text("", encoding="utf-8")
    _write_fake_bin(fake_bin, "wg", f"#!/usr/bin/env bash\nprintf '%s %s\\n' {PEER_A} 1700000001\n")
    _write_fake_bin(
        fake_bin,
        "date",
        '#!/usr/bin/env bash\n'
        'if [[ "$1" == "+%s" ]]; then echo 1700000000; else echo 20231114T000000; fi\n',
    )
    for name in ("systemctl", "systemd-run"):
        _write_fake_bin(
            fake_bin, name, f"#!/usr/bin/env bash\nprintf '{name} %s\\n' \"$*\" >> {log}\n"
        )
    add_status = "1" if fail_add else "0"
    _write_fake_bin(
        fake_bin,
        "firewall-cmd",
        "#!/usr/bin/env bash\n"
        f"printf 'firewall-cmd %s\\n' \"$*\" >> {log}\n"
        'for arg in "$@"; do\n'
        '  case "$arg" in\n'
        '    --query-port=*)\n'
        '      port="${arg#--query-port=}"\n'
        f'      case " {open_ports} " in *" $port "*) exit 0 ;; *) exit 1 ;; esac ;;\n'
        f'    --add-port=*) exit {add_status} ;;\n'
        '  esac\n'
        'done\n'
        'exit 0\n',
    )
    return fake_bin, log


def _apply_port_change(
    tmp_path: Path, fake_bin: Path, *, old: int | None, new: int | None, zone: str | None
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    state_root = tmp_path / "state"
    active = tmp_path / "wg0.conf"
    candidate = tmp_path / "candidate.conf"
    active.write_text(_config(old), encoding="utf-8")
    candidate.write_text(_config(new), encoding="utf-8")
    args = [
        "--apply",
        "--candidate",
        str(candidate),
        "--config",
        str(active),
        "--state-root",
        str(state_root),
    ]
    if zone is not None:
        args += ["--public-zone", zone]
    return _run(tmp_path, args, env=_env(fake_bin)), state_root, active


def _firewall_metadata(state_root: Path, *, added: int, apply_epoch: int, timeout: int) -> Path:
    _metadata(state_root, apply_epoch=apply_epoch, timeout=timeout, peers=PEER_A)
    path = state_root / "wg0" / "rollout.env"
    text = path.read_text(encoding="utf-8").replace(
        "STATUS=pending",
        "FIREWALL_ZONE=public\nFIREWALL_OLD_PORT=51820\nFIREWALL_NEW_PORT=45000\n"
        f"FIREWALL_NEW_PORT_ADDED={added}\nSTATUS=pending",
    )
    path.write_text(text, encoding="utf-8")
    return path


def test_apply_opens_new_port_before_switching_and_keeps_old_port(tmp_path: Path) -> None:
    fake_bin, log = _port_change_bin(tmp_path, open_ports="51820/udp")

    result, state_root, _ = _apply_port_change(tmp_path, fake_bin, old=51820, new=45000, zone="public")

    assert result.returncode == 0, result.stdout + result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    permanent_add = calls.index("firewall-cmd --permanent --zone=public --add-port=45000/udp")
    runtime_add = calls.index("firewall-cmd --zone=public --add-port=45000/udp")
    restart = calls.index("systemctl restart wg-quick@wg0.service")
    assert permanent_add < runtime_add < restart
    assert not any("--remove-port" in call for call in calls)
    assert not any("--reload" in call for call in calls)
    metadata = (state_root / "wg0" / "rollout.env").read_text(encoding="utf-8")
    assert "FIREWALL_ZONE=public" in metadata
    assert "FIREWALL_OLD_PORT=51820" in metadata
    assert "FIREWALL_NEW_PORT=45000" in metadata
    assert "FIREWALL_NEW_PORT_ADDED=1" in metadata
    assert "udp/51820 stays open" in result.stdout


def test_apply_does_not_claim_a_port_that_was_already_open(tmp_path: Path) -> None:
    fake_bin, log = _port_change_bin(tmp_path, open_ports="51820/udp 45000/udp")

    result, state_root, _ = _apply_port_change(tmp_path, fake_bin, old=51820, new=45000, zone="public")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "--add-port" not in log.read_text(encoding="utf-8")
    metadata = (state_root / "wg0" / "rollout.env").read_text(encoding="utf-8")
    assert "FIREWALL_NEW_PORT_ADDED=0" in metadata


def test_apply_warns_and_leaves_firewall_alone_without_public_zone(tmp_path: Path) -> None:
    fake_bin, log = _port_change_bin(tmp_path, open_ports="51820/udp")

    result, state_root, _ = _apply_port_change(tmp_path, fake_bin, old=51820, new=45000, zone=None)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "host firewall is not managed" in result.stdout
    assert "firewall-cmd" not in log.read_text(encoding="utf-8")
    assert "FIREWALL_ZONE=''" in (state_root / "wg0" / "rollout.env").read_text(encoding="utf-8")


def test_apply_ignores_public_zone_when_the_port_does_not_change(tmp_path: Path) -> None:
    fake_bin, log = _port_change_bin(tmp_path, open_ports="51820/udp")

    result, _, _ = _apply_port_change(tmp_path, fake_bin, old=51820, new=51820, zone="public")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "firewall-cmd" not in log.read_text(encoding="utf-8")


def test_apply_aborts_before_changing_config_when_port_cannot_be_opened(tmp_path: Path) -> None:
    fake_bin, log = _port_change_bin(tmp_path, open_ports="51820/udp", fail_add=True)

    result, state_root, active = _apply_port_change(
        tmp_path, fake_bin, old=51820, new=45000, zone="public"
    )

    assert result.returncode == 1
    assert "config not changed" in result.stderr
    assert active.read_text(encoding="utf-8") == _config(51820)
    assert "systemctl restart" not in log.read_text(encoding="utf-8")
    assert "STATUS=failed-firewall" in (state_root / "wg0" / "rollout.env").read_text(
        encoding="utf-8"
    )


def test_invalid_public_zone_is_rejected(tmp_path: Path) -> None:
    fake_bin, log = _port_change_bin(tmp_path, open_ports="")

    result, _, _ = _apply_port_change(tmp_path, fake_bin, old=51820, new=45000, zone="public;rm")

    assert result.returncode == 1
    assert "invalid firewalld zone" in result.stderr
    assert log.read_text(encoding="utf-8") == ""


def test_success_removes_old_port_only_after_fresh_handshake(tmp_path: Path) -> None:
    fake_bin, log = _port_change_bin(tmp_path, open_ports="51820/udp 45000/udp")
    state_root = tmp_path / "state"
    _firewall_metadata(state_root, added=1, apply_epoch=1699999000, timeout=1800)

    result = _run(tmp_path, ["--verify", "--state-root", str(state_root)], env=_env(fake_bin))

    assert result.returncode == 0, result.stdout + result.stderr
    calls = log.read_text(encoding="utf-8")
    assert "firewall-cmd --permanent --zone=public --remove-port=51820/udp" in calls
    assert "firewall-cmd --zone=public --remove-port=51820/udp" in calls
    assert "--remove-port=45000/udp" not in calls
    assert "removed old udp/51820" in result.stdout
    assert "STATUS=succeeded" in (state_root / "wg0" / "rollout.env").read_text(encoding="utf-8")


def test_pending_verify_never_touches_the_firewall(tmp_path: Path) -> None:
    fake_bin, log = _port_change_bin(tmp_path, open_ports="51820/udp 45000/udp")
    state_root = tmp_path / "state"
    # Applied "after" the only handshake the fake wg reports: still pending.
    _firewall_metadata(state_root, added=1, apply_epoch=1700000000 - 10, timeout=1800)
    _write_fake_bin(fake_bin, "wg", f"#!/usr/bin/env bash\nprintf '%s %s\\n' {PEER_A} 0\n")

    result = _run(tmp_path, ["--verify", "--state-root", str(state_root)], env=_env(fake_bin))

    assert result.returncode == 1
    assert "firewall-cmd" not in log.read_text(encoding="utf-8")


def _rollback_after_deadline(tmp_path: Path, *, added: int) -> tuple[subprocess.CompletedProcess[str], str]:
    fake_bin, log = _port_change_bin(tmp_path, open_ports="51820/udp 45000/udp")
    state_root = tmp_path / "state"
    _firewall_metadata(state_root, added=added, apply_epoch=1, timeout=1)
    state_dir = state_root / "wg0"
    (state_dir / "active.conf").write_text(_config(45000), encoding="utf-8")
    previous = state_dir / "previous.conf"
    previous.write_text(_config(51820), encoding="utf-8")
    previous.chmod(0o600)
    _write_fake_bin(fake_bin, "wg", f"#!/usr/bin/env bash\nprintf '%s %s\\n' {PEER_A} 0\n")
    result = _run(
        tmp_path, ["--verify-or-rollback", "--state-root", str(state_root)], env=_env(fake_bin)
    )
    assert (state_dir / "active.conf").read_text(encoding="utf-8") == _config(51820)
    return result, log.read_text(encoding="utf-8")


def test_rollback_removes_the_new_port_this_rollout_added(tmp_path: Path) -> None:
    result, calls = _rollback_after_deadline(tmp_path, added=1)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "firewall-cmd --permanent --zone=public --remove-port=45000/udp" in calls
    assert "firewall-cmd --zone=public --remove-port=45000/udp" in calls
    assert "--remove-port=51820/udp" not in calls
    assert calls.index("systemctl restart wg-quick@wg0.service") < calls.index("--remove-port=45000")


def test_rollback_leaves_a_port_it_did_not_add(tmp_path: Path) -> None:
    result, calls = _rollback_after_deadline(tmp_path, added=0)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "--remove-port" not in calls


def test_metadata_without_firewall_fields_still_loads(tmp_path: Path) -> None:
    fake_bin, log = _port_change_bin(tmp_path, open_ports="51820/udp")
    state_root = tmp_path / "state"
    _metadata(state_root, apply_epoch=1699999000, timeout=1800, peers=PEER_A)

    result = _run(tmp_path, ["--verify", "--state-root", str(state_root)], env=_env(fake_bin))

    assert result.returncode == 0, result.stdout + result.stderr
    assert "firewall-cmd" not in log.read_text(encoding="utf-8")
