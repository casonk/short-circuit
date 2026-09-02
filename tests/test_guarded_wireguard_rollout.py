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
    assert "systemctl restart wg-quick@wg0.service" in log.read_text(encoding="utf-8")
    assert "--on-active=1800s" in log.read_text(encoding="utf-8")


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
