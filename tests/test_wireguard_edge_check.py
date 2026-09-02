from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_wireguard_edge.sh"


def _write_configs(tmp_path: Path) -> tuple[Path, Path]:
    server = tmp_path / "server.conf"
    client = tmp_path / "client.conf"
    server.write_text(
        textwrap.dedent(
            """
            [Interface]
            Address = 10.99.0.1/24
            ListenPort = 41194
            """
        ).lstrip(),
        encoding="utf-8",
    )
    client.write_text(
        textwrap.dedent(
            """
            [Interface]
            Address = 10.99.0.3/32

            [Peer]
            Endpoint = 68.41.12.47:41194
            AllowedIPs = 10.99.0.1/32
            """
        ).lstrip(),
        encoding="utf-8",
    )
    return server, client


def _run(args: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "SHORT_CIRCUIT_TEST_LAN_IPV4": "192.168.0.6",
            "SHORT_CIRCUIT_TEST_PUBLIC_IPV4": "68.41.12.47",
        }
    )
    return env


def test_reports_required_router_forward_for_current_lan_ip(tmp_path: Path) -> None:
    server, client = _write_configs(tmp_path)

    result = _run(
        ["--server-config", str(server), "--client-config", str(client)],
        env=_env(),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "current_host_lan_ipv4: 192.168.0.6" in result.stdout
    assert "required_router_forward: UDP 41194 -> 192.168.0.6:41194" in result.stdout
    assert "public_endpoint_state: matches current public IPv4" in result.stdout


def test_expected_router_target_mismatch_fails(tmp_path: Path) -> None:
    server, client = _write_configs(tmp_path)

    result = _run(
        [
            "--server-config",
            str(server),
            "--client-config",
            str(client),
            "--expected-router-target",
            "192.168.0.7",
        ],
        env=_env(),
    )

    assert result.returncode == 1
    assert "expected router target 192.168.0.7" in result.stderr
    assert "current host LAN IPv4 is 192.168.0.6" in result.stderr


def test_lan_interface_option_reports_selected_interface(tmp_path: Path) -> None:
    server, client = _write_configs(tmp_path)

    result = _run(
        [
            "--server-config",
            str(server),
            "--client-config",
            str(client),
            "--lan-interface",
            "enp5s0",
            "--skip-public-ip",
        ],
        env=_env(),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "lan_interface: enp5s0" in result.stdout
    assert "required_router_forward: UDP 41194 -> 192.168.0.6:41194" in result.stdout
