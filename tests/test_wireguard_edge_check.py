from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_wireguard_edge.sh"
PUBLIC_IP_HELPER = REPO_ROOT / "scripts" / "lib" / "public_ipv4.sh"


def _write_configs(tmp_path: Path) -> tuple[Path, Path]:
    server = tmp_path / "server.conf"
    client = tmp_path / "client.conf"
    server.write_text(
        textwrap.dedent(
            """
            [Interface]
            Address = 10.99.0.1/24
            ListenPort = 51821
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
            Endpoint = 203.0.113.47:51821
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
            "SHORT_CIRCUIT_TEST_PUBLIC_INTERFACE": "enp5s0",
            "SHORT_CIRCUIT_TEST_PUBLIC_IPV4": "203.0.113.47",
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
    assert "required_router_forward: UDP 51821 -> 192.168.0.6:51821" in result.stdout
    assert "public_ipv4_interface: enp5s0 (main-table default)" in result.stdout
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
    assert "required_router_forward: UDP 51821 -> 192.168.0.6:51821" in result.stdout


def test_public_ip_lookup_binds_curl_to_main_table_default(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ip = bin_dir / "ip"
    ip.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$*\" > \"$SHORT_CIRCUIT_TEST_IP_ARGS\"\n"
        "printf '%s\\n' 'default via 192.0.2.1 dev enp5s0 proto dhcp'\n",
        encoding="utf-8",
    )
    curl = bin_dir / "curl"
    curl.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$*\" > \"$SHORT_CIRCUIT_TEST_CURL_ARGS\"\n"
        "printf '%s\\n' '203.0.113.47'\n",
        encoding="utf-8",
    )
    ip.chmod(0o755)
    curl.chmod(0o755)
    env = os.environ.copy()
    env.pop("SHORT_CIRCUIT_TEST_PUBLIC_INTERFACE", None)
    env.pop("SHORT_CIRCUIT_TEST_PUBLIC_IPV4", None)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["SHORT_CIRCUIT_TEST_IP_ARGS"] = str(tmp_path / "ip-args")
    env["SHORT_CIRCUIT_TEST_CURL_ARGS"] = str(tmp_path / "curl-args")

    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; interface="$(detect_main_table_default_interface)"; '
            'detect_public_ipv4 "$interface"',
            "test-public-ip",
            str(PUBLIC_IP_HELPER),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "203.0.113.47"
    assert (tmp_path / "ip-args").read_text(encoding="utf-8").strip() == (
        "-4 route show table main default"
    )
    curl_args = (tmp_path / "curl-args").read_text(encoding="utf-8")
    assert "--interface enp5s0" in curl_args
    assert "https://api.ipify.org" in curl_args
