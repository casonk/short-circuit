from __future__ import annotations

import base64
import contextlib
import datetime as dt
import importlib.util
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "render_nord_egress_container.py"
SPEC = importlib.util.spec_from_file_location("render_nord_egress_container", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
nord_egress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nord_egress)

PUBLIC_A = base64.b64encode(bytes([0x11]) * 32).decode("ascii")
PUBLIC_B = base64.b64encode(bytes([0x22]) * 32).decode("ascii")
PUBLIC_C = base64.b64encode(bytes([0x33]) * 32).decode("ascii")
DEFAULT_EXPIRY = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)


def active_document() -> dict[str, object]:
    document = nord_egress.inert_document()
    document["generation"] = 1
    document["enabled"] = True
    document["gateway"]["authorized_source_addresses"] = ["10.99.0.241/32"]
    document["gateway"]["wireguard_interface"] = "mesh-hub"
    return document


def active_mesh_document() -> dict[str, object]:
    return {
        "schema_version": 2,
        "generation": 1,
        "mesh": {
            "name": "temporary-home",
            "subnet": "10.99.0.240/28",
            "listen_port": 51821,
            "peer_transit": False,
        },
        "failover_mode": "manual-static",
        "cutover_epoch": 1,
        "expires_at": DEFAULT_EXPIRY,
        "egress": {
            "mode": "nord-vpn",
            "gateway_node_id": "mesh-hub",
            "authorized_leaf_ids": ["mesh-leaf"],
            "dns_servers": ["103.86.96.100", "103.86.99.100"],
            "ipv6_policy": "block",
        },
        "nodes": [
            {
                "id": "mesh-hub",
                "role": "hub",
                "platform": "linux",
                "address": "10.99.0.254/32",
                "public_key": PUBLIC_A,
            },
            {
                "id": "mesh-leaf",
                "role": "leaf",
                "platform": "linux",
                "address": "10.99.0.241/32",
                "public_key": PUBLIC_B,
                "hub_transport": {
                    "mode": "direct",
                    "endpoint": "hub.example.com:51821",
                },
            },
        ],
    }


class NordEgressValidationTests(unittest.TestCase):
    def test_tracked_example_is_valid_and_inert(self) -> None:
        example_path = REPO_ROOT / "config" / "wireguard" / "nord-egress-container.example.json"
        document = json.loads(example_path.read_text(encoding="utf-8"))

        self.assertEqual(nord_egress.validate_document(document), nord_egress.inert_document())

    def test_active_contract_normalizes_without_a_credential(self) -> None:
        normalized = nord_egress.validate_document(active_document())

        self.assertEqual(normalized["target"]["os"], "linux")
        self.assertEqual(normalized["target"]["podman_scope"], "rootful")
        self.assertEqual(normalized["target"]["podman_min_version"], "5.8.0")
        self.assertEqual(normalized["gateway"]["crud_leadership"], "none")
        self.assertEqual(normalized["gateway"]["authorized_source_addresses"], ["10.99.0.241/32"])
        self.assertNotIn("token", normalized["gateway"])
        self.assertNotIn("password", normalized["gateway"])

        inert = nord_egress.validate_document(nord_egress.inert_document())
        self.assertEqual(inert["gateway"]["authorized_source_addresses"], [])

    def test_generation_and_enabled_state_are_fail_closed(self) -> None:
        enabled_zero = nord_egress.inert_document()
        enabled_zero["enabled"] = True
        disabled_active = active_document()
        disabled_active["enabled"] = False

        with self.assertRaisesRegex(nord_egress.NordEgressError, "generation 0"):
            nord_egress.validate_document(enabled_zero)
        with self.assertRaisesRegex(nord_egress.NordEgressError, "explicitly enabled"):
            nord_egress.validate_document(disabled_active)

        boolean_schema = active_document()
        boolean_schema["schema_version"] = True
        with self.assertRaisesRegex(nord_egress.NordEgressError, "schema_version"):
            nord_egress.validate_document(boolean_schema)

    def test_only_rootful_linux_quadlet_target_is_accepted(self) -> None:
        for field, value in (
            ("os", "darwin"),
            ("podman_scope", "rootless"),
            ("podman_min_version", "5.7.0"),
            ("quadlet_directory", "~/.config/containers/systemd"),
        ):
            with self.subTest(field=field):
                document = active_document()
                document["target"][field] = value
                with self.assertRaises(nord_egress.NordEgressError):
                    nord_egress.validate_document(document)

    def test_base_image_must_be_syntactically_digest_pinned_official_ubuntu(self) -> None:
        for image in (
            "ubuntu:24.04",
            "docker.io/library/ubuntu:24.04",
            "quay.io/example/ubuntu@sha256:" + "a" * 64,
            "docker.io/library/ubuntu@sha256:" + "0" * 64,
        ):
            with self.subTest(image=image):
                document = active_document()
                document["build"]["base_image"] = image
                with self.assertRaisesRegex(nord_egress.NordEgressError, "sha256 digest"):
                    nord_egress.validate_document(document)

        moving_package = active_document()
        moving_package["build"]["nordvpn_package_version"] = "latest"
        with self.assertRaisesRegex(nord_egress.NordEgressError, "5.2.0"):
            nord_egress.validate_document(moving_package)

    def test_credentials_cannot_be_added_to_the_json_contract(self) -> None:
        for field in ("token", "password", "username", "environment"):
            with self.subTest(field=field):
                document = active_document()
                document["gateway"][field] = "must-not-appear"
                with self.assertRaisesRegex(nord_egress.NordEgressError, "unsupported field"):
                    nord_egress.validate_document(document)

    def test_secret_target_network_mode_and_authority_are_fixed(self) -> None:
        cases = (
            ("podman_secret_target", "/tmp/token"),
            ("network_mode", "host"),
            ("fail_closed", False),
            ("ipv6_policy", "enabled"),
            ("crud_leadership", "automatic"),
        )
        for field, value in cases:
            with self.subTest(field=field):
                document = active_document()
                document["gateway"][field] = value
                with self.assertRaises(nord_egress.NordEgressError):
                    nord_egress.validate_document(document)

        leading_option = active_document()
        leading_option["gateway"]["nord_connect"] = "--group"
        with self.assertRaisesRegex(nord_egress.NordEgressError, "unsupported"):
            nord_egress.validate_document(leading_option)

    def test_interfaces_are_distinct_and_peer_transit_stays_disabled(self) -> None:
        invalid_changes = (
            ("bridge_interface", "interface-name-is-too-long"),
            ("wireguard_interface", "tcne0"),
            ("peer_transit", True),
        )
        for field, value in invalid_changes:
            with self.subTest(field=field):
                document = active_document()
                document["gateway"][field] = value
                with self.assertRaises(nord_egress.NordEgressError):
                    nord_egress.validate_document(document)

    def test_mesh_source_is_narrow_private_and_disjoint_from_bridge(self) -> None:
        for subnet in ("0.0.0.0/0", "203.0.113.0/24", "10.0.0.0/8"):
            with self.subTest(subnet=subnet):
                document = active_document()
                document["gateway"]["mesh_source_subnet"] = subnet
                with self.assertRaises(nord_egress.NordEgressError):
                    nord_egress.validate_document(document)

        overlap = active_document()
        overlap["gateway"]["bridge_subnet"] = "10.99.0.248/29"
        overlap["gateway"]["bridge_gateway"] = "10.99.0.249"
        overlap["gateway"]["bridge_address"] = "10.99.0.250"
        with self.assertRaisesRegex(nord_egress.NordEgressError, "must not overlap"):
            nord_egress.validate_document(overlap)

    def test_authorized_sources_are_exact_sorted_unique_leaf_addresses(self) -> None:
        invalid_lists = (
            [],
            ["10.99.0.239/32"],
            ["10.99.0.241/32", "10.99.0.241/32"],
            ["10.99.0.241/31"],
            ["10.99.0.242/32", "10.99.0.241/32"],
            ["010.099.000.241/32"],
            ["10.99.0.241/32"] * 257,
        )
        for addresses in invalid_lists:
            with self.subTest(addresses=addresses):
                document = active_document()
                document["gateway"]["authorized_source_addresses"] = addresses
                with self.assertRaises(nord_egress.NordEgressError):
                    nord_egress.validate_document(document)

        document = active_document()
        document["gateway"]["authorized_source_addresses"] = [
            "10.99.0.241/32",
            "10.99.0.242/32",
        ]
        normalized = nord_egress.validate_document(document)
        self.assertEqual(
            normalized["gateway"]["authorized_source_addresses"],
            ["10.99.0.241/32", "10.99.0.242/32"],
        )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(nord_egress.NordEgressError, "duplicate JSON key"):
            json.loads(
                '{"schema_version": 1, "schema_version": 1}',
                object_pairs_hook=nord_egress._reject_duplicate_json_keys,
            )

    def test_active_contract_must_match_one_exact_mesh_generation(self) -> None:
        normalized, binding = nord_egress.bind_mesh_document(
            active_document(), active_mesh_document()
        )

        self.assertEqual(normalized["generation"], binding["generation"])
        self.assertEqual(binding["gateway_node_id"], "mesh-hub")
        self.assertEqual(binding["gateway_public_key"], PUBLIC_A)
        self.assertEqual(binding["gateway_address"], "10.99.0.254/32")
        self.assertEqual(binding["gateway_listen_port"], 51821)
        self.assertEqual(binding["wireguard_interface"], "mesh-hub")
        self.assertEqual(binding["authorized_leaf_ids"], ["mesh-leaf"])
        self.assertEqual(binding["authorized_source_addresses"], ["10.99.0.241/32"])
        self.assertEqual(
            binding["wireguard_peer_bindings"],
            [
                {
                    "node_id": "mesh-leaf",
                    "address": "10.99.0.241/32",
                    "public_key": PUBLIC_B,
                }
            ],
        )
        self.assertEqual(binding["egress_dns_servers"], ["103.86.96.100", "103.86.99.100"])
        self.assertEqual(len(binding["document_sha256"]), 64)

        cases = []
        wrong_generation = active_document()
        wrong_generation["generation"] = 2
        cases.append(wrong_generation)
        wrong_interface = active_document()
        wrong_interface["gateway"]["wireguard_interface"] = "wrong-hub"
        cases.append(wrong_interface)
        wrong_subnet = active_document()
        wrong_subnet["gateway"]["mesh_source_subnet"] = "10.98.0.0/24"
        cases.append(wrong_subnet)
        wrong_sources = active_document()
        wrong_sources["gateway"]["authorized_source_addresses"] = ["10.99.0.242/32"]
        cases.append(wrong_sources)

        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(nord_egress.NordEgressError):
                    nord_egress.bind_mesh_document(document, active_mesh_document())

        disabled_mesh = active_mesh_document()
        disabled_mesh["egress"] = {"mode": "disabled", "gateway_node_id": None}
        with self.assertRaisesRegex(nord_egress.NordEgressError, "must be nord-vpn"):
            nord_egress.bind_mesh_document(active_document(), disabled_mesh)


class NordEgressRenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime_root = REPO_ROOT / "runtime"
        self.runtime_created = not self.runtime_root.exists()
        self.runtime_root.mkdir(mode=0o700, exist_ok=True)
        self.temp_root = Path(tempfile.mkdtemp(prefix="nord-egress-test-", dir=self.runtime_root))

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_root, ignore_errors=True)
        if self.runtime_created:
            with contextlib.suppress(OSError):
                self.runtime_root.rmdir()

    def _write_fake_command(self, directory: Path, name: str, body: str) -> None:
        path = directory / name
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def test_generation_zero_cannot_render(self) -> None:
        with self.assertRaisesRegex(nord_egress.NordEgressError, "inert"):
            nord_egress.render(
                nord_egress.inert_document(),
                self.temp_root / "rendered",
                mesh_document=active_mesh_document(),
            )

    def test_render_writes_owner_only_ignored_inactive_quadlets(self) -> None:
        rendered = nord_egress.render(
            active_document(),
            self.temp_root / "rendered",
            mesh_document=active_mesh_document(),
        )

        for path in rendered:
            with self.subTest(path=path.name):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(
                    nord_egress.subprocess.run(
                        [
                            "git",
                            "-C",
                            str(REPO_ROOT),
                            "check-ignore",
                            "--no-index",
                            "-q",
                            "--",
                            str(path.relative_to(REPO_ROOT)),
                        ],
                        check=False,
                    ).returncode,
                    0,
                )
        self.assertEqual(stat.S_IMODE(rendered[0].parent.stat().st_mode), 0o700)

    def test_host_guard_accepts_real_iproute2_whitespace_and_detached_rules(self) -> None:
        rendered = nord_egress.render(
            active_document(),
            self.temp_root / "host-parser",
            mesh_document=active_mesh_document(),
        )
        host_guard_path = rendered[3]
        fake_bin = self.temp_root / "fake-host-tools"
        fake_bin.mkdir()
        self._write_fake_command(fake_bin, "uname", "printf '%s\\n' Linux\n")
        self._write_fake_command(fake_bin, "id", "printf '%s\\n' 0\n")
        self._write_fake_command(fake_bin, "date", "printf '%s\\n' \"$FAKE_EPOCH\"\n")
        self._write_fake_command(
            fake_bin,
            "podman",
            'case "${1:-}" in\n'
            "  info) printf '%s\\n' false ;;\n"
            "  version) printf '%s\\n' 6.0.1 ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n",
        )
        self._write_fake_command(fake_bin, "nft", "exit 0\n")
        self._write_fake_command(
            fake_bin,
            "ip",
            'case "$*" in\n'
            "  '-4 route show table 51990') printf 'prohibit default metric 32767 \\n' ;;\n"
            "  '-4 rule show priority 11990') printf '11990:\\tfrom 10.99.0.241 iif mesh-hub [detached] lookup 51990\\n' ;;\n"
            "  '-4 rule show priority 11991') printf '11991:\\tfrom 10.99.0.241 iif mesh-hub [detached] prohibit\\n' ;;\n"
            "  '-4 rule show priority 12502') printf '12502:\\tfrom all iif mesh-hub [detached] prohibit\\n' ;;\n"
            "  '-6 rule show priority 12502') printf '12502:\\tfrom all iif mesh-hub [detached] prohibit\\n' ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n",
        )
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        environment["FAKE_EPOCH"] = "1"

        result = nord_egress.subprocess.run(
            ["sh", str(host_guard_path), "verify"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

        environment["FAKE_EPOCH"] = "9999999999"
        expired = nord_egress.subprocess.run(
            ["sh", str(host_guard_path), "verify"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertNotEqual(expired.returncode, 0)
        self.assertIn("bound mesh generation has expired", expired.stderr)

    def test_wireguard_binding_rejects_broad_extra_or_wrong_peer_routes(self) -> None:
        rendered = nord_egress.render(
            active_document(),
            self.temp_root / "peer-binding",
            mesh_document=active_mesh_document(),
        )
        route_enable_path = rendered[5]
        fake_bin = self.temp_root / "fake-route-tools"
        fake_bin.mkdir()
        self._write_fake_command(fake_bin, "uname", "printf '%s\\n' Linux\n")
        self._write_fake_command(fake_bin, "id", "printf '%s\\n' 0\n")
        self._write_fake_command(fake_bin, "nft", "exit 0\n")
        self._write_fake_command(
            fake_bin,
            "ip",
            """case "$*" in
  "-4 -o address show dev mesh-hub scope global")
    printf '7: mesh-hub inet %s scope global mesh-hub\\n' "$WG_ADDRESS"
    ;;
esac
""",
        )
        self._write_fake_command(
            fake_bin,
            "wg",
            """case "$*" in
  "show mesh-hub public-key") printf '%s\\n' "$WG_PUBLIC_KEY" ;;
  "show mesh-hub listen-port") printf '%s\\n' "$WG_LISTEN_PORT" ;;
  "show mesh-hub allowed-ips") printf '%s\\n' "$WG_ALLOWED_IPS" ;;
  *) exit 1 ;;
esac
""",
        )
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        environment["WG_PUBLIC_KEY"] = PUBLIC_A
        environment["WG_ADDRESS"] = "10.99.0.254/32"
        environment["WG_LISTEN_PORT"] = "51821"

        allowed = f"{PUBLIC_B} 10.99.0.241/32"
        cases = (
            (allowed, True),
            (f"{PUBLIC_B} 10.99.0.240/28", False),
            (f"{PUBLIC_A} 10.99.0.241/32", False),
            (f"{allowed}\\n{PUBLIC_A} 10.99.0.242/32", False),
        )
        for runtime_map, expected_success in cases:
            with self.subTest(runtime_map=runtime_map):
                environment["WG_ALLOWED_IPS"] = runtime_map
                result = nord_egress.subprocess.run(
                    ["sh", str(route_enable_path), "verify-wireguard"],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertEqual(result.returncode == 0, expected_success, result.stderr)

        environment["WG_ALLOWED_IPS"] = allowed
        environment["WG_PUBLIC_KEY"] = PUBLIC_C
        stale_gateway = nord_egress.subprocess.run(
            ["sh", str(route_enable_path), "verify-wireguard"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertNotEqual(stale_gateway.returncode, 0)
        self.assertIn("gateway public key differs", stale_gateway.stderr)

    def test_quadlet_contract_is_isolated_rootful_and_fail_closed(self) -> None:
        (
            build_path,
            network_path,
            container_path,
            host_guard_path,
            host_guard_service_path,
            route_enable_path,
            route_enable_service_path,
            wg_dependency_path,
            expiry_stop_service_path,
            expiry_timer_path,
            mesh_binding_path,
            staged_containerfile_path,
            staged_entrypoint_path,
            staged_token_helper_path,
            manifest_path,
        ) = nord_egress.render(
            active_document(),
            self.temp_root / "contract",
            mesh_document=active_mesh_document(),
        )
        build = build_path.read_text(encoding="utf-8")
        network = network_path.read_text(encoding="utf-8")
        container = container_path.read_text(encoding="utf-8")
        host_guard = host_guard_path.read_text(encoding="utf-8")
        host_guard_service = host_guard_service_path.read_text(encoding="utf-8")
        route_enable = route_enable_path.read_text(encoding="utf-8")
        route_enable_service = route_enable_service_path.read_text(encoding="utf-8")
        wg_dependency = wg_dependency_path.read_text(encoding="utf-8")
        expiry_stop_service = expiry_stop_service_path.read_text(encoding="utf-8")
        expiry_timer = expiry_timer_path.read_text(encoding="utf-8")
        mesh_binding = json.loads(mesh_binding_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        all_units = (
            build
            + network
            + container
            + host_guard_service
            + route_enable_service
            + wg_dependency
            + expiry_stop_service
            + expiry_timer
        )
        root_generation = "/etc/short-circuit/nord-egress/tc-nord-egress-g1"

        self.assertIn("BuildArg=BASE_IMAGE=docker.io/library/ubuntu@sha256:", build)
        self.assertIn("BuildArg=NORDVPN_PACKAGE_VERSION=5.2.0", build)
        self.assertIn(f"File={root_generation}/build-context/Containerfile", build)
        self.assertIn("Pull=always", build)
        self.assertIn("Options=isolate=true", network)
        self.assertIn("IPv6=false", network)
        self.assertIn("InterfaceName=tcne0", network)
        self.assertIn("AddCapability=NET_ADMIN", container)
        self.assertIn("AddDevice=/dev/net/tun:/dev/net/tun:rwm", container)
        self.assertIn("UserNS=host", container)
        self.assertIn("Host.Security.Rootless", container)
        self.assertIn("AssertPathExists=/dev/net/tun", container)
        self.assertIn("ExecStartPre=", container)
        self.assertNotIn("ExecCondition=", container)
        self.assertIn("host-guard.sh verify", container)
        self.assertIn("DNS=103.86.96.100", container)
        self.assertIn("DNS=103.86.99.100", container)
        self.assertIn("Environment=TC_MESH_SOURCE_SUBNET=10.99.0.240/28", container)
        self.assertIn("Environment=TC_AUTHORIZED_SOURCE_ADDRESSES=10.99.0.241/32", container)
        self.assertIn("Environment=TC_EGRESS_FAIL_CLOSED=true", container)
        self.assertIn("Environment=TC_CRUD_LEADERSHIP=none", container)
        self.assertIn("Sysctl=net.ipv6.conf.all.disable_ipv6=1", container)
        self.assertIn("Sysctl=net.ipv6.conf.default.disable_ipv6=1", container)
        self.assertIn("HealthStartPeriod=120s", container)
        self.assertIn("HealthStartupRetries=30", container)
        self.assertIn("Requires=tc-nord-egress-g1-host-guard.service", container)
        self.assertIn("After=tc-nord-egress-g1-host-guard.service", container)
        self.assertIn("Wants=tc-nord-egress-g1-route-enable.service", container)
        self.assertNotIn("[Install]", all_units)
        self.assertNotIn("Network=host", all_units)
        self.assertNotIn("Privileged=true", all_units)
        self.assertNotIn("PublishPort=", all_units)
        self.assertNotIn(str(REPO_ROOT), all_units)
        self.assertNotIn("runtime/", all_units)

        self.assertIn("AUTHORIZED_SOURCES=10.99.0.241/32", host_guard)
        self.assertIn('ip saddr @authorized_sources oifname "$BRIDGE_INTERFACE" accept', host_guard)
        self.assertIn(
            "ip daddr @authorized_sources ct state established,related accept", host_guard
        )
        self.assertIn("ip daddr @blocked_destinations drop", host_guard)
        self.assertIn('oifname "$WIREGUARD_INTERFACE" drop', host_guard)
        self.assertIn('iifname "$WIREGUARD_INTERFACE" jump wireguard_egress', host_guard)
        self.assertIn("MESH_EXPIRES_EPOCH=", host_guard)
        self.assertIn("the bound mesh generation has expired", host_guard)
        self.assertIn('ip -4 route add table "$ROUTE_TABLE" prohibit default', host_guard)
        self.assertIn(
            'iif "$WIREGUARD_INTERFACE" from "$source_address" lookup "$ROUTE_TABLE"',
            host_guard,
        )
        self.assertIn('iif "$WIREGUARD_INTERFACE" from "$source_address" prohibit', host_guard)
        self.assertIn(
            'ip -4 rule add priority "$INTERFACE_PROHIBIT_PRIORITY" '
            'iif "$WIREGUARD_INTERFACE" prohibit',
            host_guard,
        )
        self.assertIn(
            'ip -6 rule add priority "$INTERFACE_PROHIBIT_PRIORITY" '
            'iif "$WIREGUARD_INTERFACE" prohibit',
            host_guard,
        )
        self.assertIn("NF == 4", host_guard)
        self.assertIn('oifname "$BRIDGE_INTERFACE" drop', host_guard)
        self.assertIn('iifname "$BRIDGE_INTERFACE" drop', host_guard)
        self.assertIn('iifname "$BRIDGE_INTERFACE" ip saddr $GATEWAY_ADDRESS drop', host_guard)
        self.assertIn('ip saddr $GATEWAY_ADDRESS oifname != "$BRIDGE_INTERFACE"', host_guard)
        self.assertIn("ip daddr $GATEWAY_ADDRESS ct state established,related accept", host_guard)
        self.assertNotIn("ip saddr $mesh_source", host_guard)
        install_guard = host_guard.split("install_guard() {", 1)[1].split(
            "decommission_guard() {", 1
        )[0]
        self.assertNotIn("ip link show", install_guard)

        self.assertIn("Requires=tc-nord-egress-g1-network.service", host_guard_service)
        self.assertIn("After=tc-nord-egress-g1-network.service", host_guard_service)
        self.assertIn("Before=wg-quick@mesh-hub.service", host_guard_service)
        self.assertIn("Before=tc-nord-egress-g1.service", host_guard_service)
        self.assertIn(
            f"ExecStart=/bin/sh {root_generation}/tc-nord-egress-g1-host-guard.sh install",
            host_guard_service,
        )
        self.assertNotIn("ExecStop=", host_guard_service)
        self.assertNotIn("ConditionPathExists=/sys/class/net", host_guard_service)
        self.assertNotIn("ExecCondition=", host_guard_service)

        self.assertIn(
            'ip -4 route add table "$ROUTE_TABLE" default via "$GATEWAY_ADDRESS"',
            route_enable,
        )
        self.assertNotIn('route add table "$ROUTE_TABLE" prohibit default', route_enable)
        self.assertIn("BindsTo=tc-nord-egress-g1.service", route_enable_service)
        self.assertIn("BindsTo=wg-quick@mesh-hub.service", route_enable_service)
        self.assertIn("After=tc-nord-egress-g1.service", route_enable_service)
        self.assertIn("After=wg-quick@mesh-hub.service", route_enable_service)
        self.assertIn(
            f"ExecStart=/bin/sh {root_generation}/tc-nord-egress-g1-route-enable.sh up",
            route_enable_service,
        )
        self.assertIn(
            f"ExecStop=/bin/sh {root_generation}/tc-nord-egress-g1-route-enable.sh down",
            route_enable_service,
        )
        self.assertIn("host IPv4 forwarding must already be enabled", route_enable)
        self.assertIn("strict rp_filter", route_enable)
        self.assertIn('wg show "$WIREGUARD_INTERFACE" allowed-ips', route_enable)
        self.assertIn('wg show "$WIREGUARD_INTERFACE" public-key', route_enable)
        self.assertIn('wg show "$WIREGUARD_INTERFACE" listen-port', route_enable)
        self.assertIn(f"EXPECTED_WIREGUARD_PUBLIC_KEY={PUBLIC_A}", route_enable)
        self.assertIn("EXPECTED_WIREGUARD_ADDRESS=10.99.0.254/32", route_enable)
        self.assertIn("EXPECTED_WIREGUARD_LISTEN_PORT=51821", route_enable)
        self.assertIn(f"EXPECTED_WIREGUARD_PEERS='{PUBLIC_B} 10.99.0.241/32'", route_enable)
        self.assertIn("runtime WireGuard peer keys and exact /32 routes differ", route_enable)
        self.assertIn("LC_ALL=C", route_enable)
        self.assertIn("Requires=tc-nord-egress-g1-host-guard.service", wg_dependency)
        self.assertIn("After=tc-nord-egress-g1-host-guard.service", wg_dependency)
        self.assertIn("Wants=tc-nord-egress-g1-route-enable.service", wg_dependency)
        self.assertIn("host-guard.sh verify", wg_dependency)
        self.assertIn("route-enable.sh verify-wireguard", wg_dependency)
        self.assertIn("ExecStopPost=-/usr/bin/wg-quick down %i", wg_dependency)
        self.assertIn("Requires=tc-nord-egress-g1-expiry.timer", wg_dependency)
        self.assertIn("After=tc-nord-egress-g1-expiry.timer", wg_dependency)
        self.assertNotIn("[Install]", wg_dependency)

        self.assertIn(
            "ExecStart=/usr/bin/systemctl --no-block stop wg-quick@mesh-hub.service",
            expiry_stop_service,
        )
        self.assertIn("RefuseManualStart=yes", expiry_stop_service)
        self.assertIn("BindsTo=wg-quick@mesh-hub.service", expiry_timer)
        self.assertIn("PartOf=wg-quick@mesh-hub.service", expiry_timer)
        self.assertIn(f"OnCalendar={DEFAULT_EXPIRY[:-1].replace('T', ' ')} UTC", expiry_timer)
        self.assertIn("Persistent=true", expiry_timer)

        self.assertFalse(manifest["activation_performed"])
        self.assertFalse(manifest["host_network_allowed"])
        self.assertTrue(manifest["host_route_artifact_rendered"])
        self.assertTrue(manifest["host_forwarding_policy_artifact_rendered"])
        self.assertFalse(manifest["host_policy_activation_performed"])
        self.assertEqual(manifest["crud_leadership"], "none")
        self.assertEqual(manifest["authorized_source_addresses"], ["10.99.0.241/32"])
        self.assertEqual(manifest["authorized_leaf_ids"], ["mesh-leaf"])
        self.assertEqual(manifest["wireguard_interface"], "mesh-hub")
        self.assertEqual(manifest["mesh_binding"], mesh_binding)
        self.assertEqual(manifest["mesh_document_sha256"], mesh_binding["document_sha256"])
        self.assertEqual(manifest["mesh_cutover_epoch"], 1)
        self.assertEqual(manifest["mesh_expires_at"], DEFAULT_EXPIRY)
        self.assertEqual(manifest["bootstrap_dns_servers"], ["103.86.96.100", "103.86.99.100"])
        self.assertEqual(manifest["anti_spoof_boundary"], "wireguard-cryptokey-routing")
        self.assertFalse(manifest["peer_transit"])
        self.assertEqual(manifest["podman_min_version"], "5.8.0")
        self.assertEqual(manifest["nordvpn_package_version"], "5.2.0")
        self.assertEqual(
            manifest["nordvpn_package_sha256"],
            {
                "amd64": "9850701f589e742e4d92c43eee1f2188262ddb71f40e5453d3a2ad79503db89b",
                "arm64": "7167223efdca6daf1f84281ed4d2781414a51a4992c51aaa5cab9eb44c979eb4",
            },
        )
        self.assertEqual(manifest["base_image_digest_validation"], "syntactic-only")
        self.assertTrue(manifest["host_guard_persistent"])
        self.assertFalse(manifest["host_guard_automatic_removal"])
        self.assertTrue(manifest["interface_wide_terminal_prohibit_ipv4_ipv6"])
        self.assertEqual(manifest["wireguard_activation_contract"], "systemd-wg-quick-only")
        self.assertEqual(
            manifest["wireguard_failed_start_cleanup"],
            "exec-stop-post-wg-quick-down",
        )
        self.assertEqual(
            manifest["managed_dropin_replacement"],
            "fixed-target-atomic-replacement-required",
        )
        self.assertEqual(
            manifest["mesh_expiry_enforcement"],
            "utc-startup-gate-and-systemd-timer",
        )
        self.assertEqual(manifest["credential_process_visibility"], "pr-set-dumpable-zero-wrapper")
        self.assertFalse(manifest["installation_performed"])
        self.assertTrue(all(item["target"].startswith("/etc/") for item in manifest["install_map"]))
        self.assertIn(
            "/etc/systemd/system/wg-quick@mesh-hub.service.d/" "50-short-circuit-nord-egress.conf",
            {item["target"] for item in manifest["install_map"]},
        )
        self.assertTrue(manifest["linux_integration_test_required"])

        for script in (host_guard_path, route_enable_path):
            with self.subTest(script=script.name):
                self.assertEqual(
                    nord_egress.subprocess.run(["sh", "-n", str(script)], check=False).returncode,
                    0,
                )

        self.assertEqual(
            staged_containerfile_path.read_bytes(),
            (REPO_ROOT / "containers/nord-egress/Containerfile").read_bytes(),
        )
        self.assertEqual(
            staged_entrypoint_path.read_bytes(),
            (REPO_ROOT / "containers/nord-egress/nord-egress-entrypoint.sh").read_bytes(),
        )
        self.assertEqual(
            staged_token_helper_path.read_bytes(),
            (REPO_ROOT / "containers/nord-egress/nord-token-login.c").read_bytes(),
        )

    def test_token_is_only_referenced_as_a_read_only_podman_secret_file(self) -> None:
        rendered = nord_egress.render(
            active_document(),
            self.temp_root / "secret-contract",
            mesh_document=active_mesh_document(),
        )
        container_path = rendered[2]
        manifest_path = rendered[-1]
        container = container_path.read_text(encoding="utf-8")
        manifest = manifest_path.read_text(encoding="utf-8")

        self.assertIn(
            "Secret=short-circuit-nordvpn-token,type=mount,"
            "target=/run/secrets/nordvpn-token,uid=0,gid=0,mode=0400",
            container,
        )
        self.assertNotIn("type=env", container)
        self.assertNotIn("Environment=NORDVPN_TOKEN", container)
        self.assertNotIn("--token", container)
        self.assertIn('"credential_value_present": false', manifest)

    def test_render_refuses_to_overwrite_a_reviewed_generation(self) -> None:
        output = self.temp_root / "immutable-generation"
        nord_egress.render(active_document(), output, mesh_document=active_mesh_document())

        with self.assertRaisesRegex(nord_egress.NordEgressError, "refusing to overwrite"):
            nord_egress.render(active_document(), output, mesh_document=active_mesh_document())

    def test_render_refuses_a_non_runtime_output(self) -> None:
        with self.assertRaisesRegex(nord_egress.NordEgressError, "runtime"):
            nord_egress.render(
                active_document(),
                REPO_ROOT / "not-private",
                mesh_document=active_mesh_document(),
            )

    def test_init_writes_an_owner_only_ignored_config(self) -> None:
        config_path = self.temp_root / "config.json"
        created = nord_egress.initialize(config_path)

        self.assertEqual(stat.S_IMODE(created.stat().st_mode), 0o600)
        self.assertEqual(nord_egress.load_document(created), nord_egress.inert_document())


class NordEgressImageContractTests(unittest.TestCase):
    def test_container_build_context_never_accepts_credentials(self) -> None:
        containerfile = (REPO_ROOT / "containers" / "nord-egress" / "Containerfile").read_text()

        self.assertIn("ARG BASE_IMAGE", containerfile)
        self.assertIn("FROM ${BASE_IMAGE}", containerfile)
        self.assertIn("ARG NORDVPN_PACKAGE_VERSION", containerfile)
        self.assertIn("nordvpn_${NORDVPN_PACKAGE_VERSION}_${architecture}.deb", containerfile)
        self.assertIn("9850701f589e742e4d92c43eee1f2188", containerfile)
        self.assertIn("7167223efdca6daf1f84281ed4d27814", containerfile)
        self.assertIn("sha256sum -c -", containerfile)
        self.assertIn("gpasswd -d ubuntu nordvpn", containerfile)
        self.assertIn('getent group nordvpn | cut -d: -f4)" = ""', containerfile)
        self.assertIn("COPY nord-token-login.c", containerfile)
        self.assertIn("token-helper-build", containerfile)
        self.assertIn("/tmp/nord-token-login.c -lutil", containerfile)
        self.assertNotIn("nordvpn_public.asc", containerfile)
        self.assertNotIn("ARG TOKEN", containerfile.upper())
        self.assertNotIn("ENV TOKEN", containerfile.upper())
        self.assertNotIn("COPY .ENV", containerfile.upper())

    def test_entrypoint_enforces_source_interface_and_ipv6_boundaries(self) -> None:
        entrypoint = (
            REPO_ROOT / "containers" / "nord-egress" / "nord-egress-entrypoint.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("set authorized_sources", entrypoint)
        self.assertIn("flags interval", entrypoint)
        self.assertIn("install_bootstrap_policy", entrypoint)
        self.assertIn("policy drop;", entrypoint)
        self.assertIn("keeping the nftables policy", entrypoint)
        self.assertLess(
            entrypoint.index("install_bootstrap_policy ||"),
            entrypoint.index("/etc/init.d/nordvpn start"),
        )
        self.assertIn("validate_authorized_sources", entrypoint)
        self.assertIn('source_parts[2] != "32"', entrypoint)
        self.assertIn("source_address <= previous_address", entrypoint)
        self.assertIn("policy drop;", entrypoint)
        self.assertIn('ip saddr @authorized_sources oifname "$NORD_INTERFACE"', entrypoint)
        self.assertIn("ip daddr @authorized_sources", entrypoint)
        self.assertIn(
            'ip saddr @authorized_sources oifname "$NORD_INTERFACE" masquerade', entrypoint
        )
        self.assertNotIn("ip saddr $mesh_source", entrypoint)
        self.assertNotIn("ip daddr $mesh_source", entrypoint)
        self.assertIn("meta nfproto ipv6 drop", entrypoint)
        self.assertIn("net.ipv6.conf.all.disable_ipv6=1", entrypoint)
        self.assertIn("nordvpn set killswitch on", entrypoint)
        self.assertIn("nordvpn set meshnet off", entrypoint)
        self.assertIn("timeout 3 nordvpn status", entrypoint)
        self.assertIn("Status: Connected", entrypoint)
        self.assertIn("ip -4 route show table all", entrypoint)
        self.assertIn("nft list chain", entrypoint)
        self.assertIn("timeout 90 /usr/local/sbin/nord-token-login", entrypoint)
        self.assertLess(
            entrypoint.index("nordvpn set analytics off"),
            entrypoint.index("/usr/local/sbin/nord-token-login"),
        )
        self.assertIn("User Consent: disabled", entrypoint)
        self.assertIn("Technology: NORDLYNX", entrypoint)
        self.assertIn("Kill Switch: enabled", entrypoint)
        self.assertIn("LAN Discovery: disabled", entrypoint)
        self.assertIn("Meshnet: disabled", entrypoint)
        self.assertIn('nordvpn allowlist add subnet "$authorized_source"', entrypoint)
        self.assertIn('nordvpn whitelist add subnet "$authorized_source"', entrypoint)
        self.assertNotIn('nordvpn whitelist add subnet "$mesh_source"', entrypoint)
        self.assertIn("[!A-Za-z0-9]*|*[!A-Za-z0-9_-]*|'')", entrypoint)
        self.assertNotIn("set -x", entrypoint)
        self.assertNotIn('echo "$token"', entrypoint)
        self.assertNotIn("printf '%s\\n' \"$token\" >&2", entrypoint)

        token_helper = (REPO_ROOT / "containers" / "nord-egress" / "nord-token-login.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("PR_SET_DUMPABLE", token_helper)
        self.assertIn('SECRET_PATH "/run/secrets/nordvpn-token"', token_helper)
        self.assertIn('TOKEN_PROMPT "Enter access token: "', token_helper)
        self.assertIn("forkpty(&master", token_helper)
        self.assertIn("tcgetattr(master", token_helper)
        self.assertIn("(ECHO | ECHONL)", token_helper)
        self.assertIn('char *child_argv[] = {"nordvpn", "login", "--token", NULL}', token_helper)
        self.assertIn("fexecve(cli_descriptor, child_argv, child_env)", token_helper)
        self.assertLess(
            token_helper.index("wait_for_prompt(master, child, prompt_deadline)"),
            token_helper.index("read_secret(token, &token_length)"),
        )
        self.assertIn("LOGIN_WAIT_REAPED_FAILURE", token_helper)
        self.assertIn("if (wait_result == LOGIN_WAIT_UNREAPED_ERROR)", token_helper)
        self.assertIn("value < 0x21 || value > 0x7e", token_helper)
        self.assertNotIn('"login", "--token", token', token_helper)


if __name__ == "__main__":
    unittest.main()
