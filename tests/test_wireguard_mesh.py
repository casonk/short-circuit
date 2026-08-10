from __future__ import annotations

import base64
import copy
import datetime as dt
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "render_wireguard_mesh.py"
SPEC = importlib.util.spec_from_file_location("render_wireguard_mesh", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
mesh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mesh)

PRIVATE_A = base64.b64encode(bytes(range(1, 33))).decode("ascii")
PRIVATE_B = base64.b64encode(bytes(range(33, 65))).decode("ascii")
PUBLIC_A = base64.b64encode(bytes([0x11]) * 32).decode("ascii")
PUBLIC_B = base64.b64encode(bytes([0x22]) * 32).decode("ascii")
PUBLIC_C = base64.b64encode(bytes([0x33]) * 32).decode("ascii")
PUBLIC_D = base64.b64encode(bytes([0x44]) * 32).decode("ascii")
DEFAULT_EXPIRY = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)


def active_document() -> dict[str, object]:
    return {
        "schema_version": 2,
        "generation": 7,
        "mesh": {
            "name": "temporary-home",
            "subnet": "10.99.0.240/28",
            "listen_port": 51821,
            "peer_transit": False,
        },
        "failover_mode": "manual-static",
        "cutover_epoch": 3,
        "expires_at": DEFAULT_EXPIRY,
        "egress": {"mode": "disabled", "gateway_node_id": None},
        "nodes": [
            {
                "id": "leaf-home",
                "role": "leaf",
                "platform": "linux",
                "address": "10.99.0.241/32",
                "public_key": PUBLIC_B,
                "hub_transport": {
                    "mode": "nord-meshnet",
                    "endpoint": "100.64.10.5:51821",
                },
            },
            {
                "id": "hub-air",
                "role": "hub",
                "platform": "macos",
                "address": "10.99.0.254/32",
                "public_key": PUBLIC_A,
            },
            {
                "id": "leaf-backup",
                "role": "leaf",
                "platform": "other",
                "address": "10.99.0.242/32",
                "public_key": PUBLIC_C,
                "hub_transport": {
                    "mode": "direct",
                    "endpoint": "hub.example.com:51821",
                },
            },
        ],
    }


def legacy_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "generation": 7,
        "mesh": {
            "name": "temporary-home",
            "subnet": "10.99.0.240/28",
            "listen_port": 51821,
        },
        "failover_mode": "manual-static",
        "cutover_epoch": 3,
        "expires_at": DEFAULT_EXPIRY,
        "nodes": [
            {
                "id": "leaf-home",
                "role": "leaf",
                "address": "10.99.0.241/32",
                "public_key": PUBLIC_B,
            },
            {
                "id": "hub-air",
                "role": "hub",
                "address": "10.99.0.254/32",
                "public_key": PUBLIC_A,
                "underlay_endpoint": "100.64.10.5:51821",
            },
            {
                "id": "leaf-backup",
                "role": "leaf",
                "address": "10.99.0.242/32",
                "public_key": PUBLIC_C,
            },
        ],
    }


def nord_egress_document() -> dict[str, object]:
    document = active_document()
    document["nodes"][1]["platform"] = "linux"
    document["egress"] = {
        "mode": "nord-vpn",
        "gateway_node_id": "hub-air",
        "authorized_leaf_ids": ["leaf-home"],
        "dns_servers": ["103.86.96.100", "103.86.99.100"],
        "ipv6_policy": "block",
    }
    return document


def parse_wg_quick(text: str) -> tuple[dict[str, str], list[dict[str, str]]]:
    interface: dict[str, str] | None = None
    peers: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[Interface]":
            if interface is not None:
                raise AssertionError("duplicate Interface section")
            interface = {}
            current = interface
            continue
        if line == "[Peer]":
            current = {}
            peers.append(current)
            continue
        if current is None or " = " not in line:
            raise AssertionError("invalid wg-quick line")
        key, value = line.split(" = ", 1)
        if not key or not value or key in current:
            raise AssertionError("invalid or duplicate wg-quick field")
        current[key] = value
    if interface is None:
        raise AssertionError("missing Interface section")
    return interface, peers


class WireGuardMeshTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_context = tempfile.TemporaryDirectory(prefix="short-circuit-mesh-")
        self.root = Path(self.temp_context.name)
        self.root.chmod(0o700)
        self.fake_wg = self.root / "fake-wg"
        self.fake_wg.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys

operation = sys.argv[1] if len(sys.argv) == 2 else ""
private_key = os.environ["FAKE_WG_PRIVATE_A"]
mapping = json.loads(os.environ["FAKE_WG_MAPPING"])
if operation == "genkey":
    if os.environ.get("FAKE_WG_FAIL") == "genkey":
        sys.stderr.write(private_key)
        raise SystemExit(9)
    print(private_key)
elif operation == "pubkey":
    supplied = sys.stdin.read().strip()
    if os.environ.get("FAKE_WG_FAIL") == "pubkey":
        sys.stdout.write(supplied)
        sys.stderr.write(supplied)
        raise SystemExit(8)
    if supplied not in mapping:
        raise SystemExit(7)
    print(mapping[supplied])
else:
    raise SystemExit(6)
""",
            encoding="utf-8",
        )
        self.fake_wg.chmod(0o700)
        self.environment = {
            **os.environ,
            "FAKE_WG_PRIVATE_A": PRIVATE_A,
            "FAKE_WG_MAPPING": json.dumps({PRIVATE_A: PUBLIC_A, PRIVATE_B: PUBLIC_B}),
        }

    def tearDown(self) -> None:
        self.temp_context.cleanup()

    def write_json(self, name: str, document: dict[str, object]) -> Path:
        path = self.root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o600)
        return path

    def write_key(self, name: str, private_key: str = PRIVATE_A) -> Path:
        path = self.root / name
        path.write_text(f"{private_key}\n", encoding="ascii")
        path.chmod(0o600)
        return path

    def run_cli(self, *arguments: str, environment: dict[str, str] | None = None):
        return subprocess.run(
            [sys.executable, os.fspath(SCRIPT_PATH), *arguments],
            cwd=self.root,
            env=environment or self.environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_init_writes_owner_only_inert_config_and_render_refuses_it(self) -> None:
        tracked_parent = self.root / "config" / "wireguard"
        tracked_parent.mkdir(parents=True, mode=0o755)
        tracked_parent.chmod(0o755)
        config = tracked_parent / "mesh.local.json"
        result = self.run_cli("init", "--config", os.fspath(config))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        document = json.loads(config.read_text(encoding="utf-8"))
        normalized = mesh.validate_document(document)
        self.assertEqual(normalized["generation"], 0)
        self.assertEqual(normalized["nodes"], [])
        self.assertIsNone(normalized["expires_at"])
        self.assertEqual(normalized["mesh"]["name"], "temporary-macos-host-only")
        self.assertEqual(normalized["mesh"]["subnet"], "10.99.0.240/28")
        self.assertEqual(normalized["mesh"]["listen_port"], 51821)

        render_result = self.run_cli(
            "render",
            "--config",
            os.fspath(config),
            "--node-id",
            "hub-air",
            "--private-key-file",
            os.fspath(self.root / "missing.key"),
            "--output-dir",
            os.fspath(self.root / "rendered"),
            "--wg-binary",
            os.fspath(self.fake_wg),
        )
        self.assertEqual(render_result.returncode, 1)
        self.assertIn("generation 0 is inert", render_result.stderr)
        self.assertFalse((self.root / "rendered").exists())

    def test_generate_key_uses_wg_and_never_logs_key_material(self) -> None:
        private_path = self.root / "keys" / "hub-air.key"
        public_path = self.root / "keys" / "hub-air.pub"
        result = self.run_cli(
            "generate-key",
            "--node-id",
            "hub-air",
            "--private-key-file",
            os.fspath(private_path),
            "--public-key-file",
            os.fspath(public_path),
            "--wg-binary",
            os.fspath(self.fake_wg),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(public_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(private_path.parent.stat().st_mode), 0o700)
        self.assertTrue(private_path.read_text(encoding="ascii").strip() == PRIVATE_A)
        self.assertTrue(public_path.read_text(encoding="ascii").strip() == PUBLIC_A)
        combined_log = result.stdout + result.stderr
        self.assertFalse(PRIVATE_A in combined_log)
        self.assertFalse(PUBLIC_A in combined_log)

        second = self.run_cli(
            "generate-key",
            "--node-id",
            "hub-air",
            "--private-key-file",
            os.fspath(private_path),
            "--public-key-file",
            os.fspath(public_path),
            "--wg-binary",
            os.fspath(self.fake_wg),
        )
        self.assertEqual(second.returncode, 1)
        self.assertIn("refusing to overwrite", second.stderr)

    def test_hub_render_is_complete_deterministic_and_owner_only(self) -> None:
        config = self.write_json("mesh.local.json", active_document())
        private_key = self.write_key("hub-air.key")
        first_dir = self.root / "first"
        second_dir = self.root / "second"
        with mock.patch.dict(os.environ, self.environment, clear=True):
            document = mesh.load_document(config)
            first_config, first_manifest = mesh.render(
                document=document,
                node_id="hub-air",
                private_key_path=private_key,
                output_dir=first_dir,
                wg_binary=os.fspath(self.fake_wg),
            )
            second_config, second_manifest = mesh.render(
                document=document,
                node_id="hub-air",
                private_key_path=private_key,
                output_dir=second_dir,
                wg_binary=os.fspath(self.fake_wg),
            )

        first_text = first_config.read_text(encoding="utf-8")
        self.assertEqual(first_config.name, "hub-air.conf")
        self.assertEqual(first_text, second_config.read_text(encoding="utf-8"))
        self.assertEqual(
            first_manifest.read_text(encoding="utf-8"),
            second_manifest.read_text(encoding="utf-8"),
        )
        self.assertEqual(stat.S_IMODE(first_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(first_config.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(first_manifest.stat().st_mode), 0o600)

        interface, peers = parse_wg_quick(first_text)
        self.assertEqual(set(interface), {"PrivateKey", "Address", "ListenPort"})
        self.assertEqual(len(base64.b64decode(interface["PrivateKey"], validate=True)), 32)
        self.assertEqual(interface["Address"], "10.99.0.254/32")
        self.assertEqual(len(peers), 2)
        self.assertEqual(
            {peer["AllowedIPs"] for peer in peers},
            {"10.99.0.241/32", "10.99.0.242/32"},
        )
        self.assertTrue(all("Endpoint" not in peer for peer in peers))
        self.assertTrue(all("PersistentKeepalive" not in peer for peer in peers))
        self.assertFalse("0.0.0.0/0" in first_text)
        self.assertFalse("::/0" in first_text)
        self.assertFalse("PostUp" in first_text or "PostDown" in first_text)

        manifest_text = first_manifest.read_text(encoding="utf-8")
        manifest = json.loads(manifest_text)
        self.assertFalse(PRIVATE_A in manifest_text)
        self.assertRegex(manifest["mesh_binding"]["document_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            manifest["mesh_binding"]["wireguard_peer_bindings"],
            [
                {
                    "node_id": "leaf-backup",
                    "address": "10.99.0.242/32",
                    "public_key": PUBLIC_C,
                },
                {
                    "node_id": "leaf-home",
                    "address": "10.99.0.241/32",
                    "public_key": PUBLIC_B,
                },
            ],
        )
        self.assertEqual(manifest["peer_ids"], ["leaf-backup", "leaf-home"])
        self.assertFalse(manifest["activation_performed"])
        self.assertFalse(manifest["routing_changed"])
        self.assertFalse(manifest["forwarding_enabled"])
        self.assertFalse(manifest["nat_configured"])

        before = first_config.read_bytes()
        with mock.patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaisesRegex(mesh.MeshError, "refusing to overwrite"):
                mesh.render(
                    document=document,
                    node_id="hub-air",
                    private_key_path=private_key,
                    output_dir=first_dir,
                    wg_binary=os.fspath(self.fake_wg),
                )
        self.assertEqual(first_config.read_bytes(), before)

    def test_leaf_renders_only_hub_with_its_selected_transport(self) -> None:
        config = self.write_json("mesh.local.json", active_document())
        private_key = self.write_key("leaf-home.key", PRIVATE_B)
        result = self.run_cli(
            "render",
            "--config",
            os.fspath(config),
            "--node-id",
            "leaf-home",
            "--private-key-file",
            os.fspath(private_key),
            "--output-dir",
            os.fspath(self.root / "leaf-render"),
            "--wg-binary",
            os.fspath(self.fake_wg),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = self.root / "leaf-render" / "leaf-home.conf"
        interface, peers = parse_wg_quick(rendered.read_text(encoding="utf-8"))
        self.assertEqual(interface["Address"], "10.99.0.241/32")
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["AllowedIPs"], "10.99.0.254/32")
        self.assertEqual(peers[0]["Endpoint"], "100.64.10.5:51821")
        self.assertEqual(peers[0]["PersistentKeepalive"], "25")
        self.assertFalse("leaf-backup" in rendered.read_text(encoding="utf-8"))
        self.assertFalse(PRIVATE_B in result.stdout + result.stderr)

    def test_nord_egress_is_explicit_and_scoped_to_authorized_leaves(self) -> None:
        document = nord_egress_document()
        config = self.write_json("mesh.local.json", document)
        leaf_key = self.write_key("leaf-home.key", PRIVATE_B)
        result = self.run_cli(
            "render",
            "--config",
            os.fspath(config),
            "--node-id",
            "leaf-home",
            "--private-key-file",
            os.fspath(leaf_key),
            "--output-dir",
            os.fspath(self.root / "egress-leaf"),
            "--wg-binary",
            os.fspath(self.fake_wg),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        interface, peers = parse_wg_quick(
            (self.root / "egress-leaf" / "leaf-home.conf").read_text(encoding="utf-8")
        )
        self.assertEqual(interface["DNS"], "103.86.96.100, 103.86.99.100")
        self.assertEqual(peers[0]["AllowedIPs"], "0.0.0.0/0, ::/0")
        manifest = json.loads(
            (self.root / "egress-leaf" / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertTrue(manifest["egress_authorized"])
        self.assertTrue(manifest["requires_fail_closed_egress"])
        self.assertFalse(manifest["requires_nat"])

        normalized = mesh.validate_document(document)
        unauthorized = next(node for node in normalized["nodes"] if node["id"] == "leaf-backup")
        unauthorized_text = mesh._render_wg_quick(normalized, unauthorized, PRIVATE_B)
        _, unauthorized_peers = parse_wg_quick(unauthorized_text)
        self.assertEqual(unauthorized_peers[0]["AllowedIPs"], "10.99.0.254/32")
        self.assertNotIn("DNS =", unauthorized_text)

        hub = next(node for node in normalized["nodes"] if node["id"] == "hub-air")
        hub_text = mesh._render_wg_quick(normalized, hub, PRIVATE_A)
        _, hub_peers = parse_wg_quick(hub_text)
        self.assertEqual(
            {peer["AllowedIPs"] for peer in hub_peers},
            {"10.99.0.241/32", "10.99.0.242/32"},
        )
        self.assertNotIn("Endpoint =", hub_text)
        hub_manifest = json.loads(mesh._render_manifest(normalized, hub, "hub-air.conf"))
        self.assertTrue(hub_manifest["requires_forwarding"])
        self.assertTrue(hub_manifest["requires_nat"])
        self.assertTrue(hub_manifest["requires_fail_closed_egress"])
        self.assertEqual(hub_manifest["mesh_binding"]["gateway_node_id"], "hub-air")
        self.assertEqual(hub_manifest["mesh_binding"]["wireguard_interface"], "hub-air")
        self.assertEqual(hub_manifest["mesh_binding"]["gateway_address"], "10.99.0.254/32")
        self.assertEqual(hub_manifest["mesh_binding"]["gateway_public_key"], PUBLIC_A)
        self.assertEqual(hub_manifest["mesh_binding"]["cutover_epoch"], 3)
        self.assertEqual(
            hub_manifest["mesh_binding"]["authorized_source_addresses"],
            ["10.99.0.241/32"],
        )
        self.assertEqual(
            hub_manifest["mesh_binding"]["wireguard_peer_bindings"],
            [
                {
                    "node_id": "leaf-backup",
                    "address": "10.99.0.242/32",
                    "public_key": PUBLIC_C,
                },
                {
                    "node_id": "leaf-home",
                    "address": "10.99.0.241/32",
                    "public_key": PUBLIC_B,
                },
            ],
        )

        direct_egress = nord_egress_document()
        direct_egress["egress"]["authorized_leaf_ids"] = ["leaf-backup"]
        direct_normalized = mesh.validate_document(direct_egress)
        direct_leaf = next(
            node for node in direct_normalized["nodes"] if node["id"] == "leaf-backup"
        )
        _, direct_peers = parse_wg_quick(
            mesh._render_wg_quick(direct_normalized, direct_leaf, PRIVATE_B)
        )
        self.assertEqual(direct_peers[0]["AllowedIPs"], "0.0.0.0/0, ::/0")
        self.assertEqual(direct_peers[0]["Endpoint"], "hub.example.com:51821")

    def test_peer_transit_routes_only_the_recovery_overlay(self) -> None:
        document = active_document()
        document["mesh"]["peer_transit"] = True
        document["nodes"][1]["platform"] = "linux"
        normalized = mesh.validate_document(document)
        leaf = next(node for node in normalized["nodes"] if node["id"] == "leaf-home")
        _, peers = parse_wg_quick(mesh._render_wg_quick(normalized, leaf, PRIVATE_B))
        self.assertEqual(peers[0]["AllowedIPs"], "10.99.0.240/28")
        hub = next(node for node in normalized["nodes"] if node["id"] == "hub-air")
        manifest = json.loads(mesh._render_manifest(normalized, hub, "hub-air.conf"))
        self.assertTrue(manifest["requires_forwarding"])
        self.assertFalse(manifest["requires_nat"])

        macos_hub = active_document()
        macos_hub["mesh"]["peer_transit"] = True
        with self.assertRaisesRegex(mesh.MeshError, "requires a Linux hub"):
            mesh.validate_document(macos_hub)

    def test_node_id_is_safe_for_wg_quick_interface_and_filename(self) -> None:
        document = active_document()
        for invalid in ["A", "a" * 16, "../escape", ".hidden", "has_underscore", ""]:
            with self.subTest(invalid=invalid):
                candidate = copy.deepcopy(document)
                candidate["nodes"][0]["id"] = invalid
                with self.assertRaises(mesh.MeshError):
                    mesh.validate_document(candidate)
        self.assertEqual(mesh._validate_node_id("a" * 15), "a" * 15)

    def test_schema_rejects_duplicate_identity_and_non_host_routes(self) -> None:
        mutations = []

        duplicate_id = active_document()
        duplicate_id["nodes"][2]["id"] = "leaf-home"
        mutations.append(duplicate_id)

        duplicate_address = active_document()
        duplicate_address["nodes"][2]["address"] = "10.99.0.241/32"
        mutations.append(duplicate_address)

        duplicate_key = active_document()
        duplicate_key["nodes"][2]["public_key"] = PUBLIC_B
        mutations.append(duplicate_key)

        broad_address = active_document()
        broad_address["nodes"][0]["address"] = "10.99.0.241/28"
        mutations.append(broad_address)

        default_route = active_document()
        default_route["nodes"][0]["allowed_ips"] = ["0.0.0.0/0"]
        mutations.append(default_route)

        for candidate in mutations:
            with self.subTest(candidate=candidate):
                with self.assertRaises(mesh.MeshError):
                    mesh.validate_document(candidate)

    def test_schema_requires_one_hub_and_fixed_manual_failover(self) -> None:
        no_hub = active_document()
        no_hub["nodes"][1]["role"] = "leaf"
        two_hubs = active_document()
        two_hubs["nodes"][0]["role"] = "hub"
        automatic = active_document()
        automatic["failover_mode"] = "automatic"
        zero_epoch = active_document()
        zero_epoch["cutover_epoch"] = 0
        for candidate in [no_hub, two_hubs, automatic, zero_epoch]:
            with self.subTest(candidate=candidate):
                with self.assertRaises(mesh.MeshError):
                    mesh.validate_document(candidate)

    def test_schema_requires_unexpired_canonical_expiry(self) -> None:
        reference = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
        expired = active_document()
        expired["expires_at"] = "2029-12-31T23:59:59Z"
        offset = active_document()
        offset["expires_at"] = "2099-01-01T00:00:00+00:00"
        null_expiry = active_document()
        null_expiry["expires_at"] = None
        too_distant = active_document()
        too_distant["expires_at"] = "2030-02-02T00:00:01Z"
        for candidate in [expired, offset, null_expiry, too_distant]:
            with self.subTest(candidate=candidate):
                with self.assertRaises(mesh.MeshError):
                    mesh.validate_document(candidate, now=reference)

    def test_default_render_paths_are_generation_scoped(self) -> None:
        config_dir = self.root / "config" / "wireguard"
        config_dir.mkdir(parents=True, mode=0o700)
        config = config_dir / "mesh.local.json"
        document = active_document()
        config.write_text(json.dumps(document), encoding="utf-8")
        config.chmod(0o600)

        key_dir = config_dir / "mesh.local.d" / "keys"
        key_dir.mkdir(parents=True, mode=0o700)
        key = key_dir / "hub-air.key"
        key.write_text(f"{PRIVATE_A}\n", encoding="ascii")
        key.chmod(0o600)

        first = self.run_cli(
            "render",
            "--node-id",
            "hub-air",
            "--wg-binary",
            os.fspath(self.fake_wg),
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        generation_seven = config_dir / "mesh.local.d" / "rendered" / "generation-7"
        self.assertTrue((generation_seven / "hub-air" / "hub-air.conf").is_file())

        document["generation"] = 8
        document["cutover_epoch"] = 4
        config.write_text(json.dumps(document), encoding="utf-8")
        config.chmod(0o600)
        second = self.run_cli(
            "render",
            "--node-id",
            "hub-air",
            "--wg-binary",
            os.fspath(self.fake_wg),
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        generation_eight = config_dir / "mesh.local.d" / "rendered" / "generation-8"
        self.assertTrue((generation_eight / "hub-air" / "hub-air.conf").is_file())
        self.assertTrue((generation_seven / "hub-air" / "hub-air.conf").is_file())

    def test_load_document_rejects_duplicate_json_keys(self) -> None:
        config = self.root / "mesh.local.json"
        config.write_text(
            '{"schema_version":1,"schema_version":1}',
            encoding="utf-8",
        )
        config.chmod(0o600)
        with self.assertRaisesRegex(mesh.MeshError, "duplicate JSON key"):
            mesh.load_document(config)

    def test_schema_v1_migrates_in_memory_without_rewriting_source(self) -> None:
        legacy = legacy_document()
        config = self.write_json("legacy.local.json", legacy)
        before = config.read_bytes()
        normalized, source_version = mesh.load_document_with_source(config)
        self.assertEqual(source_version, 1)
        self.assertEqual(normalized["schema_version"], 2)
        self.assertEqual(normalized["egress"], {"mode": "disabled", "gateway_node_id": None})
        self.assertFalse(normalized["mesh"]["peer_transit"])
        hub = next(node for node in normalized["nodes"] if node["role"] == "hub")
        self.assertEqual(hub["platform"], "macos")
        self.assertNotIn("hub_transport", hub)
        leaves = [node for node in normalized["nodes"] if node["role"] == "leaf"]
        self.assertEqual({node["hub_transport"]["mode"] for node in leaves}, {"nord-meshnet"})
        self.assertEqual(
            {node["hub_transport"]["endpoint"] for node in leaves},
            {"100.64.10.5:51821"},
        )
        self.assertEqual(config.read_bytes(), before)

        result = self.run_cli("validate", "--config", os.fspath(config))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("schema-v1 was migrated", result.stderr)
        self.assertIn("valid schema-v2", result.stdout)
        self.assertEqual(config.read_bytes(), before)

        legacy_direct = legacy_document()
        legacy_direct["nodes"][1]["underlay_endpoint"] = "[192.168.50.3]:051821"
        normalized_direct = mesh.validate_document(legacy_direct)
        direct_leaves = [node for node in normalized_direct["nodes"] if node["role"] == "leaf"]
        self.assertEqual(
            {node["hub_transport"]["endpoint"] for node in direct_leaves},
            {"192.168.50.3:51821"},
        )
        self.assertEqual({node["hub_transport"]["mode"] for node in direct_leaves}, {"direct"})

    def test_schema_version_rejects_boolean_float_and_string_aliases(self) -> None:
        for version in (True, False, 1.0, 2.0, "1", "2"):
            with self.subTest(version=version):
                document = active_document()
                document["schema_version"] = version
                with self.assertRaisesRegex(mesh.MeshError, "schema_version"):
                    mesh.validate_document(document)

    def test_nord_egress_requires_linux_hub_exact_gateway_and_leaf_scope(self) -> None:
        invalid_documents = []

        macos_gateway = nord_egress_document()
        macos_gateway["nodes"][1]["platform"] = "macos"
        invalid_documents.append(macos_gateway)

        leaf_gateway = nord_egress_document()
        leaf_gateway["egress"]["gateway_node_id"] = "leaf-home"
        invalid_documents.append(leaf_gateway)

        unknown_authorized = nord_egress_document()
        unknown_authorized["egress"]["authorized_leaf_ids"] = ["not-present"]
        invalid_documents.append(unknown_authorized)

        hub_authorized = nord_egress_document()
        hub_authorized["egress"]["authorized_leaf_ids"] = ["hub-air"]
        invalid_documents.append(hub_authorized)

        duplicate_authorized = nord_egress_document()
        duplicate_authorized["egress"]["authorized_leaf_ids"] = [
            "leaf-home",
            "leaf-home",
        ]
        invalid_documents.append(duplicate_authorized)

        empty_authorized = nord_egress_document()
        empty_authorized["egress"]["authorized_leaf_ids"] = []
        invalid_documents.append(empty_authorized)

        unsafe_dns = nord_egress_document()
        unsafe_dns["egress"]["dns_servers"] = ["192.168.1.1"]
        invalid_documents.append(unsafe_dns)

        ipv6_passthrough = nord_egress_document()
        ipv6_passthrough["egress"]["ipv6_policy"] = "passthrough"
        invalid_documents.append(ipv6_passthrough)

        transit_egress = nord_egress_document()
        transit_egress["mesh"]["peer_transit"] = True
        invalid_documents.append(transit_egress)

        disabled_gateway = active_document()
        disabled_gateway["egress"]["gateway_node_id"] = "hub-air"
        invalid_documents.append(disabled_gateway)

        for candidate in invalid_documents:
            with self.subTest(candidate=candidate):
                with self.assertRaises(mesh.MeshError):
                    mesh.validate_document(candidate)

    def test_schema_enforces_reserved_recovery_identity_plan(self) -> None:
        broad_subnet = active_document()
        broad_subnet["mesh"]["subnet"] = "10.99.0.0/24"

        canonical_port = active_document()
        canonical_port["mesh"]["listen_port"] = 51820
        canonical_port["nodes"][0]["hub_transport"]["endpoint"] = "100.64.10.5:51820"
        canonical_port["nodes"][2]["hub_transport"]["endpoint"] = "hub.example.com:51820"

        wrong_hub_address = active_document()
        wrong_hub_address["nodes"][1]["address"] = "10.99.0.253/32"

        canonical_server_address = active_document()
        canonical_server_address["nodes"][1]["address"] = "10.99.0.1/32"

        leaf_endpoint = active_document()
        leaf_endpoint["nodes"][1]["hub_transport"] = {
            "mode": "direct",
            "endpoint": "192.168.50.4:51821",
        }

        for candidate in [
            broad_subnet,
            canonical_port,
            wrong_hub_address,
            canonical_server_address,
            leaf_endpoint,
        ]:
            with self.subTest(candidate=candidate):
                with self.assertRaises(mesh.MeshError):
                    mesh.validate_document(candidate)

    def test_schema_separates_direct_nord_and_opaque_relay_transports(self) -> None:
        accepted_direct = [
            "192.168.50.3:51821",
            "8.8.8.8:51821",
            "8.8.8.8:443",
            "hub.example.com:51821",
            "hub.example.com:443",
            "[fd42::1]:51821",
            "[2001:4860::1]:51821",
            "[2001:4860::1]:8443",
        ]
        for endpoint in accepted_direct:
            with self.subTest(mode="direct", endpoint=endpoint):
                candidate = active_document()
                candidate["nodes"][0]["hub_transport"] = {
                    "mode": "direct",
                    "endpoint": endpoint,
                }
                normalized = mesh.validate_document(candidate)
                leaf = next(node for node in normalized["nodes"] if node["id"] == "leaf-home")
                self.assertEqual(leaf["hub_transport"]["endpoint"], endpoint)

        rejected_direct = [
            "100.64.10.5:51821",
            "10.99.0.250:51821",
            "localhost:51821",
            "http://hub.example.com:51821",
            "192.168.50.3:443",
            "[fd42::1]:443",
            "hub.example.com:0",
            "hub.example.com:65536",
            "hub.example.com:0443",
            "fd42::1:51821",
            "[192.168.50.3]:51821",
        ]
        for endpoint in rejected_direct:
            with self.subTest(mode="direct", endpoint=endpoint):
                candidate = active_document()
                candidate["nodes"][0]["hub_transport"] = {
                    "mode": "direct",
                    "endpoint": endpoint,
                }
                with self.assertRaises(mesh.MeshError):
                    mesh.validate_document(candidate)

        accepted_opaque_relays = [
            "8.8.8.8:1",
            "8.8.8.8:443",
            "relay.mesh.example.com:443",
            "[2606:4700:4700::1111]:8443",
            "relay.mesh.example.com:65535",
        ]
        for endpoint in accepted_opaque_relays:
            with self.subTest(mode="opaque-udp-relay", endpoint=endpoint):
                candidate = active_document()
                candidate["nodes"][0]["hub_transport"] = {
                    "mode": "opaque-udp-relay",
                    "endpoint": endpoint,
                }
                normalized = mesh.validate_document(candidate)
                leaf = next(node for node in normalized["nodes"] if node["id"] == "leaf-home")
                self.assertEqual(leaf["hub_transport"]["mode"], "opaque-udp-relay")
                self.assertEqual(leaf["hub_transport"]["endpoint"], endpoint)

        rejected_opaque_relays = [
            "192.168.50.3:443",
            "100.64.10.5:443",
            "10.99.0.250:443",
            "[fd42::1]:443",
            "127.0.0.1:443",
            "169.254.10.5:443",
            "224.0.0.1:443",
            "0.0.0.0:443",
            "192.0.2.1:443",
            "Relay.Example.com:443",
            "relay.example.com.:443",
            "relay.invalid:443",
            "hub.local:443",
            "node.home.arpa:443",
            "relay.internal:443",
            "relay.example:443",
            "0x7f.0.0.1:443",
            "192.168.001.2:443",
            "[2606:4700::1%en0]:443",
            "2606:4700:4700::1111:443",
            "https://relay.mesh.example.com:443",
            "relay.mesh.example.com:0",
            "relay.mesh.example.com:65536",
            "relay.mesh.example.com:0443",
        ]
        for endpoint in rejected_opaque_relays:
            with self.subTest(mode="opaque-udp-relay", endpoint=endpoint):
                candidate = active_document()
                candidate["nodes"][0]["hub_transport"] = {
                    "mode": "opaque-udp-relay",
                    "endpoint": endpoint,
                }
                with self.assertRaises(mesh.MeshError):
                    mesh.validate_document(candidate)

        for endpoint in [
            "192.168.50.3:51821",
            "8.8.8.8:51821",
            "hub.example.com:51821",
            "100.64.10.5:443",
            "100.64.10.5:51820",
            "[fd42::1]:51821",
            "10.99.0.250:51821",
        ]:
            with self.subTest(mode="nord-meshnet", endpoint=endpoint):
                candidate = active_document()
                candidate["nodes"][0]["hub_transport"] = {
                    "mode": "nord-meshnet",
                    "endpoint": endpoint,
                }
                with self.assertRaises(mesh.MeshError):
                    mesh.validate_document(candidate)

        normalized = mesh.validate_document(active_document())
        leaf = next(node for node in normalized["nodes"] if node["id"] == "leaf-home")
        self.assertEqual(leaf["hub_transport"]["mode"], "nord-meshnet")
        self.assertEqual(leaf["hub_transport"]["endpoint"], "100.64.10.5:51821")

    def test_leaf_render_preserves_external_client_port(self) -> None:
        for mode in ("direct", "opaque-udp-relay"):
            with self.subTest(mode=mode):
                document = active_document()
                document["nodes"][0]["hub_transport"] = {
                    "mode": mode,
                    "endpoint": "relay.mesh.example.com:443",
                }
                normalized = mesh.validate_document(document)
                leaf = next(
                    node for node in normalized["nodes"] if node["id"] == "leaf-home"
                )
                interface, peers = parse_wg_quick(
                    mesh._render_wg_quick(normalized, leaf, PRIVATE_B)
                )
                self.assertEqual(interface["Address"], "10.99.0.241/32")
                self.assertEqual(normalized["mesh"]["listen_port"], 51821)
                self.assertEqual(peers[0]["Endpoint"], "relay.mesh.example.com:443")
                self.assertEqual(peers[0]["PersistentKeepalive"], "25")

    def test_schema_rejects_invalid_curve25519_public_keys_and_public_overlay(self) -> None:
        invalid_base64 = active_document()
        invalid_base64["nodes"][0]["public_key"] = "not-a-key"
        all_zero = active_document()
        all_zero["nodes"][0]["public_key"] = base64.b64encode(bytes(32)).decode("ascii")
        public_overlay = active_document()
        public_overlay["mesh"]["subnet"] = "203.0.113.0/24"
        for candidate in [invalid_base64, all_zero, public_overlay]:
            with self.subTest(candidate=candidate):
                with self.assertRaises(mesh.MeshError):
                    mesh.validate_document(candidate)

    def test_private_inputs_require_owner_only_regular_files(self) -> None:
        config = self.write_json("mesh.local.json", active_document())
        config.chmod(0o644)
        with self.assertRaisesRegex(mesh.MeshError, "group or other"):
            mesh.load_document(config)

        target = self.write_json("target.local.json", active_document())
        symlink = self.root / "symlink.local.json"
        symlink.symlink_to(target)
        with self.assertRaisesRegex(mesh.MeshError, "symlink"):
            mesh.load_document(symlink)

        unsafe_parent = self.root / "unsafe"
        unsafe_parent.mkdir(mode=0o770)
        unsafe_parent.chmod(0o770)
        with self.assertRaisesRegex(mesh.MeshError, "group/world-writable"):
            mesh.initialize(unsafe_parent / "mesh.local.json")

    def test_private_paths_inside_git_worktree_must_be_ignored_and_untracked(self) -> None:
        worktree = self.root / "worktree"
        worktree.mkdir(mode=0o700)
        subprocess.run(
            ["git", "init", "-q", os.fspath(worktree)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        local_config = worktree / "mesh.local.json"
        with self.assertRaisesRegex(mesh.MeshError, "ignored by Git"):
            mesh.initialize(local_config)

        (worktree / ".gitignore").write_text("mesh.local.json\nstate/\n", encoding="utf-8")
        mesh.initialize(local_config)
        self.assertEqual(stat.S_IMODE(local_config.stat().st_mode), 0o600)

        subprocess.run(
            ["git", "-C", os.fspath(worktree), "add", "-f", "mesh.local.json"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with self.assertRaisesRegex(mesh.MeshError, "must be untracked"):
            mesh.load_document(local_config)

    def test_init_allows_safe_tracked_style_parent_but_key_state_stays_private(self) -> None:
        worktree = self.root / "default-layout"
        config_directory = worktree / "config" / "wireguard"
        config_directory.mkdir(parents=True, mode=0o755)
        config_directory.chmod(0o755)
        subprocess.run(
            ["git", "init", "-q", os.fspath(worktree)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        (worktree / ".gitignore").write_text(
            "config/wireguard/mesh.local.json\nconfig/wireguard/mesh.local.d/\n",
            encoding="utf-8",
        )

        config_path = config_directory / "mesh.local.json"
        mesh.initialize(config_path)
        self.assertEqual(stat.S_IMODE(config_directory.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)

        private_path = config_directory / "mesh.local.d" / "keys" / "hub-air.key"
        public_path = config_directory / "mesh.local.d" / "keys" / "hub-air.pub"
        with mock.patch.dict(os.environ, self.environment, clear=True):
            mesh.generate_key_pair(
                node_id="hub-air",
                private_key_path=private_path,
                public_key_path=public_path,
                wg_binary=os.fspath(self.fake_wg),
            )
        self.assertEqual(stat.S_IMODE(private_path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(public_path.stat().st_mode), 0o600)

    def test_wg_failure_and_key_mismatch_do_not_disclose_keys(self) -> None:
        config = self.write_json("mesh.local.json", active_document())
        private_key = self.write_key("hub-air.key")
        failure_environment = {**self.environment, "FAKE_WG_FAIL": "pubkey"}
        failed = self.run_cli(
            "render",
            "--config",
            os.fspath(config),
            "--node-id",
            "hub-air",
            "--private-key-file",
            os.fspath(private_key),
            "--output-dir",
            os.fspath(self.root / "failed"),
            "--wg-binary",
            os.fspath(self.fake_wg),
            environment=failure_environment,
        )
        self.assertEqual(failed.returncode, 1)
        self.assertIn("wg pubkey failed", failed.stderr)
        self.assertFalse(PRIVATE_A in failed.stdout + failed.stderr)
        self.assertFalse((self.root / "failed").exists())

        mismatch_document = active_document()
        mismatch_document["nodes"][1]["public_key"] = PUBLIC_D
        mismatch_config = self.write_json("mismatch.local.json", mismatch_document)
        mismatch = self.run_cli(
            "render",
            "--config",
            os.fspath(mismatch_config),
            "--node-id",
            "hub-air",
            "--private-key-file",
            os.fspath(private_key),
            "--output-dir",
            os.fspath(self.root / "mismatch"),
            "--wg-binary",
            os.fspath(self.fake_wg),
        )
        self.assertEqual(mismatch.returncode, 1)
        self.assertIn("does not match", mismatch.stderr)
        combined = mismatch.stdout + mismatch.stderr
        self.assertFalse(PRIVATE_A in combined)
        self.assertFalse(PUBLIC_A in combined)
        self.assertFalse(PUBLIC_D in combined)

    def test_render_rejects_non_owner_only_output_directory(self) -> None:
        config = self.write_json("mesh.local.json", active_document())
        private_key = self.write_key("hub-air.key")
        output = self.root / "rendered"
        output.mkdir(mode=0o755)
        output.chmod(0o755)
        with mock.patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaisesRegex(mesh.MeshError, "owner-only"):
                mesh.render(
                    document=mesh.load_document(config),
                    node_id="hub-air",
                    private_key_path=private_key,
                    output_dir=output,
                    wg_binary=os.fspath(self.fake_wg),
                )


if __name__ == "__main__":
    unittest.main()
