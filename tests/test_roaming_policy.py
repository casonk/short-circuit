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
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "render_roaming_policy.py"
SPEC = importlib.util.spec_from_file_location("render_roaming_policy", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)

PUBLIC_A = base64.b64encode(bytes([0x11]) * 32).decode("ascii")
PUBLIC_B = base64.b64encode(bytes([0x22]) * 32).decode("ascii")
PRIVATE_SENTINEL = base64.b64encode(bytes([0x99]) * 32).decode("ascii")
EXPIRY = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)


def active_mesh() -> dict[str, object]:
    return {
        "schema_version": 2,
        "generation": 7,
        "mesh": {
            "name": "roaming-test",
            "subnet": "10.99.0.240/28",
            "listen_port": 51821,
            "peer_transit": False,
        },
        "failover_mode": "manual-static",
        "cutover_epoch": 3,
        "expires_at": EXPIRY,
        "egress": {"mode": "disabled", "gateway_node_id": None},
        "nodes": [
            {
                "id": "leaf-a",
                "role": "leaf",
                "platform": "ios",
                "address": "10.99.0.241/32",
                "public_key": PUBLIC_B,
                "hub_transport": {
                    "mode": "opaque-udp-relay",
                    "endpoint": "relay.mesh.example.com:443",
                },
            },
            {
                "id": "hub-a",
                "role": "hub",
                "platform": "macos",
                "address": "10.99.0.254/32",
                "public_key": PUBLIC_A,
            },
        ],
    }


def legacy_mesh() -> dict[str, object]:
    return {
        "schema_version": 1,
        "generation": 7,
        "mesh": {
            "name": "roaming-test",
            "subnet": "10.99.0.240/28",
            "listen_port": 51821,
        },
        "failover_mode": "manual-static",
        "cutover_epoch": 3,
        "expires_at": EXPIRY,
        "nodes": [
            {
                "id": "leaf-a",
                "role": "leaf",
                "address": "10.99.0.241/32",
                "public_key": PUBLIC_B,
            },
            {
                "id": "hub-a",
                "role": "hub",
                "address": "10.99.0.254/32",
                "public_key": PUBLIC_A,
                "underlay_endpoint": "192.168.50.10:51821",
            },
        ],
    }


def network_classes() -> list[dict[str, object]]:
    return [
        {"id": "trusted-wlan", "local_peer_access": True},
        {"id": "isolated-wlan", "local_peer_access": False},
        {"id": "offsite", "local_peer_access": False},
    ]


def audit_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "generation": 2,
        "enforcement": "audit-only",
        "nord_role": "egress-only",
        "mesh_generation": 7,
        "hub_node_id": "hub-a",
        "network_classes": network_classes(),
        "paths": [
            {
                "id": "lan-primary",
                "kind": "lan-direct",
                "endpoint": "192.168.50.10:51821",
                "available_on": ["trusted-wlan"],
            }
        ],
        "selection": {
            "strategy": "stable-primary",
            "primary_path_id": "lan-primary",
        },
    }


def required_document() -> dict[str, object]:
    document = audit_document()
    document["enforcement"] = "required"
    document["paths"] = [
        {
            "id": "relay-primary",
            "kind": "opaque-udp-relay",
            "endpoint": "relay.mesh.example.com:443",
            "available_on": ["offsite", "trusted-wlan", "isolated-wlan"],
        },
        {
            "id": "lan-direct",
            "kind": "lan-direct",
            "endpoint": "192.168.50.10:51821",
            "available_on": ["trusted-wlan"],
        },
    ]
    document["selection"]["primary_path_id"] = "relay-primary"
    return document


class RoamingPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_context = tempfile.TemporaryDirectory(prefix="short-circuit-roaming-")
        self.root = Path(self.temp_context.name)
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temp_context.cleanup()

    def write_json(self, name: str, document: dict[str, object]) -> Path:
        path = self.root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o600)
        return path

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, os.fspath(SCRIPT_PATH), *arguments],
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_invalid(self, document: dict[str, object], pattern: str) -> None:
        with self.assertRaisesRegex(policy.RoamingPolicyError, pattern):
            policy.validate_document(document, mesh_document=active_mesh())

    def test_tracked_example_is_exactly_inert(self) -> None:
        example_path = REPO_ROOT / "config" / "wireguard" / "roaming-policy.example.json"
        example = json.loads(example_path.read_text(encoding="utf-8"))
        self.assertEqual(example, policy.inert_document())
        self.assertEqual(policy.validate_document(example), policy.inert_document())

    def test_generation_zero_is_exact_and_needs_no_mesh(self) -> None:
        inert = policy.inert_document()
        self.assertEqual(policy.validate_document(inert), inert)

        invalid_documents: list[dict[str, object]] = []
        for key, value in (
            ("enforcement", "required"),
            ("nord_role", "carrier"),
            ("mesh_generation", 1),
            ("hub_node_id", "hub-a"),
            ("network_classes", network_classes()),
            ("paths", audit_document()["paths"]),
        ):
            changed = copy.deepcopy(inert)
            changed[key] = value
            invalid_documents.append(changed)
        changed = copy.deepcopy(inert)
        changed["selection"]["primary_path_id"] = "relay-primary"
        invalid_documents.append(changed)
        for invalid in invalid_documents:
            with self.subTest(invalid=invalid):
                with self.assertRaises(policy.RoamingPolicyError):
                    policy.validate_document(invalid)

    def test_strict_top_level_scalars_and_active_mesh_requirement(self) -> None:
        document = audit_document()
        with self.assertRaisesRegex(policy.RoamingPolicyError, "requires a WireGuard mesh"):
            policy.validate_document(document)

        invalid_values = (
            ("schema_version", True, "schema_version"),
            ("schema_version", 2, "schema_version"),
            ("generation", True, "generation"),
            ("generation", -1, "generation"),
            ("enforcement", "automatic", "enforcement"),
            ("nord_role", "mesh-carrier", "nord_role"),
            ("mesh_generation", True, "mesh_generation"),
            ("mesh_generation", 8, "must match"),
            ("hub_node_id", "hub-b", "mesh hub"),
        )
        for key, value, pattern in invalid_values:
            changed = copy.deepcopy(document)
            changed[key] = value
            with self.subTest(key=key, value=value):
                self.assert_invalid(changed, pattern)
        changed = copy.deepcopy(document)
        changed["unsupported"] = True
        self.assert_invalid(changed, "unsupported field")

        inert_mesh = policy.MESH.inert_document()
        with self.assertRaisesRegex(policy.RoamingPolicyError, "active WireGuard mesh"):
            policy.validate_document(document, mesh_document=inert_mesh)

    def test_network_classes_are_exact_and_normalized(self) -> None:
        document = audit_document()
        document["network_classes"].reverse()
        normalized = policy.validate_document(document, mesh_document=active_mesh())
        self.assertEqual(
            [item["id"] for item in normalized["network_classes"]],
            list(policy.NETWORK_CLASS_ORDER),
        )

        invalid_classes = [
            network_classes()[:-1],
            [*network_classes(), {"id": "cellular", "local_peer_access": False}],
            [network_classes()[0], network_classes()[0], *network_classes()[1:]],
        ]
        wrong_flag = network_classes()
        wrong_flag[1]["local_peer_access"] = True
        invalid_classes.append(wrong_flag)
        extra_field = network_classes()
        extra_field[0]["ssid"] = "secret"
        invalid_classes.append(extra_field)
        for classes in invalid_classes:
            changed = audit_document()
            changed["network_classes"] = classes
            with self.subTest(classes=classes):
                with self.assertRaises(policy.RoamingPolicyError):
                    policy.validate_document(changed, mesh_document=active_mesh())

    def test_valid_path_kinds_and_endpoint_forms(self) -> None:
        document = audit_document()
        document["paths"] = [
            {
                "id": "lan-v4",
                "kind": "lan-direct",
                "endpoint": "10.0.0.5:51821",
                "available_on": ["trusted-wlan"],
            },
            {
                "id": "lan-v6",
                "kind": "lan-direct",
                "endpoint": "[fd00::5]:51821",
                "available_on": ["trusted-wlan"],
            },
            {
                "id": "public-v4",
                "kind": "public-direct",
                "endpoint": "8.8.8.8:443",
                "available_on": ["offsite"],
            },
            {
                "id": "public-v6",
                "kind": "public-direct",
                "endpoint": "[2606:4700:4700::1111]:8443",
                "available_on": ["isolated-wlan", "offsite"],
            },
            {
                "id": "relay-fqdn",
                "kind": "opaque-udp-relay",
                "endpoint": "relay.mesh.example.com:443",
                "available_on": ["offsite", "trusted-wlan", "isolated-wlan"],
            },
        ]
        document["selection"]["primary_path_id"] = "relay-fqdn"
        normalized = policy.validate_document(document, mesh_document=active_mesh())
        self.assertEqual(
            [path["id"] for path in normalized["paths"]],
            ["lan-v4", "lan-v6", "public-v4", "public-v6", "relay-fqdn"],
        )
        relay = normalized["paths"][-1]
        self.assertEqual(relay["endpoint"], "relay.mesh.example.com:443")
        self.assertEqual(relay["available_on"], list(policy.NETWORK_CLASS_ORDER))

    def test_endpoint_and_path_invariants_reject_unsafe_values(self) -> None:
        invalid_cases = (
            ("lan-direct", "100.64.0.1:51821", ["trusted-wlan"], "RFC1918/ULA"),
            ("lan-direct", "relay.example.com:51821", ["trusted-wlan"], "literal"),
            ("lan-direct", "192.168.1.2:51820", ["trusted-wlan"], "listen_port"),
            ("lan-direct", "192.168.1.2:51821", ["offsite"], "exactly trusted-wlan"),
            ("public-direct", "192.168.1.2:51821", ["offsite"], "global IP"),
            ("public-direct", "100.64.1.2:51821", ["offsite"], "RFC6598"),
            ("public-direct", "192.168.001.2:51821", ["offsite"], "disguise"),
            ("public-direct", "[fd00::2]:51821", ["offsite"], "global IP"),
            ("public-direct", "127.0.0.1:51821", ["offsite"], "global IP"),
            ("public-direct", "Relay.Example.com:51821", ["offsite"], "lowercase"),
            ("public-direct", "relay.example.com.:51821", ["offsite"], "trailing dot"),
            ("public-direct", "relay.invalid:51821", ["offsite"], "special-use"),
            ("public-direct", "hub.local:51821", ["offsite"], "special-use"),
            (
                "public-direct",
                "localhost.localhost:51821",
                ["offsite"],
                "special-use",
            ),
            ("public-direct", "node.home.arpa:51821", ["offsite"], "special-use"),
            ("public-direct", "relay.internal:51821", ["offsite"], "special-use"),
            ("public-direct", "relay.example:51821", ["offsite"], "special-use"),
            ("public-direct", "0x7f.0.0.1:51821", ["offsite"], "disguise"),
            (
                "public-direct",
                "[2606:4700::1%en0]:51821",
                ["offsite"],
                "interface-scoped",
            ),
            ("public-direct", "relay.example.com:0", ["offsite"], "1 through 65535"),
            ("public-direct", "relay.example.com:65536", ["offsite"], "1 through 65535"),
            ("public-direct", "relay.example.com:0443", ["offsite"], "canonical integer"),
            (
                "opaque-udp-relay",
                "https://relay.example.com:51821",
                ["offsite"],
                "host and port",
            ),
            ("opaque-udp-relay", "2606:4700:4700::1111:51821", ["offsite"], "brackets"),
        )
        for kind, endpoint, available, pattern in invalid_cases:
            document = audit_document()
            document["paths"][0].update(
                {"kind": kind, "endpoint": endpoint, "available_on": available}
            )
            with self.subTest(endpoint=endpoint):
                self.assert_invalid(document, pattern)

        documents: list[dict[str, object]] = []
        duplicate_id = audit_document()
        duplicate_id["paths"].append(copy.deepcopy(duplicate_id["paths"][0]))
        documents.append(duplicate_id)
        duplicate_class = audit_document()
        duplicate_class["paths"][0]["available_on"] = ["trusted-wlan", "trusted-wlan"]
        documents.append(duplicate_class)
        unknown_class = audit_document()
        unknown_class["paths"][0]["available_on"] = ["cellular"]
        documents.append(unknown_class)
        empty_classes = audit_document()
        empty_classes["paths"][0]["available_on"] = []
        documents.append(empty_classes)
        extra_field = audit_document()
        extra_field["paths"][0]["priority"] = 1
        documents.append(extra_field)
        for invalid in documents:
            with self.subTest(invalid=invalid):
                with self.assertRaises(policy.RoamingPolicyError):
                    policy.validate_document(invalid, mesh_document=active_mesh())

    def test_stable_primary_required_and_audit_coverage(self) -> None:
        normalized = policy.validate_document(required_document(), mesh_document=active_mesh())
        coverage = policy.coverage_report(normalized)
        self.assertTrue(coverage["coverage_evaluated"])
        self.assertTrue(coverage["all_classes_have_a_declared_path"])
        self.assertTrue(coverage["primary_available_on_all_classes"])
        self.assertFalse(coverage["automatic_failover"])

        alignment = policy._mesh_transport_alignment(
            normalized["paths"],
            normalized["selection"],
            policy.MESH.validate_document(active_mesh()),
        )
        self.assertTrue(alignment["all_mesh_leaf_transports_select_primary"])

        audit = policy.validate_document(audit_document(), mesh_document=active_mesh())
        coverage = policy.coverage_report(audit)
        self.assertEqual(coverage["uncovered_network_classes"], ["isolated-wlan", "offsite"])
        self.assertEqual(coverage["primary_unavailable_on"], ["isolated-wlan", "offsite"])
        self.assertFalse(coverage["automatic_failover"])

        empty = audit_document()
        empty["paths"] = []
        empty["selection"]["primary_path_id"] = None
        empty_normalized = policy.validate_document(empty, mesh_document=active_mesh())
        self.assertEqual(
            policy.coverage_report(empty_normalized)["uncovered_network_classes"],
            list(policy.NETWORK_CLASS_ORDER),
        )

        collective = required_document()
        collective["enforcement"] = "audit-only"
        collective["selection"]["primary_path_id"] = "lan-direct"
        collective_normalized = policy.validate_document(
            collective, mesh_document=active_mesh()
        )
        collective_coverage = policy.coverage_report(collective_normalized)
        self.assertEqual(collective_coverage["uncovered_network_classes"], [])
        self.assertEqual(
            collective_coverage["primary_unavailable_on"],
            ["isolated-wlan", "offsite"],
        )

        required_null = required_document()
        required_null["selection"]["primary_path_id"] = None
        self.assert_invalid(required_null, "requires a primary")
        required_partial = required_document()
        required_partial["selection"]["primary_path_id"] = "lan-direct"
        self.assert_invalid(required_partial, "every network class")
        unknown = audit_document()
        unknown["selection"]["primary_path_id"] = "missing"
        self.assert_invalid(unknown, "declared path")
        wrong_strategy = audit_document()
        wrong_strategy["selection"]["strategy"] = "automatic-failover"
        self.assert_invalid(wrong_strategy, "stable-primary")

        misaligned_mesh = active_mesh()
        misaligned_mesh["nodes"][0]["hub_transport"]["endpoint"] = (
            "other.mesh.example.com:443"
        )
        with self.assertRaisesRegex(policy.RoamingPolicyError, "every mesh leaf"):
            policy.validate_document(required_document(), mesh_document=misaligned_mesh)

        wrong_mode_mesh = active_mesh()
        wrong_mode_mesh["nodes"][0]["hub_transport"] = {
            "mode": "direct",
            "endpoint": "relay.mesh.example.com:443",
        }
        with self.assertRaisesRegex(policy.RoamingPolicyError, "every mesh leaf"):
            policy.validate_document(required_document(), mesh_document=wrong_mode_mesh)

        nord_mesh = active_mesh()
        nord_mesh["nodes"][0]["hub_transport"] = {
            "mode": "nord-meshnet",
            "endpoint": "100.64.0.10:51821",
        }
        with self.assertRaisesRegex(policy.RoamingPolicyError, "every mesh leaf"):
            policy.validate_document(required_document(), mesh_document=nord_mesh)

    def test_mesh_transport_alignment_matches_path_kind_to_transport_mode(self) -> None:
        cases = (
            (
                "lan-direct",
                "direct",
                "192.168.50.10:51821",
                ["trusted-wlan"],
            ),
            (
                "public-direct",
                "direct",
                "relay.mesh.example.com:443",
                list(policy.NETWORK_CLASS_ORDER),
            ),
            (
                "opaque-udp-relay",
                "opaque-udp-relay",
                "relay.mesh.example.com:443",
                list(policy.NETWORK_CLASS_ORDER),
            ),
        )
        for path_kind, transport_mode, endpoint, available_on in cases:
            with self.subTest(path_kind=path_kind, transport_mode=transport_mode):
                mesh_document = active_mesh()
                mesh_document["nodes"][0]["hub_transport"] = {
                    "mode": transport_mode,
                    "endpoint": endpoint,
                }
                paths = [
                    {
                        "id": "primary-path",
                        "kind": path_kind,
                        "endpoint": endpoint,
                        "available_on": available_on,
                    }
                ]
                alignment = policy._mesh_transport_alignment(
                    paths,
                    {"strategy": "stable-primary", "primary_path_id": "primary-path"},
                    policy.MESH.validate_document(mesh_document),
                )
                self.assertTrue(alignment["all_mesh_leaf_transports_select_primary"])

        for path_kind, transport_mode in (
            ("public-direct", "opaque-udp-relay"),
            ("opaque-udp-relay", "direct"),
        ):
            with self.subTest(path_kind=path_kind, wrong_transport_mode=transport_mode):
                endpoint = "relay.mesh.example.com:443"
                mesh_document = active_mesh()
                mesh_document["nodes"][0]["hub_transport"] = {
                    "mode": transport_mode,
                    "endpoint": endpoint,
                }
                mismatch = policy._mesh_transport_alignment(
                    [
                        {
                            "id": "primary-path",
                            "kind": path_kind,
                            "endpoint": endpoint,
                            "available_on": list(policy.NETWORK_CLASS_ORDER),
                        }
                    ],
                    {"strategy": "stable-primary", "primary_path_id": "primary-path"},
                    policy.MESH.validate_document(mesh_document),
                )
                self.assertFalse(mismatch["all_mesh_leaf_transports_select_primary"])

    def test_legacy_mesh_is_normalized_into_the_same_canonical_binding(self) -> None:
        document = audit_document()
        current_normalized = policy.validate_document(document, mesh_document=active_mesh())
        legacy_normalized = policy.validate_document(document, mesh_document=legacy_mesh())
        self.assertEqual(current_normalized, legacy_normalized)

        current_plan = policy._build_plan(
            current_normalized, policy.MESH.validate_document(active_mesh())
        )
        legacy_plan = policy._build_plan(
            legacy_normalized, policy.MESH.validate_document(legacy_mesh())
        )
        self.assertEqual(
            current_plan["mesh_binding"], policy.MESH.build_mesh_binding(active_mesh())
        )
        self.assertEqual(
            legacy_plan["mesh_binding"], policy.MESH.build_mesh_binding(legacy_mesh())
        )
        self.assertEqual(
            current_plan["mesh_binding"]["wireguard_peer_bindings"],
            legacy_plan["mesh_binding"]["wireguard_peer_bindings"],
        )

    def test_render_is_owner_only_inert_key_free_and_refuses_overwrite(self) -> None:
        output = self.root / "rendered"
        with mock.patch.object(
            policy.MESH.subprocess,
            "run",
            side_effect=AssertionError("render must not invoke commands"),
        ):
            json_path, markdown_path = policy.render(
                document=required_document(),
                mesh_document=active_mesh(),
                output_dir=output,
            )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(json_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(markdown_path.stat().st_mode), 0o600)

        plan_text = json_path.read_text(encoding="utf-8")
        markdown = markdown_path.read_text(encoding="utf-8")
        plan = json.loads(plan_text)
        self.assertEqual(plan["mesh_document_sha256"], plan["mesh_binding"]["document_sha256"])
        self.assertFalse(plan["activation_performed"])
        self.assertFalse(plan["router_changes_performed"])
        self.assertFalse(plan["nord_carrier"])
        self.assertFalse(plan["reachability_verified"])
        self.assertFalse(plan["wireguard_profiles_updated"])
        self.assertTrue(
            plan["mesh_transport_alignment"][
                "all_mesh_leaf_transports_select_primary"
            ]
        )
        self.assertFalse(plan["coverage"]["automatic_failover"])
        self.assertIn("Automatic failover: `false`", markdown)
        self.assertIn("Reachability verified: `false`", markdown)
        self.assertIn("WireGuard profiles updated: `false`", markdown)
        self.assertIn("outbound egress only", markdown)
        for rendered in (plan_text, markdown):
            self.assertNotIn(PRIVATE_SENTINEL, rendered)
            self.assertNotIn("PrivateKey", rendered)
            self.assertNotIn("0.0.0.0/0", rendered)
            self.assertNotIn("::/0", rendered)
            self.assertNotIn("activation_performed: true", rendered.lower())

        with self.assertRaisesRegex(policy.RoamingPolicyError, "refusing to overwrite"):
            policy.render(
                document=required_document(),
                mesh_document=active_mesh(),
                output_dir=output,
            )

    def test_render_preflights_both_targets_before_writing(self) -> None:
        output = self.root / "partial"
        output.mkdir(mode=0o700)
        existing = output / "roaming-plan.md"
        existing.write_text("operator-owned\n", encoding="utf-8")
        existing.chmod(0o600)
        with self.assertRaisesRegex(policy.RoamingPolicyError, "refusing to overwrite"):
            policy.render(
                document=required_document(),
                mesh_document=active_mesh(),
                output_dir=output,
            )
        self.assertFalse((output / "roaming-plan.json").exists())
        self.assertEqual(existing.read_text(encoding="utf-8"), "operator-owned\n")

    # -- atomic generation-directory commit and orphan-staging recovery ------------

    def render_into(self, output: Path):
        return policy.render(
            document=required_document(), mesh_document=active_mesh(), output_dir=output
        )

    def staging_dirs(self, parent: Path) -> list[Path]:
        return sorted(parent.glob(".*.staging-*"))

    def test_render_publishes_the_pair_by_renaming_a_complete_staging_directory(self) -> None:
        output = self.root / "atomic"
        seen: list[tuple[Path, Path, set[str], bool]] = []
        real_rename = os.rename

        def recording(source, target):
            seen.append(
                (Path(source), Path(target), {p.name for p in Path(source).iterdir()}, Path(target).exists())
            )
            return real_rename(source, target)

        with mock.patch.object(policy.os, "rename", recording):
            json_path, markdown_path = self.render_into(output)
        self.assertEqual(len(seen), 1)
        staged, target, names, existed = seen[0]
        self.assertEqual(target, output)
        self.assertEqual(names, {"roaming-plan.json", "roaming-plan.md"})  # complete before the commit
        self.assertFalse(existed)  # the generation directory did not exist until the rename
        self.assertEqual(staged.parent, output.parent)
        self.assertEqual((json_path.parent, markdown_path.parent), (output, output))
        self.assertEqual(self.staging_dirs(self.root), [])

    def test_a_failure_between_the_two_files_leaves_nothing_and_a_retry_works(self) -> None:
        output = self.root / "between"
        real_write = policy.MESH._write_owner_only_new
        calls = {"n": 0}

        def second_fails(path, contents, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise policy.MESH.MeshError("simulated write failure")
            return real_write(path, contents, **kwargs)

        with mock.patch.object(policy.MESH, "_write_owner_only_new", second_fails):
            with self.assertRaisesRegex(policy.RoamingPolicyError, "simulated write failure"):
                self.render_into(output)
        self.assertFalse(output.exists())  # no half pair is ever visible
        self.assertEqual(self.staging_dirs(self.root), [])
        json_path, markdown_path = self.render_into(output)  # nothing blocks the retry
        self.assertTrue(json_path.is_file() and markdown_path.is_file())

    def test_a_crash_before_the_commit_leaves_only_staging_and_the_next_render_recovers(self) -> None:
        output = self.root / "crash"

        class Crash(BaseException):
            """Stands in for power loss: nothing after it runs."""

        with (
            mock.patch.object(policy.os, "rename", side_effect=Crash),
            mock.patch.object(policy, "_remove_staging", return_value=False),  # no cleanup in a crash
            self.assertRaises(Crash),
        ):
            self.render_into(output)
        self.assertFalse(output.exists())
        orphans = self.staging_dirs(self.root)
        self.assertEqual(len(orphans), 1)
        self.assertEqual({p.name for p in orphans[0].iterdir()}, {"roaming-plan.json", "roaming-plan.md"})
        self.assertEqual(stat.S_IMODE(orphans[0].stat().st_mode), 0o700)

        self.render_into(output)  # a retry is not blocked, and a fresh orphan is left alone
        self.assertTrue((output / "roaming-plan.json").is_file())
        self.assertEqual(self.staging_dirs(self.root), orphans)

        old = time.time() - policy.STALE_STAGING_SECONDS - 60
        os.utime(orphans[0], (old, old))
        self.render_into(self.root / "crash-next")  # an old orphan of this output is removed
        self.assertEqual(self.staging_dirs(self.root), orphans)  # different output name: untouched
        policy.recover_orphan_staging(output)
        self.assertEqual(self.staging_dirs(self.root), [])

    def test_recovery_removes_only_genuine_old_staging_directories_of_its_own_output(self) -> None:
        output = self.root / "generation-3"
        prefix = f".{output.name}.staging-"
        genuine = self.root / f"{prefix}{'a' * 16}"
        genuine.mkdir(mode=0o700)
        (genuine / "roaming-plan.json").write_text("{}", encoding="utf-8")
        decoys = {
            "bad suffix": self.root / f"{prefix}not-hex",
            "other output": self.root / f".generation-4.staging-{'b' * 16}",
            "plain file": self.root / f"{prefix}{'c' * 16}.txt",
        }
        decoys["bad suffix"].mkdir(mode=0o700)
        decoys["other output"].mkdir(mode=0o700)
        decoys["plain file"].write_text("x", encoding="utf-8")
        link = self.root / f"{prefix}{'d' * 16}"
        link.symlink_to(decoys["bad suffix"])
        open_mode = self.root / f"{prefix}{'e' * 16}"
        open_mode.mkdir(mode=0o755)
        os.chmod(open_mode, 0o755)
        extra = self.root / f"{prefix}{'f' * 16}"
        extra.mkdir(mode=0o700)
        (extra / "operator-notes.txt").write_text("keep", encoding="utf-8")
        future = time.time() + 2 * policy.STALE_STAGING_SECONDS
        removed = policy.recover_orphan_staging(output, now=future)
        self.assertEqual(removed, [genuine])
        self.assertFalse(genuine.exists())
        for label, path in decoys.items():
            self.assertTrue(path.exists(), label)
        self.assertTrue(link.is_symlink() and open_mode.is_dir() and extra.is_dir())
        self.assertEqual((extra / "operator-notes.txt").read_text(encoding="utf-8"), "keep")
        self.assertEqual(policy.recover_orphan_staging(output, now=future), [])  # nothing left to do

    def test_a_young_staging_directory_is_left_for_the_render_that_may_still_own_it(self) -> None:
        output = self.root / "generation-5"
        young = self.root / f".generation-5.staging-{'1' * 16}"
        young.mkdir(mode=0o700)
        self.assertEqual(policy.recover_orphan_staging(output), [])
        self.assertTrue(young.is_dir())

    def test_an_existing_generation_directory_is_never_replaced_or_staged_next_to(self) -> None:
        empty = self.root / "empty-generation"
        empty.mkdir(mode=0o700)
        with self.assertRaisesRegex(policy.RoamingPolicyError, "refusing to overwrite"):
            self.render_into(empty)
        self.assertEqual(list(empty.iterdir()), [])
        done = self.root / "done-generation"
        self.render_into(done)
        before = {p.name: p.read_bytes() for p in done.iterdir()}
        with self.assertRaisesRegex(policy.RoamingPolicyError, "refusing to overwrite"):
            self.render_into(done)
        self.assertEqual({p.name: p.read_bytes() for p in done.iterdir()}, before)
        self.assertEqual(self.staging_dirs(self.root), [])

    def test_a_directory_created_while_staging_wins_and_is_not_touched(self) -> None:
        output = self.root / "race"
        real_rename = os.rename

        def someone_else_first(source, target):
            Path(target).mkdir(mode=0o700)
            (Path(target) / "operator.txt").write_text("theirs", encoding="utf-8")
            return real_rename(source, target)

        with mock.patch.object(policy.os, "rename", someone_else_first):
            with self.assertRaisesRegex(policy.RoamingPolicyError, "refusing to overwrite"):
                self.render_into(output)
        self.assertEqual((output / "operator.txt").read_text(encoding="utf-8"), "theirs")
        self.assertFalse((output / "roaming-plan.json").exists())
        self.assertEqual(self.staging_dirs(self.root), [])

    def test_two_generations_stage_and_commit_independently(self) -> None:
        first, second = self.root / "generation-1", self.root / "generation-2"
        self.render_into(first)
        self.render_into(second)
        for output in (first, second):
            self.assertEqual({p.name for p in output.iterdir()}, {"roaming-plan.json", "roaming-plan.md"})
        self.assertEqual(self.staging_dirs(self.root), [])

    def test_init_validate_and_render_cli(self) -> None:
        inert_path = self.root / "inert.json"
        result = self.run_cli("init", "--policy", os.fspath(inert_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(inert_path.stat().st_mode), 0o600)
        result = self.run_cli(
            "validate", "--policy", os.fspath(inert_path), "--mesh-config", "missing.json"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("inert", result.stdout)
        self.assertIn("coverage: not evaluated", result.stdout)

        policy_path = self.write_json("policy.json", audit_document())
        mesh_path = self.write_json("mesh.json", legacy_mesh())
        result = self.run_cli(
            "validate",
            "--policy",
            os.fspath(policy_path),
            "--mesh-config",
            os.fspath(mesh_path),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("declared path gaps: isolated-wlan,offsite", result.stdout)
        self.assertIn("primary path gaps: isolated-wlan,offsite", result.stdout)
        self.assertIn("mesh transports select primary: true", result.stdout)
        self.assertIn("reachability verified: false", result.stdout)
        self.assertIn("automatic failover: false", result.stdout)

        collective = required_document()
        collective["enforcement"] = "audit-only"
        collective["selection"]["primary_path_id"] = "lan-direct"
        collective_path = self.write_json("collective.json", collective)
        result = self.run_cli(
            "validate",
            "--policy",
            os.fspath(collective_path),
            "--mesh-config",
            os.fspath(mesh_path),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("declared path gaps: none", result.stdout)
        self.assertIn("primary path gaps: isolated-wlan,offsite", result.stdout)

        output = self.root / "cli-output"
        result = self.run_cli(
            "render",
            "--policy",
            os.fspath(policy_path),
            "--mesh-config",
            os.fspath(mesh_path),
            "--output-dir",
            os.fspath(output),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((output / "roaming-plan.json").is_file())
        self.assertTrue((output / "roaming-plan.md").is_file())

        result = self.run_cli(
            "render", "--policy", os.fspath(inert_path), "--output-dir", os.fspath(output)
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("inert and cannot be rendered", result.stderr)

    def test_private_input_duplicate_keys_and_modes_are_enforced(self) -> None:
        mesh_path = self.write_json("mesh.json", active_mesh())
        policy_path = self.write_json("policy.json", audit_document())
        loaded_mesh = policy.load_mesh_document(mesh_path)
        loaded = policy.load_document(policy_path, mesh_document=loaded_mesh)
        self.assertEqual(loaded["generation"], 2)

        policy_path.chmod(0o644)
        with self.assertRaisesRegex(policy.RoamingPolicyError, "group or other"):
            policy.load_document(policy_path, mesh_document=loaded_mesh)

        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"schema_version":1,"schema_version":1}', encoding="utf-8"
        )
        duplicate.chmod(0o600)
        with self.assertRaisesRegex(policy.RoamingPolicyError, "duplicate JSON key"):
            policy.load_document(duplicate)

    def test_render_refuses_inert_policy_even_if_a_mesh_is_supplied(self) -> None:
        with self.assertRaisesRegex(policy.RoamingPolicyError, "generation 0"):
            policy.render(
                document=policy.inert_document(),
                mesh_document=active_mesh(),
                output_dir=self.root / "inert-output",
            )


if __name__ == "__main__":
    unittest.main()
