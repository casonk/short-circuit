from __future__ import annotations

import base64
import copy
import datetime as dt
import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = REPO_ROOT / "scripts" / "render_wireguard_access_bundle.py"
MESH_PATH = REPO_ROOT / "scripts" / "render_wireguard_mesh.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bundle = _load_module("render_wireguard_access_bundle", BUNDLE_PATH)
mesh = _load_module("render_wireguard_mesh_for_bundle_test", MESH_PATH)

PRIVATE_A = base64.b64encode(bytes(range(1, 33))).decode("ascii")
PUBLIC_A = base64.b64encode(bytes([0x11]) * 32).decode("ascii")
PUBLIC_B = base64.b64encode(bytes([0x22]) * 32).decode("ascii")
PUBLIC_C = base64.b64encode(bytes([0x33]) * 32).decode("ascii")
EXPIRY = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")


def mesh_document() -> dict[str, object]:
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
        "expires_at": EXPIRY,
        "egress": {"mode": "disabled", "gateway_node_id": None},
        "nodes": [
            {
                "id": "air",
                "role": "hub",
                "platform": "macos",
                "address": "10.99.0.254/32",
                "public_key": PUBLIC_A,
            },
            {
                "id": "mini",
                "role": "leaf",
                "platform": "ios",
                "address": "10.99.0.241/32",
                "public_key": PUBLIC_B,
                "hub_transport": {"mode": "direct", "endpoint": "192.168.10.125:51821"},
            },
        ],
    }


def bundle_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "generation": 7,
        "expires_at": EXPIRY,
        "client": {"id": "mini", "address": "10.99.0.241/32", "public_key": PUBLIC_B},
        "peers": [
            {
                "id": "air",
                "kind": "temporary-mesh",
                "address": "10.99.0.254/32",
                "public_key": PUBLIC_A,
                "endpoint": "192.168.10.125:51821",
            },
            {
                "id": "fed",
                "kind": "canonical-service",
                "address": "10.99.0.1/32",
                "public_key": PUBLIC_C,
                "endpoint": "home.example.net:51820",
            },
        ],
    }


class AccessBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_context = tempfile.TemporaryDirectory(prefix="short-circuit-access-bundle-")
        self.root = Path(self.temp_context.name)
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temp_context.cleanup()

    def test_valid_bundle_has_exact_disjoint_peer_routes(self) -> None:
        validated = bundle.validate_document(bundle_document(), mesh_document=mesh_document())

        self.assertEqual([peer["id"] for peer in validated["peers"]], ["air", "fed"])
        self.assertEqual(validated["client"]["id"], "mini")

    def test_temporary_peer_must_match_mesh_hub_and_client_transport(self) -> None:
        document = bundle_document()
        document["peers"][0]["endpoint"] = "192.168.10.126:51821"

        with self.assertRaisesRegex(bundle.AccessBundleError, "exactly match"):
            bundle.validate_document(document, mesh_document=mesh_document())

    def test_canonical_peer_cannot_overlap_temporary_mesh_subnet(self) -> None:
        document = bundle_document()
        document["peers"][1]["address"] = "10.99.0.242/32"

        with self.assertRaisesRegex(bundle.AccessBundleError, "outside the temporary mesh subnet"):
            bundle.validate_document(document, mesh_document=mesh_document())

    def test_bundle_requires_matching_client_identity_and_expiry(self) -> None:
        document = bundle_document()
        document["client"]["public_key"] = PUBLIC_C
        with self.assertRaisesRegex(bundle.AccessBundleError, "exactly match the active mesh leaf"):
            bundle.validate_document(document, mesh_document=mesh_document())

        document = bundle_document()
        document["expires_at"] = "2030-01-02T00:00:00Z"
        with self.assertRaisesRegex(bundle.AccessBundleError, "expiry must equal"):
            bundle.validate_document(document, mesh_document=mesh_document())

    def test_render_is_owner_only_and_key_free_except_profile(self) -> None:
        private_path = self.root / "mini.key"
        private_path.write_text(f"{PRIVATE_A}\n", encoding="ascii")
        private_path.chmod(0o600)
        output = self.root / "bundle"
        with mock.patch.object(bundle.MESH, "_run_wg", return_value=PUBLIC_B):
            profile_path, manifest_path = bundle.render(
                document=copy.deepcopy(bundle_document()),
                mesh_document=copy.deepcopy(mesh_document()),
                private_key_path=private_path,
                output_dir=output,
            )

        profile = profile_path.read_text(encoding="utf-8")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertIn("AllowedIPs = 10.99.0.254/32", profile)
        self.assertIn("AllowedIPs = 10.99.0.1/32", profile)
        self.assertNotIn("0.0.0.0/0", profile)
        self.assertNotIn("10.99.0.240/28", profile)
        self.assertNotIn(PRIVATE_A, manifest_path.read_text(encoding="utf-8"))
        self.assertFalse(manifest["activation_performed"])
        self.assertFalse(manifest["application_writer_selected"])
        self.assertEqual(stat.S_IMODE(profile_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)

    def test_render_refuses_overwrite(self) -> None:
        private_path = self.root / "mini.key"
        private_path.write_text(f"{PRIVATE_A}\n", encoding="ascii")
        private_path.chmod(0o600)
        output = self.root / "bundle"
        with mock.patch.object(bundle.MESH, "_run_wg", return_value=PUBLIC_B):
            bundle.render(
                document=bundle_document(),
                mesh_document=mesh_document(),
                private_key_path=private_path,
                output_dir=output,
            )
            with self.assertRaisesRegex(bundle.AccessBundleError, "refusing to overwrite"):
                bundle.render(
                    document=bundle_document(),
                    mesh_document=mesh_document(),
                    private_key_path=private_path,
                    output_dir=output,
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
