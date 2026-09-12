from __future__ import annotations

import importlib.util
import json
import tempfile
import urllib.error
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_active_lease.py"
SPEC = importlib.util.spec_from_file_location("check_active_lease", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
lease = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lease)

import unittest  # noqa: E402  (after dynamic import of the module under test)


def base_config() -> dict[str, object]:
    return {
        "lease_id": "mesh-hub",
        "node_id": "linux",
        "provider": {"kind": "http-acid-lease", "url": "https://10.99.0.254:9443"},
    }


def responder(payload: object):
    def http_get(url, tls, timeout):
        assert url == "https://10.99.0.254:9443/leases/mesh-hub", url
        if isinstance(payload, Exception):
            raise payload
        return payload

    return http_get


def _with_provider(**overrides: object) -> dict[str, object]:
    document = base_config()
    document["provider"] = {"kind": "http-acid-lease", "url": "https://x", **overrides}
    return document


class ValidateConfigTest(unittest.TestCase):
    def test_valid_config_normalizes(self) -> None:
        config = lease.validate_config(
            _with_provider(url="https://10.99.0.254:9443/", timeout_seconds=9)
        )
        # Trailing slash trimmed; timeout carried through.
        self.assertEqual(config["provider"]["url"], "https://10.99.0.254:9443")
        self.assertEqual(config["provider"]["timeout_seconds"], 9)

    def test_rejections(self) -> None:
        cases = {
            "http url": (_with_provider(url="http://x"), "https"),
            "bad kind": (_with_provider(kind="file"), "http-acid-lease"),
            "missing provider": ({"lease_id": "mesh-hub", "node_id": "linux"}, "missing"),
            "unknown field": ({**base_config(), "surprise": 1}, "unsupported"),
            "bad lease_id": ({**base_config(), "lease_id": "Mesh_Hub"}, "lease_id"),
            "bad node_id": ({**base_config(), "node_id": "Linux Hub"}, "node_id"),
            "bad timeout": (_with_provider(timeout_seconds=0), "timeout"),
        }
        for name, (document, needle) in cases.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(lease.LeaseError, needle):
                    lease.validate_config(document)


class IsActiveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = lease.validate_config(base_config())

    def test_active_only_when_this_node_holds_a_healthy_fence(self) -> None:
        held = responder({"holder": "linux", "epoch": 7, "healthy": True})
        active, _ = lease.is_active(self.config, held)
        self.assertTrue(active)

    def test_fail_closed_cases(self) -> None:
        cases = {
            "another holder": {"holder": "air", "epoch": 7, "healthy": True},
            "quorum unhealthy": {"holder": "linux", "epoch": 7, "healthy": False},
            "missing epoch": {"holder": "linux", "healthy": True},
            "epoch is bool": {"holder": "linux", "epoch": True, "healthy": True},
            "missing holder": {"epoch": 7, "healthy": True},
            "non-object": "garbage",
            "provider unreachable": urllib.error.URLError("connection refused"),
            "provider timeout": TimeoutError("timed out"),
        }
        for name, payload in cases.items():
            with self.subTest(case=name):
                active, reason = lease.is_active(self.config, responder(payload))
                self.assertFalse(active, reason)


class LoadConfigOwnerOnlyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="lease-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, mode: int) -> Path:
        path = self.root / "fencing.local.json"
        path.write_text(json.dumps(base_config()), encoding="utf-8")
        path.chmod(mode)
        return path

    def test_owner_only_loads(self) -> None:
        self.assertEqual(lease.load_config(self._write(0o600))["node_id"], "linux")

    def test_group_or_world_readable_rejected(self) -> None:
        with self.assertRaisesRegex(lease.LeaseError, "group or other"):
            lease.load_config(self._write(0o644))

    def test_symlink_rejected(self) -> None:
        target = self._write(0o600)
        link = self.root / "link.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(lease.LeaseError, "symlink"):
            lease.load_config(link)


class MainExitCodesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="lease-main-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_config_error_returns_2(self) -> None:
        missing = self.root / "does-not-exist.json"
        self.assertEqual(lease.main(["--config", str(missing), "--quiet"]), 2)


if __name__ == "__main__":
    unittest.main()
