from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "update_mesh_ddns.py"
SPEC = importlib.util.spec_from_file_location("update_mesh_ddns", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
ddns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ddns)


def cloudflare_config() -> dict[str, object]:
    return {
        "fqdn": "mesh.example.com",
        "provider": "cloudflare",
        "record_type": "A",
        "ttl": 60,
        "ip_source": "https://ip.example.com",
        "api_token": "token-value",
        "zone_id": "zone1",
    }


def generic_config() -> dict[str, object]:
    return {
        "fqdn": "mesh.example.com",
        "provider": "generic-url",
        "record_type": "A",
        "ttl": 60,
        "ip_source": "https://ip.example.com",
        "url_template": "https://dyndns.example.com/update?myip={ip}",
    }


def make_http(detected: object, current: str | None, capture: list | None = None):
    capture = capture if capture is not None else []

    def http(method, url, headers, body):
        capture.append((method, url, headers, body))
        if url == "https://ip.example.com":
            return detected
        if "api.cloudflare.com" in url and method == "GET":
            return {"result": [{"id": "rec1", "content": current}]}
        if "api.cloudflare.com" in url and method == "PUT":
            return {"success": True}
        return None

    http.capture = capture  # type: ignore[attr-defined]
    return http


class ValidateConfigTest(unittest.TestCase):
    def test_valid_configs_normalize(self) -> None:
        self.assertEqual(ddns.validate_config(cloudflare_config())["provider"], "cloudflare")
        self.assertEqual(ddns.validate_config(generic_config())["provider"], "generic-url")

    def test_rejections(self) -> None:
        cases = {
            "bad provider": ({**cloudflare_config(), "provider": "bogus"}, "provider"),
            "http ip_source": ({**cloudflare_config(), "ip_source": "http://x"}, "https"),
            "bad ttl": ({**cloudflare_config(), "ttl": 5}, "ttl"),
            "bad record_type": ({**cloudflare_config(), "record_type": "TXT"}, "record_type"),
            "bad fqdn": ({**cloudflare_config(), "fqdn": "nope"}, "DNS"),
            "missing token": (
                {k: v for k, v in cloudflare_config().items() if k != "api_token"},
                "missing",
            ),
            "unknown field": ({**cloudflare_config(), "surprise": 1}, "unsupported"),
            "template without ip": (
                {**generic_config(), "url_template": "https://x/update"},
                "{ip}",
            ),
        }
        for name, (document, needle) in cases.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(ddns.DdnsError, needle):
                    ddns.validate_config(document)


class DetectIpTest(unittest.TestCase):
    def test_accepts_bare_and_json_ip(self) -> None:
        config = ddns.validate_config(cloudflare_config())
        self.assertEqual(ddns.detect_public_ip(config, make_http("9.9.9.9", None)), "9.9.9.9")
        self.assertEqual(
            ddns.detect_public_ip(config, make_http('{"ip": "9.9.9.9"}', None)), "9.9.9.9"
        )

    def test_rejects_private_and_wrong_family(self) -> None:
        config = ddns.validate_config(cloudflare_config())
        with self.assertRaisesRegex(ddns.DdnsError, "global"):
            ddns.detect_public_ip(config, make_http("192.168.1.9", None))
        with self.assertRaisesRegex(ddns.DdnsError, "record_type"):
            ddns.detect_public_ip(config, make_http("2606:4700:4700::1111", None))


class UpdateTest(unittest.TestCase):
    def test_cloudflare_updates_only_on_change(self) -> None:
        config = ddns.validate_config(cloudflare_config())

        capture: list = []
        changed = ddns.update(config, http=make_http("9.9.9.9", "1.1.1.1", capture))
        self.assertEqual(changed["action"], "updated")
        self.assertEqual(changed["ip"], "9.9.9.9")
        self.assertTrue(any(m == "PUT" for m, *_ in capture))

        unchanged = ddns.update(config, http=make_http("9.9.9.9", "9.9.9.9"))
        self.assertEqual(unchanged["action"], "unchanged")

        dry = ddns.update(config, dry_run=True, http=make_http("9.9.9.9", "1.1.1.1"))
        self.assertEqual(dry["action"], "would-update")

        forced_cap: list = []
        forced = ddns.update(config, force=True, http=make_http("9.9.9.9", "9.9.9.9", forced_cap))
        self.assertEqual(forced["action"], "updated")
        self.assertTrue(any(m == "PUT" for m, *_ in forced_cap))

    def test_cloudflare_put_carries_token_and_ttl(self) -> None:
        config = ddns.validate_config(cloudflare_config())
        capture: list = []
        ddns.update(config, http=make_http("9.9.9.9", "1.1.1.1", capture))
        put = next(entry for entry in capture if entry[0] == "PUT")
        _, url, headers, body = put
        self.assertIn("zone1", url)
        self.assertEqual(headers["Authorization"], "Bearer token-value")
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(payload["content"], "9.9.9.9")
        self.assertEqual(payload["ttl"], 60)
        self.assertFalse(payload["proxied"])

    def test_generic_update_substitutes_ip(self) -> None:
        config = ddns.validate_config(generic_config())
        capture: list = []
        result = ddns.update(config, http=make_http("9.9.9.9", None, capture))
        self.assertEqual(result["action"], "updated")
        self.assertTrue(any("myip=9.9.9.9" in url for _, url, *_ in capture))

    def test_active_check_gates_the_update(self) -> None:
        config = ddns.validate_config(cloudflare_config())
        capture: list = []
        skipped = ddns.update(
            config,
            http=make_http("9.9.9.9", "1.1.1.1", capture),
            active_check_command="false",
        )
        self.assertEqual(skipped["action"], "skipped")
        # Nothing was fetched or published when this host is not the active hub.
        self.assertEqual(capture, [])
        ran = ddns.update(
            config,
            http=make_http("9.9.9.9", "1.1.1.1"),
            active_check_command="true",
        )
        self.assertEqual(ran["action"], "updated")


class OwnerOnlyLoadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="ddns-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, mode: int) -> Path:
        path = self.root / "ddns.local.json"
        path.write_text(json.dumps(cloudflare_config()), encoding="utf-8")
        path.chmod(mode)
        return path

    def test_owner_only_config_loads(self) -> None:
        path = self._write(0o600)
        self.assertEqual(ddns.load_config(path)["fqdn"], "mesh.example.com")

    def test_group_or_world_readable_config_is_rejected(self) -> None:
        path = self._write(0o644)
        with self.assertRaisesRegex(ddns.DdnsError, "group or other"):
            ddns.load_config(path)

    def test_symlinked_config_is_rejected(self) -> None:
        target = self._write(0o600)
        link = self.root / "link.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(ddns.DdnsError, "symlink"):
            ddns.load_config(link)


if __name__ == "__main__":
    unittest.main()
