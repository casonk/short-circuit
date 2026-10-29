from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "prepare_listen_port_change.py"
SPEC = importlib.util.spec_from_file_location("prepare_listen_port_change", SCRIPT)
prep = importlib.util.module_from_spec(SPEC)
sys.modules["prepare_listen_port_change"] = prep
SPEC.loader.exec_module(prep)

SERVER = "[Interface]\nPrivateKey = SERVERKEY\nListenPort = 51820\nAddress = 10.0.0.1/24\n"
CLIENT = (
    "[Interface]\nPrivateKey = CLIENTKEY\nAddress = 10.0.0.2/32\n"
    "[Peer]\nPublicKey = PUB\nEndpoint = vpn.example.net:51820\nAllowedIPs = 10.0.0.1/32\n"
)


def make_repo(root: Path, ignore: str = "*.local.conf\nartifacts/\n") -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / ".gitignore").write_text(ignore)
    config = root / "config" / "wireguard"
    config.mkdir(parents=True)
    (config / "wg0-server.public-vpn.local.conf").write_text(SERVER)
    (config / "client-peer.air.public-vpn.local.conf").write_text(CLIENT)
    for path in config.iterdir():
        path.chmod(0o600)


class PureTests(unittest.TestCase):
    def test_parse_port_bounds(self):
        self.assertEqual(prep.parse_port("443"), 443)
        for bad in ("0", "65536", "abc", "-1"):
            with self.subTest(bad=bad), self.assertRaises(prep.PrepareError):
                prep.parse_port(bad)

    def test_endpoint_rewrite_keeps_host_and_other_ports(self):
        text = (
            "Endpoint = [2001:db8::1]:51820\nEndpoint = other.example:9999\n"
            "Endpoint = host.example:51820\n"
        )
        out = prep.with_endpoint_port(text, 51820, 4000)
        self.assertIn("Endpoint = [2001:db8::1]:4000", out)
        self.assertIn("Endpoint = host.example:4000", out)
        self.assertIn("Endpoint = other.example:9999", out)

    def test_listen_port_rewrite(self):
        self.assertEqual(prep.listen_port(SERVER), 51820)
        self.assertEqual(prep.listen_port(prep.with_listen_port(SERVER, 4000)), 4000)


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        make_repo(self.root)
        self.config = self.root / "config" / "wireguard"
        self.client = self.config / "client-peer.air.public-vpn.local.conf"

    def tearDown(self):
        self._tmp.cleanup()

    def test_writes_candidate_backup_and_client_without_touching_live(self):
        report = prep.prepare(self.root, 4000, Path("artifacts/out"), qr=False, stamp="T")
        candidate = self.root / "artifacts" / "out" / "wg0-server.public-vpn.local.conf"
        self.assertIn("ListenPort = 4000", candidate.read_text())
        self.assertIn("PrivateKey = SERVERKEY", candidate.read_text())
        self.assertEqual(oct(candidate.stat().st_mode & 0o777), "0o600")
        self.assertIn(":4000", self.client.read_text())
        backup = self.client.with_name(self.client.name + ".bak-T")
        self.assertIn(":51820", backup.read_text())
        self.assertEqual(oct(backup.stat().st_mode & 0o777), "0o600")
        # the source server config is not modified
        self.assertIn("ListenPort = 51820", (self.config / "wg0-server.public-vpn.local.conf").read_text())
        self.assertNotIn("SERVERKEY", "\n".join(report))
        self.assertNotIn("CLIENTKEY", "\n".join(report))

    def test_dry_run_writes_nothing(self):
        prep.prepare(self.root, 4000, Path("artifacts/out"), qr=False, dry_run=True)
        self.assertFalse((self.root / "artifacts").exists())
        self.assertIn(":51820", self.client.read_text())

    def test_same_port_changes_nothing(self):
        report = prep.prepare(self.root, 51820, Path("artifacts/out"), qr=False)
        self.assertIn("nothing to change", report[-1])

    def test_client_on_other_port_is_left_alone(self):
        self.client.write_text(CLIENT.replace("51820", "7777"))
        report = prep.prepare(self.root, 4000, Path("artifacts/out"), qr=False)
        self.assertIn(":7777", self.client.read_text())
        self.assertTrue(any("no Endpoint on port 51820" in line for line in report))

    def test_refuses_unignored_files_and_output(self):
        (self.root / ".gitignore").write_text("artifacts/\n")
        with self.assertRaises(prep.PrepareError):
            prep.prepare(self.root, 4000, Path("artifacts/out"), qr=False)
        (self.root / ".gitignore").write_text("*.local.conf\n")
        with self.assertRaises(prep.PrepareError):
            prep.prepare(self.root, 4000, Path("tracked-out"), qr=False)

    def test_servers_that_disagree_are_refused(self):
        (self.config / "wg0-server.lan-vpn.local.conf").write_text(SERVER.replace("51820", "6000"))
        with self.assertRaises(prep.PrepareError):
            prep.prepare(self.root, 4000, Path("artifacts/out"), qr=False)

    def test_cli_reports_bad_port(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--new-port", "99999", "--root", str(self.root)],
            capture_output=True, text=True, check=False, env={**os.environ},
        )  # fmt: skip
        self.assertEqual(result.returncode, 2)
        self.assertIn("out of range", result.stderr)


if __name__ == "__main__":
    unittest.main()
