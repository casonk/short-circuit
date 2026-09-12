from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "hub_activation_guard.sh"


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


class HubActivationGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="hub-guard-")
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "actions.log"
        self.marker = self.root / "iface-up"  # present iff the interface is "up"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _env(self, *, up: bool, lease_code: int, ddns_code: int = 0) -> dict[str, str]:
        if up:
            self.marker.write_text("", encoding="utf-8")
        # fake wg: `wg show <iface>` exits 0 iff the marker exists (interface up).
        _write_exec(
            self.bin / "wg",
            f'#!/usr/bin/env bash\n'
            f'if [[ "$1" == "show" ]]; then [[ -f "{self.marker}" ]]; exit $?; fi\n'
            f'exit 0\n',
        )
        # fake wg-quick: up creates the marker, down removes it; both are logged.
        _write_exec(
            self.bin / "wg-quick",
            f'#!/usr/bin/env bash\n'
            f'echo "wg-quick $*" >> "{self.log}"\n'
            f'if [[ "$1" == "up" ]]; then : > "{self.marker}"; '
            f'elif [[ "$1" == "down" ]]; then rm -f "{self.marker}"; fi\n',
        )
        _write_exec(
            self.bin / "lease",
            f'#!/usr/bin/env bash\necho lease >> "{self.log}"\nexit {lease_code}\n',
        )
        _write_exec(
            self.bin / "ddns",
            f'#!/usr/bin/env bash\necho ddns >> "{self.log}"\nexit {ddns_code}\n',
        )
        return {
            **os.environ,
            "HUB_INTERFACE": "wg0",
            "WG_BINARY": str(self.bin / "wg"),
            "WG_QUICK_BINARY": str(self.bin / "wg-quick"),
            "LEASE_CHECK_COMMAND": str(self.bin / "lease"),
            "DDNS_UPDATE_COMMAND": str(self.bin / "ddns"),
        }

    def _run(self, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT)], env=env, text=True, capture_output=True, check=False
        )

    def _log(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    def test_fence_held_and_down_brings_up_and_refreshes_dns(self) -> None:
        result = self._run(self._env(up=False, lease_code=0))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())  # interface came up
        self.assertIn("wg-quick up wg0", self._log())
        self.assertIn("ddns", self._log())

    def test_fence_held_and_up_is_idempotent_but_still_refreshes_dns(self) -> None:
        result = self._run(self._env(up=True, lease_code=0))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())
        self.assertNotIn("wg-quick up", self._log())  # no redundant bring-up
        self.assertIn("ddns", self._log())

    def test_fence_lost_while_up_tears_down(self) -> None:
        result = self._run(self._env(up=True, lease_code=1))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())  # interface torn down
        self.assertIn("wg-quick down wg0", self._log())
        self.assertNotIn("ddns", self._log())  # DDNS only runs when active

    def test_not_fence_holder_and_down_is_a_noop(self) -> None:
        result = self._run(self._env(up=False, lease_code=1))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertNotIn("wg-quick", self._log())

    def test_lease_check_error_is_fail_closed_and_tears_down(self) -> None:
        # Exit 2 = the lease check's config-error code; must be treated as
        # "not the holder", not as "active".
        result = self._run(self._env(up=True, lease_code=2))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertIn("wg-quick down wg0", self._log())

    def test_ddns_failure_does_not_fail_the_guard_or_drop_the_interface(self) -> None:
        result = self._run(self._env(up=False, lease_code=0, ddns_code=1))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())  # interface stays up despite DDNS error
        self.assertIn("warning", result.stdout.lower() + result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
