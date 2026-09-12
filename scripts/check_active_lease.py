#!/usr/bin/env python3
"""Answer "is this host the active hub?" by checking the ACID fencing lease.

The v4 dual-hub mesh shares one virtual hub identity across a primary and one or
more standbys. Exactly one host may activate that identity at a time; the one
allowed to is the holder of a fenced, quorum-backed lease. This tool is the
read-side check: it asks the lease provider "am I the current fence holder for
`<lease_id>`?" and exits 0 iff yes.

It is the concrete implementation of the seams already in place:
  * the v4 manifest's `requires_active_lease` (a hub host must hold the lease
    before wg-quick up);
  * update_mesh_ddns.py's `--check-active-command` (only the active hub updates
    the client DNS record).

Decouple + fail-closed, matching the rest of the repo:
  * the tracked code speaks only a generic `http-acid-lease` contract; the
    concrete lease provider, its endpoint, and its mTLS identity live in an
    owner-only, git-ignored local config, so no private component is named here;
  * ANY ambiguity -- an error, an unhealthy/absent quorum, a missing fence, or a
    holder that is not this node -- resolves to "not active" (exit 1). Only an
    unambiguous "this node holds the current fence" is exit 0. This is what keeps
    a shared hub identity from going split-brain.

The provider must expose: GET {url}/leases/{lease_id} ->
  {"holder": "<node_id>", "epoch": <int>, "healthy": <bool>}
Active iff healthy is true and holder equals this host's node_id.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

DEFAULT_CONFIG = Path("config/wireguard/fencing.local.json")
MAX_CONFIG_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 64 * 1024
NODE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,14}$")
LEASE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
CONFIG_FIELDS = {"lease_id", "node_id", "provider"}
PROVIDER_FIELDS = {"kind", "url"}
PROVIDER_OPTIONAL = {"timeout_seconds", "tls"}
TLS_FIELDS = {"cert", "key", "ca"}

# A GET returning parsed JSON, injectable so tests need no network or TLS.
HttpGet = Callable[[str, "dict[str, Any] | None", int], Any]


class LeaseError(Exception):
    """A safe, user-facing configuration failure (distinct from 'not active')."""


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LeaseError(f"{label} must be a JSON object")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise LeaseError(f"{label} must be a non-empty string")
    return value


def _read_owner_only(path: Path) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = absolute.lstat()
    except FileNotFoundError as error:
        raise LeaseError(f"local config does not exist: {absolute}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LeaseError(f"local config must be a regular file, not a symlink: {absolute}")
    if metadata.st_uid != os.geteuid():
        raise LeaseError(f"local config must be owned by the current user: {absolute}")
    if metadata.st_mode & 0o077:
        raise LeaseError(f"local config must not grant group or other permissions: {absolute}")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise LeaseError(f"local config exceeds its maximum allowed size: {absolute}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read(MAX_CONFIG_BYTES + 1)
    finally:
        os.close(descriptor)


def load_config(path: Path) -> dict[str, Any]:
    raw = _read_owner_only(path)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LeaseError("fencing config must be valid UTF-8 JSON") from error
    return validate_config(document)


def validate_config(document: Any) -> dict[str, Any]:
    root = _require_object(document, "fencing config")
    missing = CONFIG_FIELDS - root.keys()
    unknown = root.keys() - CONFIG_FIELDS
    if missing:
        raise LeaseError(f"fencing config is missing field(s): {', '.join(sorted(missing))}")
    if unknown:
        raise LeaseError(f"fencing config has unsupported field(s): {', '.join(sorted(unknown))}")

    lease_id = _require_string(root["lease_id"], "lease_id")
    if not LEASE_ID_RE.fullmatch(lease_id):
        raise LeaseError(f"lease_id must match {LEASE_ID_RE.pattern}")
    node_id = _require_string(root["node_id"], "node_id")
    if not NODE_ID_RE.fullmatch(node_id):
        raise LeaseError(f"node_id must match {NODE_ID_RE.pattern}")

    provider = _require_object(root["provider"], "provider")
    p_missing = PROVIDER_FIELDS - provider.keys()
    p_unknown = provider.keys() - PROVIDER_FIELDS - PROVIDER_OPTIONAL
    if p_missing:
        raise LeaseError(f"provider is missing field(s): {', '.join(sorted(p_missing))}")
    if p_unknown:
        raise LeaseError(f"provider has unsupported field(s): {', '.join(sorted(p_unknown))}")
    if _require_string(provider["kind"], "provider.kind") != "http-acid-lease":
        raise LeaseError("provider.kind must be http-acid-lease")
    url = _require_string(provider["url"], "provider.url")
    if not url.startswith("https://"):
        raise LeaseError("provider.url must be an https:// URL")

    normalized_provider: dict[str, Any] = {"kind": "http-acid-lease", "url": url.rstrip("/")}
    timeout = provider.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
        raise LeaseError("provider.timeout_seconds must be an integer from 1 through 60")
    normalized_provider["timeout_seconds"] = timeout
    if "tls" in provider:
        tls = _require_object(provider["tls"], "provider.tls")
        if tls.keys() - TLS_FIELDS:
            raise LeaseError("provider.tls has unsupported field(s)")
        normalized_provider["tls"] = {
            field: _require_string(tls[field], f"provider.tls.{field}")
            for field in ("cert", "key", "ca")
            if field in tls
        }
    return {"lease_id": lease_id, "node_id": node_id, "provider": normalized_provider}


def _build_ssl_context(tls: dict[str, str] | None) -> ssl.SSLContext | None:
    if not tls:
        return None
    context = ssl.create_default_context(cafile=tls.get("ca"))
    if "cert" in tls:
        context.load_cert_chain(certfile=tls["cert"], keyfile=tls.get("key"))
    return context


def _default_http_get(url: str, tls: dict[str, Any] | None, timeout: int) -> Any:
    context = _build_ssl_context(tls)
    request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise LeaseError("lease provider response is too large")
    return json.loads(payload.decode("utf-8"))


def is_active(config: dict[str, Any], http_get: HttpGet | None = None) -> tuple[bool, str]:
    """Return (active, reason). Fail-closed: any doubt yields active=False."""
    http_get = http_get or _default_http_get
    provider = config["provider"]
    url = f"{provider['url']}/leases/{config['lease_id']}"
    try:
        result = http_get(url, provider.get("tls"), provider["timeout_seconds"])
    except (urllib.error.URLError, OSError, ValueError, LeaseError) as error:
        return False, f"lease provider unreachable or invalid: {error}"
    if not isinstance(result, dict):
        return False, "lease provider returned a non-object response"
    if result.get("healthy") is not True:
        return False, "lease/quorum is not healthy"
    if not isinstance(result.get("epoch"), int) or isinstance(result.get("epoch"), bool):
        return False, "lease response is missing a fence epoch"
    holder = result.get("holder")
    if holder != config["node_id"]:
        return False, f"active hub is {holder!r}, not this node {config['node_id']!r}"
    return True, f"this node holds lease {config['lease_id']!r} at epoch {result['epoch']}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Exit 0 iff this host holds the ACID fencing lease (is the active hub)."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--quiet", action="store_true", help="suppress the status line on stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
    except LeaseError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2  # configuration error is distinct from "not active"
    active, reason = is_active(config)
    if not args.quiet:
        print(json.dumps({"active": active, "reason": reason}, sort_keys=True))
    return 0 if active else 1


if __name__ == "__main__":
    raise SystemExit(main())
