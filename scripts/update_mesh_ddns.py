#!/usr/bin/env python3
"""Keep the mesh's client-facing DNS name pointed at the active hub's WAN IP.

The schema-v4 dual-hub mesh gives every leaf one stable `client_endpoint` (a DNS
name), so a phone imports a single profile that survives both hub failover and a
changing home WAN IP. This updater is the piece that keeps that name current: it
detects the host's public IP and publishes it to the record, only when it has
changed.

Design constraints, matching the rest of this repo:
  * stdlib only (urllib), no third-party dependencies;
  * the config is an owner-only, git-ignored local file (it carries an API
    token) distributed by the portfolio's encrypted config store; nothing
    secret is tracked;
  * it must run only on the *active* hub. Enforcement of "am I active" is the
    acid-lease fence (provider named only in local config); until that lands,
    pass --check-active-command
    with the command that exits 0 only on the lease holder, and wire this into
    the post-activation path. Without it the updater assumes the caller already
    fenced.

It performs a real DNS side effect, so it is not "render-only"; --dry-run reports
the intended change without calling the provider.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

DEFAULT_CONFIG = Path("config/wireguard/ddns.local.json")
MAX_CONFIG_BYTES = 64 * 1024
HTTP_TIMEOUT_SECONDS = 15
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
CONFIG_FIELDS = {"fqdn", "provider", "record_type", "ttl", "ip_source"}
CLOUDFLARE_FIELDS = {"api_token", "zone_id"}
GENERIC_FIELDS = {"url_template"}
OPTIONAL_CLOUDFLARE = {"record_id"}
OPTIONAL_GENERIC = {"basic_auth_user", "basic_auth_password", "state_file"}

# An HTTP call: (method, url, headers, body) -> parsed JSON (or None for empty).
HttpFn = Callable[[str, str, dict[str, str], bytes | None], Any]


class DdnsError(Exception):
    """A safe, user-facing DDNS failure."""


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DdnsError(f"{label} must be a JSON object")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DdnsError(f"{label} must be a non-empty string")
    return value


def _require_https_url(value: Any, label: str) -> str:
    url = _require_string(value, label)
    if not url.startswith("https://"):
        raise DdnsError(f"{label} must be an https:// URL")
    return url


def _validate_fqdn(value: Any, label: str = "fqdn") -> str:
    host = _require_string(value, label).lower()
    if not host.isascii() or host.endswith(".") or "." not in host or len(host) > 253:
        raise DdnsError(f"{label} must be a fully qualified DNS name without a trailing dot")
    if not all(DNS_LABEL_RE.fullmatch(part) for part in host.split(".")):
        raise DdnsError(f"{label} is not a canonical DNS name")
    return host


def _read_owner_only(path: Path) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = absolute.lstat()
    except FileNotFoundError as error:
        raise DdnsError(f"local config does not exist: {absolute}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DdnsError(f"local config must be a regular file, not a symlink: {absolute}")
    if metadata.st_uid != os.geteuid():
        raise DdnsError(f"local config must be owned by the current user: {absolute}")
    if metadata.st_mode & 0o077:
        raise DdnsError(f"local config must not grant group or other permissions: {absolute}")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise DdnsError(f"local config exceeds its maximum allowed size: {absolute}")
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
        raise DdnsError("ddns config must be valid UTF-8 JSON") from error
    return validate_config(document)


def validate_config(document: Any) -> dict[str, Any]:
    root = _require_object(document, "ddns config")
    provider = _require_string(root.get("provider"), "provider")
    if provider == "cloudflare":
        provider_fields, optional = CLOUDFLARE_FIELDS, OPTIONAL_CLOUDFLARE
    elif provider == "generic-url":
        provider_fields, optional = GENERIC_FIELDS, OPTIONAL_GENERIC
    else:
        raise DdnsError("provider must be cloudflare or generic-url")

    expected = CONFIG_FIELDS | provider_fields
    missing = expected - root.keys()
    unknown = root.keys() - expected - optional
    if missing:
        raise DdnsError(f"ddns config is missing field(s): {', '.join(sorted(missing))}")
    if unknown:
        raise DdnsError(f"ddns config has unsupported field(s): {', '.join(sorted(unknown))}")

    fqdn = _validate_fqdn(root["fqdn"])
    record_type = _require_string(root["record_type"], "record_type")
    if record_type not in {"A", "AAAA"}:
        raise DdnsError("record_type must be A or AAAA")
    ttl = root["ttl"]
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 30 <= ttl <= 86400:
        raise DdnsError("ttl must be an integer from 30 through 86400 seconds")
    ip_source = _require_https_url(root["ip_source"], "ip_source")

    normalized: dict[str, Any] = {
        "fqdn": fqdn,
        "provider": provider,
        "record_type": record_type,
        "ttl": ttl,
        "ip_source": ip_source,
    }
    if provider == "cloudflare":
        normalized["api_token"] = _require_string(root["api_token"], "api_token")
        normalized["zone_id"] = _require_string(root["zone_id"], "zone_id")
        if "record_id" in root:
            normalized["record_id"] = _require_string(root["record_id"], "record_id")
    else:
        template = _require_https_url(root["url_template"], "url_template")
        if "{ip}" not in template:
            raise DdnsError("url_template must contain the {ip} placeholder")
        normalized["url_template"] = template
        for field in ("basic_auth_user", "basic_auth_password"):
            if field in root:
                normalized[field] = _require_string(root[field], field)
        if "state_file" in root:
            normalized["state_file"] = _require_string(root["state_file"], "state_file")
    return normalized


def _default_http(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            payload = response.read(MAX_CONFIG_BYTES + 1)
    except urllib.error.URLError as error:
        raise DdnsError(f"{method} {url} failed: {error}") from error
    if not payload:
        return None
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return payload.decode("utf-8", "replace")


def _validate_ip(value: str, record_type: str, label: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise DdnsError(f"{label} is not a valid IP address") from error
    want_v4 = record_type == "A"
    if isinstance(address, ipaddress.IPv4Address) != want_v4:
        raise DdnsError(f"{label} does not match record_type {record_type}")
    if not address.is_global:
        raise DdnsError(f"{label} must be a global (public) address")
    return address.compressed


def detect_public_ip(config: dict[str, Any], http: HttpFn) -> str:
    result = http("GET", config["ip_source"], {"Accept": "text/plain"}, None)
    text = result if isinstance(result, str) else json.dumps(result)
    # Accept a bare IP or a JSON body like {"ip": "..."}.
    candidate = text.strip()
    if candidate.startswith("{"):
        try:
            candidate = str(json.loads(candidate).get("ip", "")).strip()
        except json.JSONDecodeError:
            candidate = ""
    return _validate_ip(candidate, config["record_type"], "detected public IP")


def _cloudflare_current(config: dict[str, Any], http: HttpFn) -> tuple[str, str | None]:
    token = config["api_token"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    zone = config["zone_id"]
    base = f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records"
    if "record_id" in config:
        result = http("GET", f"{base}/{config['record_id']}", headers, None)
        record = _require_object(result, "cloudflare response").get("result") or {}
        return config["record_id"], record.get("content")
    query = f"{base}?type={config['record_type']}&name={config['fqdn']}"
    result = _require_object(http("GET", query, headers, None), "cloudflare response")
    records = result.get("result") or []
    if not records:
        raise DdnsError("cloudflare returned no matching DNS record; set record_id or create it")
    return records[0]["id"], records[0].get("content")


def _cloudflare_update(config: dict[str, Any], record_id: str, ip: str, http: HttpFn) -> None:
    token = config["api_token"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    zone = config["zone_id"]
    url = f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{record_id}"
    body = json.dumps(
        {
            "type": config["record_type"],
            "name": config["fqdn"],
            "content": ip,
            "ttl": config["ttl"],
            "proxied": False,
        }
    ).encode("utf-8")
    result = _require_object(http("PUT", url, headers, body), "cloudflare response")
    if not result.get("success", False):
        raise DdnsError("cloudflare rejected the DNS update")


def _generic_state_ip(config: dict[str, Any]) -> str | None:
    if "state_file" not in config:
        return None
    path = Path(config["state_file"])
    try:
        return _read_owner_only(path).decode("ascii").strip() or None
    except DdnsError:
        return None


def _generic_update(config: dict[str, Any], ip: str, http: HttpFn) -> None:
    url = config["url_template"].replace("{ip}", ip)
    headers = {"Accept": "text/plain"}
    if "basic_auth_user" in config:
        raw = f"{config['basic_auth_user']}:{config.get('basic_auth_password', '')}".encode("utf-8")
        headers["Authorization"] = f"Basic {base64.b64encode(raw).decode('ascii')}"
    http("GET", url, headers, None)
    if "state_file" in config:
        _write_owner_only(Path(config["state_file"]), f"{ip}\n".encode("ascii"))


def _write_owner_only(path: Path, contents: bytes) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(descriptor)
        os.chmod(absolute, 0o600, follow_symlinks=False)
    finally:
        os.close(descriptor)


def _run_active_check(command: str) -> bool:
    try:
        result = subprocess.run(
            ["/bin/sh", "-c", command],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DdnsError("active-hub check could not run") from error
    return result.returncode == 0


def update(
    config: dict[str, Any],
    *,
    dry_run: bool = False,
    force: bool = False,
    http: HttpFn | None = None,
    active_check_command: str | None = None,
) -> dict[str, Any]:
    """Publish the current public IP to the mesh DNS record if it changed."""
    http = http or _default_http
    if active_check_command is not None and not _run_active_check(active_check_command):
        return {"action": "skipped", "reason": "not the active hub", "fqdn": config["fqdn"]}

    desired_ip = detect_public_ip(config, http)

    record_id: str | None = None
    if config["provider"] == "cloudflare":
        record_id, current_ip = _cloudflare_current(config, http)
    else:
        current_ip = _generic_state_ip(config)

    if current_ip == desired_ip and not force:
        return {"action": "unchanged", "ip": desired_ip, "fqdn": config["fqdn"]}
    if dry_run:
        return {
            "action": "would-update",
            "ip": desired_ip,
            "from": current_ip,
            "fqdn": config["fqdn"],
        }

    if config["provider"] == "cloudflare":
        assert record_id is not None
        _cloudflare_update(config, record_id, desired_ip, http)
    else:
        _generic_update(config, desired_ip, http)
    return {"action": "updated", "ip": desired_ip, "from": current_ip, "fqdn": config["fqdn"]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Update the mesh client-endpoint DNS record to the active hub's public IP."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report the intended change without calling the provider",
    )
    parser.add_argument(
        "--force", action="store_true", help="publish even if the record already matches"
    )
    parser.add_argument(
        "--check-active-command",
        help="shell command that must exit 0 for this host to be the active hub (fencing seam)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        outcome = update(
            config,
            dry_run=args.dry_run,
            force=args.force,
            active_check_command=args.check_active_command,
        )
    except DdnsError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(outcome, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
