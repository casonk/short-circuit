#!/usr/bin/env python3
"""Validate and render a static, render-only WireGuard mesh configuration.

This module deliberately stops before activation.  It does not create an
interface, alter routes, enable forwarding, or configure NAT/firewall rules.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import datetime as dt
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
DEFAULT_CONFIG = Path("config/wireguard/mesh.local.json")
DEFAULT_STATE_ROOT = Path("config/wireguard/mesh.local.d")
MAX_CONFIG_BYTES = 1024 * 1024
MAX_KEY_BYTES = 256
WG_TIMEOUT_SECONDS = 10
MAX_ACTIVE_LIFETIME = dt.timedelta(days=31)

NODE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,14}$")
MESH_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

TOP_LEVEL_FIELDS = {
    "schema_version",
    "generation",
    "mesh",
    "failover_mode",
    "cutover_epoch",
    "expires_at",
    "nodes",
}
MESH_FIELDS = {"name", "subnet", "listen_port"}
NODE_FIELDS = {"id", "role", "address", "public_key", "underlay_endpoint"}

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
RFC6598_NETWORK = ipaddress.ip_network("100.64.0.0/10")
IPV6_ULA_NETWORK = ipaddress.ip_network("fc00::/7")
RECOVERY_OVERLAY = ipaddress.ip_network("10.99.0.240/28")
RECOVERY_HUB_ADDRESS = ipaddress.ip_address("10.99.0.254")
RECOVERY_LISTEN_PORT = 51821


class MeshError(Exception):
    """A safe, user-facing validation or rendering failure."""


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MeshError(f"{label} must be a JSON object")
    return value


def _require_exact_fields(
    value: dict[str, Any], expected: set[str], label: str, *, optional: set[str] | None = None
) -> None:
    optional = optional or set()
    missing = expected - optional - value.keys()
    unknown = value.keys() - expected
    if missing:
        raise MeshError(f"{label} is missing field(s): {', '.join(sorted(missing))}")
    if unknown:
        raise MeshError(f"{label} contains unsupported field(s): {', '.join(sorted(unknown))}")


def _require_int(value: Any, label: str, *, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MeshError(f"{label} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f" through {maximum}" if maximum is not None else " or greater"
        raise MeshError(f"{label} must be {minimum}{suffix}")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MeshError(f"{label} must be a non-empty string")
    return value


def _validate_node_id(value: Any, label: str = "node id") -> str:
    node_id = _require_string(value, label)
    if not NODE_ID_RE.fullmatch(node_id):
        raise MeshError(f"{label} must match {NODE_ID_RE.pattern} (a safe wg-quick interface name)")
    return node_id


def _decode_wireguard_key(value: Any, label: str) -> bytes:
    key = _require_string(value, label)
    try:
        decoded = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError) as error:
        raise MeshError(f"{label} must be a canonical base64 WireGuard Curve25519 key") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != key:
        raise MeshError(f"{label} must be a canonical base64 WireGuard Curve25519 key")
    if not any(decoded):
        raise MeshError(f"{label} must not be the all-zero Curve25519 key")
    return decoded


def _is_private_underlay_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv4Address):
        return any(address in network for network in RFC1918_NETWORKS) or address in RFC6598_NETWORK
    return address in IPV6_ULA_NETWORK


def _parse_underlay_endpoint(
    value: Any, label: str, overlay: ipaddress.IPv4Network, listen_port: int
) -> str:
    endpoint = _require_string(value, label)
    host: str
    port_text: str
    bracketed = endpoint.startswith("[")
    if bracketed:
        closing = endpoint.find("]")
        if closing < 0 or endpoint[closing + 1 : closing + 2] != ":":
            raise MeshError(f"{label} must be a literal private IP address and port")
        host = endpoint[1:closing]
        port_text = endpoint[closing + 2 :]
    else:
        host, separator, port_text = endpoint.rpartition(":")
        if not separator:
            raise MeshError(f"{label} must be a literal private IP address and port")

    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise MeshError(f"{label} must use a literal private IP address") from error
    if not _is_private_underlay_address(address):
        raise MeshError(f"{label} must use RFC1918, RFC6598, or IPv6 ULA private addressing")
    if isinstance(address, ipaddress.IPv6Address) and not bracketed:
        raise MeshError(f"{label} must put an IPv6 address inside brackets")
    if isinstance(address, ipaddress.IPv4Address) and address in overlay:
        raise MeshError(f"{label} must not route the overlay through itself")
    if not port_text.isascii() or not port_text.isdecimal():
        raise MeshError(f"{label} port must be an integer")
    try:
        port = int(port_text, 10)
    except ValueError as error:
        raise MeshError(f"{label} port must be an integer") from error
    if port != listen_port:
        raise MeshError(f"{label} port must equal mesh.listen_port")
    return endpoint


def _parse_expiry(value: Any, *, now: dt.datetime) -> str:
    expiry_text = _require_string(value, "expires_at")
    if not RFC3339_UTC_RE.fullmatch(expiry_text):
        raise MeshError("expires_at must use canonical UTC form YYYY-MM-DDTHH:MM:SSZ")
    try:
        expiry = dt.datetime.strptime(expiry_text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as error:
        raise MeshError("expires_at is not a valid UTC timestamp") from error
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    now_utc = now.astimezone(dt.timezone.utc)
    if expiry <= now_utc:
        raise MeshError("the active mesh document has expired")
    if expiry > now_utc + MAX_ACTIVE_LIFETIME:
        raise MeshError("expires_at must be no more than 31 days in the future")
    return expiry_text


def validate_document(document: Any, *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Validate and normalize a schema-v1 mesh document.

    The returned object contains only validated schema fields and may be used
    directly for deterministic rendering.
    """

    now = now or dt.datetime.now(dt.timezone.utc)
    root = _require_object(document, "document")
    _require_exact_fields(root, TOP_LEVEL_FIELDS, "document")

    if root["schema_version"] != SCHEMA_VERSION:
        raise MeshError(f"schema_version must be {SCHEMA_VERSION}")
    generation = _require_int(root["generation"], "generation", minimum=0)

    mesh = _require_object(root["mesh"], "mesh")
    _require_exact_fields(mesh, MESH_FIELDS, "mesh")
    mesh_name = _require_string(mesh["name"], "mesh.name")
    if not MESH_NAME_RE.fullmatch(mesh_name):
        raise MeshError(f"mesh.name must match {MESH_NAME_RE.pattern}")
    try:
        overlay = ipaddress.ip_network(_require_string(mesh["subnet"], "mesh.subnet"), strict=True)
    except ValueError as error:
        raise MeshError("mesh.subnet must be a canonical IPv4 CIDR") from error
    if not isinstance(overlay, ipaddress.IPv4Network) or overlay != RECOVERY_OVERLAY:
        raise MeshError(f"mesh.subnet must be the reserved recovery slice {RECOVERY_OVERLAY}")
    listen_port = _require_int(mesh["listen_port"], "mesh.listen_port", minimum=1, maximum=65535)
    if listen_port != RECOVERY_LISTEN_PORT:
        raise MeshError(
            f"mesh.listen_port must be the reserved recovery port {RECOVERY_LISTEN_PORT}"
        )

    if root["failover_mode"] != "manual-static":
        raise MeshError("failover_mode must be manual-static")
    cutover_epoch = _require_int(root["cutover_epoch"], "cutover_epoch", minimum=0)

    nodes_value = root["nodes"]
    if not isinstance(nodes_value, list):
        raise MeshError("nodes must be a JSON array")

    if generation == 0:
        if cutover_epoch != 0 or root["expires_at"] is not None or nodes_value:
            raise MeshError("generation 0 must be inert: epoch 0, null expiry, and no nodes")
        return {
            "schema_version": SCHEMA_VERSION,
            "generation": 0,
            "mesh": {
                "name": mesh_name,
                "subnet": str(overlay),
                "listen_port": listen_port,
            },
            "failover_mode": "manual-static",
            "cutover_epoch": 0,
            "expires_at": None,
            "nodes": [],
        }

    if cutover_epoch < 1:
        raise MeshError("an active generation requires cutover_epoch of 1 or greater")
    expires_at = _parse_expiry(root["expires_at"], now=now)
    if len(nodes_value) < 2:
        raise MeshError("an active mesh requires a hub and at least one leaf")

    normalized_nodes: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    node_addresses: set[ipaddress.IPv4Address] = set()
    public_keys: set[str] = set()
    hub_count = 0

    for index, raw_node in enumerate(nodes_value):
        label = f"nodes[{index}]"
        node = _require_object(raw_node, label)
        _require_exact_fields(node, NODE_FIELDS, label, optional={"underlay_endpoint"})

        node_id = _validate_node_id(node["id"], f"{label}.id")
        if node_id in node_ids:
            raise MeshError(f"node id {node_id!r} is duplicated")
        node_ids.add(node_id)

        role = _require_string(node["role"], f"{label}.role")
        if role not in {"hub", "leaf"}:
            raise MeshError(f"{label}.role must be hub or leaf")
        if role == "hub":
            hub_count += 1

        address_text = _require_string(node["address"], f"{label}.address")
        try:
            interface = ipaddress.ip_interface(address_text)
        except ValueError as error:
            raise MeshError(f"{label}.address must be an IPv4 /32") from error
        if not isinstance(interface, ipaddress.IPv4Interface) or interface.network.prefixlen != 32:
            raise MeshError(f"{label}.address must be an IPv4 /32")
        address = interface.ip
        if address not in overlay or address in {
            overlay.network_address,
            overlay.broadcast_address,
        }:
            raise MeshError(f"{label}.address must be a usable /32 inside mesh.subnet")
        if address in node_addresses:
            raise MeshError(f"node address {address} is duplicated")
        if role == "hub" and address != RECOVERY_HUB_ADDRESS:
            raise MeshError(f"the recovery hub must use {RECOVERY_HUB_ADDRESS}/32")
        if role == "leaf" and address == RECOVERY_HUB_ADDRESS:
            raise MeshError("a recovery leaf must use 10.99.0.241/32 through 10.99.0.253/32")
        node_addresses.add(address)

        public_key = _require_string(node["public_key"], f"{label}.public_key")
        _decode_wireguard_key(public_key, f"{label}.public_key")
        if public_key in public_keys:
            raise MeshError("node public keys must be unique")
        public_keys.add(public_key)

        endpoint: str | None = None
        if "underlay_endpoint" in node:
            if role != "hub":
                raise MeshError("only the recovery hub may declare underlay_endpoint")
            endpoint = _parse_underlay_endpoint(
                node["underlay_endpoint"], f"{label}.underlay_endpoint", overlay, listen_port
            )
        if role == "hub" and endpoint is None:
            raise MeshError("the hub requires a private underlay_endpoint")

        normalized_node: dict[str, Any] = {
            "id": node_id,
            "role": role,
            "address": f"{address}/32",
            "public_key": public_key,
        }
        if endpoint is not None:
            normalized_node["underlay_endpoint"] = endpoint
        normalized_nodes.append(normalized_node)

    if hub_count != 1:
        raise MeshError("an active mesh requires exactly one hub")

    normalized_nodes.sort(key=lambda item: item["id"])
    return {
        "schema_version": SCHEMA_VERSION,
        "generation": generation,
        "mesh": {
            "name": mesh_name,
            "subnet": str(overlay),
            "listen_port": listen_port,
        },
        "failover_mode": "manual-static",
        "cutover_epoch": cutover_epoch,
        "expires_at": expires_at,
        "nodes": normalized_nodes,
    }


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _find_worktree_root(path: Path) -> Path | None:
    absolute = _absolute(path)
    candidate = absolute if absolute.is_dir() else absolute.parent
    for parent in (candidate, *candidate.parents):
        try:
            marker = parent / ".git"
            marker.lstat()
        except FileNotFoundError:
            continue
        if marker.is_dir() or marker.is_file():
            return parent
    return None


def _check_safe_components(path: Path, *, worktree_root: Path | None) -> None:
    absolute = _absolute(path)
    if worktree_root is not None:
        anchor = _absolute(worktree_root)
        try:
            relative = absolute.relative_to(anchor)
        except ValueError as error:
            raise MeshError("local path escaped its Git worktree") from error
        candidates = [anchor]
        current = anchor
        for part in relative.parts:
            current /= part
            candidates.append(current)
    else:
        anchor = absolute if absolute.is_dir() else absolute.parent
        while not anchor.exists() and anchor != anchor.parent:
            anchor = anchor.parent
        for ancestor in anchor.parents:
            metadata = ancestor.lstat()
            if metadata.st_uid != os.geteuid():
                break
            if stat.S_ISLNK(metadata.st_mode):
                raise MeshError(f"local path must not traverse a symlink: {ancestor}")
            if stat.S_ISDIR(metadata.st_mode) and metadata.st_mode & 0o022:
                break
        candidates = [anchor]
        current = anchor
        try:
            relative = absolute.relative_to(anchor)
        except ValueError as error:
            raise MeshError("could not establish a safe local path anchor") from error
        for part in relative.parts:
            current /= part
            candidates.append(current)

    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise MeshError(f"local path must not traverse a symlink: {candidate}")
        if candidate != absolute and stat.S_ISDIR(metadata.st_mode) and metadata.st_mode & 0o022:
            raise MeshError(f"local parent directory must not be group/world-writable: {candidate}")
        if metadata.st_uid != os.geteuid():
            raise MeshError(f"local path must be owned by the current user: {candidate}")


def _git_path_must_be_private(path: Path) -> None:
    absolute = _absolute(path)
    worktree_root = _find_worktree_root(absolute)
    _check_safe_components(absolute, worktree_root=worktree_root)
    if worktree_root is None:
        return

    relative = absolute.relative_to(worktree_root)
    command_prefix = ["git", "-C", os.fspath(worktree_root)]
    try:
        tracked = subprocess.run(
            [*command_prefix, "ls-files", "--error-unmatch", "--", os.fspath(relative)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=WG_TIMEOUT_SECONDS,
        )
        ignored = subprocess.run(
            [*command_prefix, "check-ignore", "--no-index", "-q", "--", os.fspath(relative)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=WG_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise MeshError(
            "git is required to verify private local paths inside a worktree"
        ) from error

    if tracked.returncode == 0:
        raise MeshError(f"private local path must be untracked: {relative}")
    if tracked.returncode not in {0, 1}:
        raise MeshError("git could not verify whether a private local path is tracked")
    if ignored.returncode != 0:
        if ignored.returncode == 1:
            raise MeshError(f"private local path must be ignored by Git: {relative}")
        raise MeshError("git could not verify whether a private local path is ignored")


def _assert_owner_only_file(path: Path) -> os.stat_result:
    absolute = _absolute(path)
    _git_path_must_be_private(absolute)
    try:
        metadata = absolute.lstat()
    except FileNotFoundError as error:
        raise MeshError(f"local file does not exist: {absolute}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise MeshError(f"local file must be a regular file, not a symlink: {absolute}")
    if metadata.st_uid != os.geteuid():
        raise MeshError(f"local file must be owned by the current user: {absolute}")
    if metadata.st_mode & 0o077:
        raise MeshError(f"local file must not grant group or other permissions: {absolute}")
    if not metadata.st_mode & stat.S_IRUSR:
        raise MeshError(f"local file must be readable by its owner: {absolute}")
    return metadata


def _read_owner_only_file(path: Path, *, maximum_bytes: int) -> bytes:
    absolute = _absolute(path)
    expected = _assert_owner_only_file(absolute)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise MeshError(f"could not securely open local file: {absolute}") from error
    try:
        actual = os.fstat(descriptor)
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise MeshError(f"local file changed while being opened: {absolute}")
        if actual.st_size > maximum_bytes:
            raise MeshError(f"local file exceeds its maximum allowed size: {absolute}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            contents = stream.read(maximum_bytes + 1)
        if len(contents) > maximum_bytes:
            raise MeshError(f"local file exceeds its maximum allowed size: {absolute}")
        return contents
    finally:
        os.close(descriptor)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise MeshError(f"mesh config contains duplicate JSON key: {key}")
        document[key] = value
    return document


def load_document(path: Path) -> dict[str, Any]:
    raw = _read_owner_only_file(path, maximum_bytes=MAX_CONFIG_BYTES)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MeshError("mesh config must be valid UTF-8 JSON") from error
    return validate_document(document)


def _assert_target_available(path: Path) -> None:
    absolute = _absolute(path)
    _git_path_must_be_private(absolute)
    try:
        absolute.lstat()
    except FileNotFoundError:
        return
    raise MeshError(f"refusing to overwrite existing path: {absolute}")


def _ensure_private_directory(path: Path, *, owner_only: bool = True) -> Path:
    absolute = _absolute(path)
    worktree_root = _find_worktree_root(absolute)
    _check_safe_components(absolute, worktree_root=worktree_root)

    missing: list[Path] = []
    candidate = absolute
    while not candidate.exists():
        missing.append(candidate)
        candidate = candidate.parent
    metadata = candidate.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise MeshError(f"local parent must be a real directory: {candidate}")
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise MeshError(f"local parent directory is not safely owned: {candidate}")

    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError as error:
            raise MeshError(f"local directory changed while being created: {directory}") from error

    final_metadata = absolute.lstat()
    if stat.S_ISLNK(final_metadata.st_mode) or not stat.S_ISDIR(final_metadata.st_mode):
        raise MeshError(f"local output path must be a real directory: {absolute}")
    if final_metadata.st_uid != os.geteuid():
        raise MeshError(f"local output directory must be owned by the current user: {absolute}")
    if owner_only and final_metadata.st_mode & 0o077:
        raise MeshError(f"local output directory must be owner-only: {absolute}")
    if not owner_only and final_metadata.st_mode & 0o022:
        raise MeshError(f"local output directory must not be group/world-writable: {absolute}")
    return absolute


def _ensure_safe_existing_directory(path: Path) -> Path:
    absolute = _absolute(path)
    worktree_root = _find_worktree_root(absolute)
    _check_safe_components(absolute, worktree_root=worktree_root)
    try:
        metadata = absolute.lstat()
    except FileNotFoundError:
        return _ensure_private_directory(absolute, owner_only=False)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise MeshError(f"local parent must be a real directory: {absolute}")
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise MeshError(f"local parent directory is not safely owned: {absolute}")
    return absolute


def _write_owner_only_new(
    path: Path, contents: bytes, *, require_owner_only_parent: bool = True
) -> Path:
    absolute = _absolute(path)
    _assert_target_available(absolute)
    if require_owner_only_parent:
        _ensure_private_directory(absolute.parent)
    else:
        _ensure_safe_existing_directory(absolute.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags, 0o600)
    except OSError as error:
        raise MeshError(f"could not securely create local file: {absolute}") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(descriptor)
        os.chmod(absolute, 0o600, follow_symlinks=False)
    except Exception:
        with contextlib.suppress(OSError):
            absolute.unlink()
        raise
    finally:
        os.close(descriptor)
    return absolute


def _run_wg(wg_binary: str, operation: str, *, private_key: str | None = None) -> str:
    command = [wg_binary, operation]
    try:
        result = subprocess.run(
            command,
            input=None if private_key is None else f"{private_key}\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=WG_TIMEOUT_SECONDS,
            env={**os.environ, "LC_ALL": "C"},
        )
    except FileNotFoundError as error:
        raise MeshError("the WireGuard wg executable was not found") from error
    except subprocess.TimeoutExpired as error:
        raise MeshError(f"wg {operation} timed out") from error
    if result.returncode != 0:
        raise MeshError(f"wg {operation} failed")
    output = result.stdout.strip()
    _decode_wireguard_key(output, f"wg {operation} output")
    return output


def _read_private_key(path: Path) -> str:
    raw = _read_owner_only_file(path, maximum_bytes=MAX_KEY_BYTES)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise MeshError("private key file must contain one ASCII WireGuard key") from error
    lines = text.splitlines()
    if len(lines) != 1 or lines[0] != lines[0].strip():
        raise MeshError("private key file must contain exactly one WireGuard key line")
    private_key = lines[0]
    _decode_wireguard_key(private_key, "private key file")
    return private_key


def _default_private_key_path(node_id: str) -> Path:
    return DEFAULT_STATE_ROOT / "keys" / f"{node_id}.key"


def _default_public_key_path(node_id: str) -> Path:
    return DEFAULT_STATE_ROOT / "keys" / f"{node_id}.pub"


def _default_render_dir(node_id: str, generation: int) -> Path:
    return DEFAULT_STATE_ROOT / "rendered" / f"generation-{generation}" / node_id


def inert_document() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generation": 0,
        "mesh": {
            "name": "temporary-macos-host-only",
            "subnet": "10.99.0.240/28",
            "listen_port": 51821,
        },
        "failover_mode": "manual-static",
        "cutover_epoch": 0,
        "expires_at": None,
        "nodes": [],
    }


def initialize(path: Path) -> Path:
    payload = (json.dumps(inert_document(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    return _write_owner_only_new(path, payload, require_owner_only_parent=False)


def generate_key_pair(
    *, node_id: str, private_key_path: Path, public_key_path: Path, wg_binary: str
) -> tuple[Path, Path]:
    _validate_node_id(node_id)
    private_absolute = _absolute(private_key_path)
    public_absolute = _absolute(public_key_path)
    if private_absolute == public_absolute:
        raise MeshError("private and public key paths must be different")
    _assert_target_available(private_absolute)
    _assert_target_available(public_absolute)
    _ensure_private_directory(private_absolute.parent)
    _ensure_private_directory(public_absolute.parent)

    private_key = _run_wg(wg_binary, "genkey")
    public_key = _run_wg(wg_binary, "pubkey", private_key=private_key)

    private_created: Path | None = None
    try:
        private_created = _write_owner_only_new(
            private_absolute, f"{private_key}\n".encode("ascii")
        )
        public_created = _write_owner_only_new(public_absolute, f"{public_key}\n".encode("ascii"))
    except Exception:
        if private_created is not None:
            with contextlib.suppress(OSError):
                private_created.unlink()
        raise
    return private_created, public_created


def _select_node(document: dict[str, Any], node_id: str) -> dict[str, Any]:
    for node in document["nodes"]:
        if node["id"] == node_id:
            return node
    raise MeshError(f"node id {node_id!r} is not present in the mesh document")


def _render_wg_quick(document: dict[str, Any], node: dict[str, Any], private_key: str) -> str:
    hub = next(item for item in document["nodes"] if item["role"] == "hub")
    if node["role"] == "hub":
        peers = [item for item in document["nodes"] if item["role"] == "leaf"]
    else:
        peers = [hub]

    lines = [
        "# Render-only WireGuard mesh profile.",
        "# Importing or running wg-quick is a separate, explicit operation.",
        "# This profile does not enable forwarding, NAT, or firewall changes.",
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {node['address']}",
        f"ListenPort = {document['mesh']['listen_port']}",
    ]
    for peer in peers:
        allowed_ip = peer["address"]
        if allowed_ip in {"0.0.0.0/0", "::/0"}:
            raise MeshError("default routes are forbidden in mesh output")
        lines.extend(
            [
                "",
                "[Peer]",
                f"# Node = {peer['id']}",
                f"PublicKey = {peer['public_key']}",
                f"AllowedIPs = {allowed_ip}",
            ]
        )
        endpoint = peer.get("underlay_endpoint")
        if endpoint is not None:
            lines.append(f"Endpoint = {endpoint}")
            lines.append("PersistentKeepalive = 25")
    return "\n".join(lines) + "\n"


def _render_manifest(document: dict[str, Any], node: dict[str, Any], config_name: str) -> str:
    hub = next(item for item in document["nodes"] if item["role"] == "hub")
    peers = (
        [item for item in document["nodes"] if item["role"] == "leaf"]
        if node["role"] == "hub"
        else [hub]
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generation": document["generation"],
        "mesh_name": document["mesh"]["name"],
        "node_id": node["id"],
        "node_role": node["role"],
        "config_file": config_name,
        "failover_mode": document["failover_mode"],
        "cutover_epoch": document["cutover_epoch"],
        "expires_at": document["expires_at"],
        "peer_ids": [peer["id"] for peer in peers],
        "allowed_ips": [peer["address"] for peer in peers],
        "activation_performed": False,
        "routing_changed": False,
        "forwarding_enabled": False,
        "nat_configured": False,
        "private_key_in_manifest": False,
    }
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def render(
    *,
    document: dict[str, Any],
    node_id: str,
    private_key_path: Path,
    output_dir: Path,
    wg_binary: str,
) -> tuple[Path, Path]:
    node_id = _validate_node_id(node_id)
    document = validate_document(document)
    if document["generation"] == 0:
        raise MeshError("generation 0 is inert and cannot be rendered")
    node = _select_node(document, node_id)
    private_key = _read_private_key(private_key_path)
    derived_public_key = _run_wg(wg_binary, "pubkey", private_key=private_key)
    if derived_public_key != node["public_key"]:
        raise MeshError("the private key does not match the selected node's configured public key")

    output_absolute = _absolute(output_dir)
    _ensure_private_directory(output_absolute)
    config_path = output_absolute / f"{node_id}.conf"
    manifest_path = output_absolute / "manifest.json"
    _assert_target_available(config_path)
    _assert_target_available(manifest_path)

    config = _render_wg_quick(document, node, private_key).encode("utf-8")
    manifest = _render_manifest(document, node, config_path.name).encode("utf-8")
    config_created: Path | None = None
    try:
        config_created = _write_owner_only_new(config_path, config)
        manifest_created = _write_owner_only_new(manifest_path, manifest)
    except Exception:
        if config_created is not None:
            with contextlib.suppress(OSError):
                config_created.unlink()
        raise
    return config_created, manifest_created


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render a fixed, manual-failover WireGuard mesh without activating it."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="write an inert generation-0 local config")
    init_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)

    validate_parser = subparsers.add_parser("validate", help="validate a private local config")
    validate_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)

    key_parser = subparsers.add_parser("generate-key", help="generate separate local key files")
    key_parser.add_argument("--node-id", required=True)
    key_parser.add_argument("--private-key-file", type=Path)
    key_parser.add_argument("--public-key-file", type=Path)
    key_parser.add_argument("--wg-binary", default="wg")

    render_parser = subparsers.add_parser("render", help="render one node without activation")
    render_parser.add_argument("--node-id", required=True)
    render_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    render_parser.add_argument("--private-key-file", type=Path)
    render_parser.add_argument("--output-dir", type=Path)
    render_parser.add_argument("--wg-binary", default="wg")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            path = initialize(args.config)
            print(f"initialized inert mesh config: {path}")
        elif args.command == "validate":
            document = load_document(args.config)
            state = "inert" if document["generation"] == 0 else "active"
            print(f"valid schema-v1 mesh config ({state}, generation {document['generation']})")
        elif args.command == "generate-key":
            node_id = _validate_node_id(args.node_id)
            private_path = args.private_key_file or _default_private_key_path(node_id)
            public_path = args.public_key_file or _default_public_key_path(node_id)
            created_private, created_public = generate_key_pair(
                node_id=node_id,
                private_key_path=private_path,
                public_key_path=public_path,
                wg_binary=args.wg_binary,
            )
            print(f"created private key file: {created_private}")
            print(f"created public key file: {created_public}")
        elif args.command == "render":
            node_id = _validate_node_id(args.node_id)
            document = load_document(args.config)
            private_path = args.private_key_file or _default_private_key_path(node_id)
            output_dir = args.output_dir or _default_render_dir(node_id, document["generation"])
            config_path, manifest_path = render(
                document=document,
                node_id=node_id,
                private_key_path=private_path,
                output_dir=output_dir,
                wg_binary=args.wg_binary,
            )
            print(f"rendered owner-only WireGuard config: {config_path}")
            print(f"rendered key-free local manifest: {manifest_path}")
        else:  # pragma: no cover - argparse guarantees a known subcommand.
            parser.error("unknown command")
    except MeshError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
