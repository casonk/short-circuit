#!/usr/bin/env python3
"""Validate and render an inert rootful Podman NordVPN egress contract.

The renderer writes owner-only Quadlet source files but never copies them into
systemd's search path, creates a Podman secret, builds an image, starts a
container, changes a route, or grants application leadership.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import importlib.util
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
MAX_CONFIG_BYTES = 1024 * 1024
GIT_TIMEOUT_SECONDS = 10
HOST_ROUTE_TABLE = 51990
HOST_RULE_PRIORITY_BASE = 11990
MINIMUM_PODMAN_VERSION = "5.8.0"
NORDVPN_PACKAGE_VERSION = "5.2.0"
NORDVPN_PACKAGE_SHA256 = {
    "amd64": "9850701f589e742e4d92c43eee1f2188262ddb71f40e5453d3a2ad79503db89b",
    "arm64": "7167223efdca6daf1f84281ed4d2781414a51a4992c51aaa5cab9eb44c979eb4",
}
REPO_ROOT = Path(__file__).resolve().parents[1]
MESH_RENDERER_PATH = REPO_ROOT / "scripts" / "render_wireguard_mesh.py"
DEFAULT_CONFIG = Path("runtime/nord-egress-container/config.json")
DEFAULT_OUTPUT_ROOT = Path("runtime/nord-egress-container/rendered")
ROOT_INSTALL_BASE = Path("/etc/short-circuit/nord-egress")
EXAMPLE_BASE_IMAGE = (
    "docker.io/library/ubuntu@"
    "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
)

TOP_LEVEL_FIELDS = {"schema_version", "generation", "enabled", "target", "build", "gateway"}
TARGET_FIELDS = {"os", "podman_scope", "podman_min_version", "quadlet_directory"}
BUILD_FIELDS = {"base_image", "image_name", "containerfile", "nordvpn_package_version"}
GATEWAY_FIELDS = {
    "id",
    "hostname",
    "mesh_source_subnet",
    "authorized_source_addresses",
    "bridge_subnet",
    "bridge_gateway",
    "bridge_address",
    "bridge_interface",
    "wireguard_interface",
    "peer_transit",
    "podman_secret_name",
    "podman_secret_target",
    "nord_connect",
    "network_mode",
    "fail_closed",
    "ipv6_policy",
    "crud_leadership",
}

SAFE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
INTERFACE_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,14}$")
SECRET_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,62}$")
CONNECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
BASE_IMAGE_RE = re.compile(r"^docker\.io/library/ubuntu@sha256:([0-9a-f]{64})$")
LOCAL_IMAGE_RE = re.compile(
    r"^localhost/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class NordEgressError(Exception):
    """A safe validation or rendering failure."""


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NordEgressError(f"{label} must be a JSON object")
    return value


def _require_exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    unknown = value.keys() - expected
    if missing:
        raise NordEgressError(f"{label} is missing field(s): {', '.join(sorted(missing))}")
    if unknown:
        raise NordEgressError(
            f"{label} contains unsupported field(s): {', '.join(sorted(unknown))}"
        )


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise NordEgressError(f"{label} must be a non-empty string")
    if any(character in value for character in ("\r", "\n", "\0")):
        raise NordEgressError(f"{label} must not contain control characters")
    return value


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise NordEgressError(f"{label} must be a boolean")
    return value


def _require_generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NordEgressError("generation must be an integer of zero or greater")
    return value


def _parse_private_network(value: Any, label: str) -> ipaddress.IPv4Network:
    text = _require_string(value, label)
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as error:
        raise NordEgressError(f"{label} must be a canonical IPv4 CIDR") from error
    if not isinstance(network, ipaddress.IPv4Network):
        raise NordEgressError(f"{label} must be an IPv4 network")
    if not any(network.subnet_of(private) for private in RFC1918_NETWORKS):
        raise NordEgressError(f"{label} must be contained in RFC1918 space")
    return network


def _parse_usable_address(
    value: Any, label: str, network: ipaddress.IPv4Network
) -> ipaddress.IPv4Address:
    text = _require_string(value, label)
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise NordEgressError(f"{label} must be an IPv4 address") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise NordEgressError(f"{label} must be an IPv4 address")
    if address not in network or address in {network.network_address, network.broadcast_address}:
        raise NordEgressError(f"{label} must be a usable address inside gateway.bridge_subnet")
    return address


def _parse_authorized_source_addresses(
    value: Any, mesh_source: ipaddress.IPv4Network, *, required: bool
) -> list[str]:
    if not isinstance(value, list):
        raise NordEgressError("gateway.authorized_source_addresses must be a JSON array")
    if required and not value:
        raise NordEgressError("gateway.authorized_source_addresses must be non-empty when enabled")
    if len(value) > 256:
        raise NordEgressError(
            "gateway.authorized_source_addresses cannot contain more than 256 entries"
        )

    normalized: list[tuple[ipaddress.IPv4Address, str]] = []
    seen: set[ipaddress.IPv4Address] = set()
    for index, raw_address in enumerate(value):
        label = f"gateway.authorized_source_addresses[{index}]"
        address_text = _require_string(raw_address, label)
        try:
            interface = ipaddress.ip_interface(address_text)
        except ValueError as error:
            raise NordEgressError(f"{label} must be a canonical IPv4 /32") from error
        if not isinstance(interface, ipaddress.IPv4Interface) or interface.network.prefixlen != 32:
            raise NordEgressError(f"{label} must be a canonical IPv4 /32")
        canonical = f"{interface.ip}/32"
        if address_text != canonical:
            raise NordEgressError(f"{label} must be a canonical IPv4 /32")
        address = interface.ip
        if address not in mesh_source or address in {
            mesh_source.network_address,
            mesh_source.broadcast_address,
        }:
            raise NordEgressError(f"{label} must be usable inside gateway.mesh_source_subnet")
        if address in seen:
            raise NordEgressError("gateway.authorized_source_addresses must be unique")
        seen.add(address)
        normalized.append((address, canonical))

    sorted_addresses = sorted(normalized, key=lambda item: int(item[0]))
    if normalized != sorted_addresses:
        raise NordEgressError(
            "gateway.authorized_source_addresses must be sorted in ascending address order"
        )
    return [canonical for _, canonical in normalized]


def validate_document(document: Any) -> dict[str, Any]:
    """Strictly validate and normalize schema version 1."""

    root = _require_object(document, "document")
    _require_exact_fields(root, TOP_LEVEL_FIELDS, "document")
    if (
        isinstance(root["schema_version"], bool)
        or not isinstance(root["schema_version"], int)
        or root["schema_version"] != SCHEMA_VERSION
    ):
        raise NordEgressError(f"schema_version must be {SCHEMA_VERSION}")

    generation = _require_generation(root["generation"])
    enabled = _require_bool(root["enabled"], "enabled")
    if generation == 0 and enabled:
        raise NordEgressError("generation 0 must remain disabled")
    if generation > 0 and not enabled:
        raise NordEgressError("a nonzero generation must be explicitly enabled")

    target = _require_object(root["target"], "target")
    _require_exact_fields(target, TARGET_FIELDS, "target")
    if target["os"] != "linux":
        raise NordEgressError("target.os must be linux")
    if target["podman_scope"] != "rootful":
        raise NordEgressError("target.podman_scope must be rootful")
    if target["podman_min_version"] != MINIMUM_PODMAN_VERSION:
        raise NordEgressError(f"target.podman_min_version must be {MINIMUM_PODMAN_VERSION}")
    if target["quadlet_directory"] != "/etc/containers/systemd":
        raise NordEgressError("target.quadlet_directory must be /etc/containers/systemd")

    build = _require_object(root["build"], "build")
    _require_exact_fields(build, BUILD_FIELDS, "build")
    base_image = _require_string(build["base_image"], "build.base_image")
    digest_match = BASE_IMAGE_RE.fullmatch(base_image)
    if digest_match is None or digest_match.group(1) == "0" * 64:
        raise NordEgressError(
            "build.base_image must syntactically pin docker.io/library/ubuntu by a "
            "nonzero sha256 digest"
        )
    image_name = _require_string(build["image_name"], "build.image_name")
    if not LOCAL_IMAGE_RE.fullmatch(image_name):
        raise NordEgressError("build.image_name must be an untagged localhost image name")
    containerfile = _require_string(build["containerfile"], "build.containerfile")
    if containerfile != "containers/nord-egress/Containerfile":
        raise NordEgressError("build.containerfile must be containers/nord-egress/Containerfile")
    if build["nordvpn_package_version"] != NORDVPN_PACKAGE_VERSION:
        raise NordEgressError(f"build.nordvpn_package_version must be {NORDVPN_PACKAGE_VERSION}")

    gateway = _require_object(root["gateway"], "gateway")
    _require_exact_fields(gateway, GATEWAY_FIELDS, "gateway")
    gateway_id = _require_string(gateway["id"], "gateway.id")
    hostname = _require_string(gateway["hostname"], "gateway.hostname")
    if not SAFE_NAME_RE.fullmatch(gateway_id):
        raise NordEgressError(f"gateway.id must match {SAFE_NAME_RE.pattern}")
    if not SAFE_NAME_RE.fullmatch(hostname):
        raise NordEgressError(f"gateway.hostname must match {SAFE_NAME_RE.pattern}")

    mesh_source = _parse_private_network(
        gateway["mesh_source_subnet"], "gateway.mesh_source_subnet"
    )
    if mesh_source.prefixlen < 16:
        raise NordEgressError("gateway.mesh_source_subnet must be /16 or narrower")
    authorized_sources = _parse_authorized_source_addresses(
        gateway["authorized_source_addresses"], mesh_source, required=enabled
    )
    bridge = _parse_private_network(gateway["bridge_subnet"], "gateway.bridge_subnet")
    if bridge.prefixlen not in {29, 30}:
        raise NordEgressError("gateway.bridge_subnet must be a dedicated /29 or /30")
    if bridge.overlaps(mesh_source):
        raise NordEgressError("the bridge and mesh source subnets must not overlap")
    bridge_gateway = _parse_usable_address(
        gateway["bridge_gateway"], "gateway.bridge_gateway", bridge
    )
    bridge_address = _parse_usable_address(
        gateway["bridge_address"], "gateway.bridge_address", bridge
    )
    if bridge_gateway == bridge_address:
        raise NordEgressError("the bridge gateway and container address must be different")
    bridge_interface = _require_string(gateway["bridge_interface"], "gateway.bridge_interface")
    wireguard_interface = _require_string(
        gateway["wireguard_interface"], "gateway.wireguard_interface"
    )
    for interface, label in (
        (bridge_interface, "gateway.bridge_interface"),
        (wireguard_interface, "gateway.wireguard_interface"),
    ):
        if not INTERFACE_NAME_RE.fullmatch(interface):
            raise NordEgressError(f"{label} must match {INTERFACE_NAME_RE.pattern}")
    if bridge_interface == wireguard_interface:
        raise NordEgressError("bridge and WireGuard interfaces must be different")
    peer_transit = _require_bool(gateway["peer_transit"], "gateway.peer_transit")
    if peer_transit:
        raise NordEgressError("gateway.peer_transit must remain false")

    secret_name = _require_string(gateway["podman_secret_name"], "gateway.podman_secret_name")
    if not SECRET_NAME_RE.fullmatch(secret_name):
        raise NordEgressError(f"gateway.podman_secret_name must match {SECRET_NAME_RE.pattern}")
    secret_target = _require_string(gateway["podman_secret_target"], "gateway.podman_secret_target")
    if secret_target != "/run/secrets/nordvpn-token":
        raise NordEgressError("gateway.podman_secret_target must be /run/secrets/nordvpn-token")
    nord_connect = _require_string(gateway["nord_connect"], "gateway.nord_connect")
    if not CONNECT_RE.fullmatch(nord_connect):
        raise NordEgressError("gateway.nord_connect contains unsupported characters")
    if gateway["network_mode"] != "isolated-bridge":
        raise NordEgressError("gateway.network_mode must be isolated-bridge")
    if gateway["fail_closed"] is not True:
        raise NordEgressError("gateway.fail_closed must be true")
    if gateway["ipv6_policy"] != "disabled-drop":
        raise NordEgressError("gateway.ipv6_policy must be disabled-drop")
    if gateway["crud_leadership"] != "none":
        raise NordEgressError("gateway.crud_leadership must be none")

    return {
        "schema_version": SCHEMA_VERSION,
        "generation": generation,
        "enabled": enabled,
        "target": {
            "os": "linux",
            "podman_scope": "rootful",
            "podman_min_version": MINIMUM_PODMAN_VERSION,
            "quadlet_directory": "/etc/containers/systemd",
        },
        "build": {
            "base_image": base_image,
            "image_name": image_name,
            "containerfile": containerfile,
            "nordvpn_package_version": NORDVPN_PACKAGE_VERSION,
        },
        "gateway": {
            "id": gateway_id,
            "hostname": hostname,
            "mesh_source_subnet": str(mesh_source),
            "authorized_source_addresses": authorized_sources,
            "bridge_subnet": str(bridge),
            "bridge_gateway": str(bridge_gateway),
            "bridge_address": str(bridge_address),
            "bridge_interface": bridge_interface,
            "wireguard_interface": wireguard_interface,
            "peer_transit": False,
            "podman_secret_name": secret_name,
            "podman_secret_target": secret_target,
            "nord_connect": nord_connect,
            "network_mode": "isolated-bridge",
            "fail_closed": True,
            "ipv6_policy": "disabled-drop",
            "crud_leadership": "none",
        },
    }


def inert_document() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generation": 0,
        "enabled": False,
        "target": {
            "os": "linux",
            "podman_scope": "rootful",
            "podman_min_version": MINIMUM_PODMAN_VERSION,
            "quadlet_directory": "/etc/containers/systemd",
        },
        "build": {
            "base_image": EXAMPLE_BASE_IMAGE,
            "image_name": "localhost/short-circuit-nord-egress",
            "containerfile": "containers/nord-egress/Containerfile",
            "nordvpn_package_version": NORDVPN_PACKAGE_VERSION,
        },
        "gateway": {
            "id": "tc-nord-egress",
            "hostname": "tc-nord-egress",
            "mesh_source_subnet": "10.99.0.240/28",
            "authorized_source_addresses": [],
            "bridge_subnet": "10.89.77.0/29",
            "bridge_gateway": "10.89.77.1",
            "bridge_address": "10.89.77.2",
            "bridge_interface": "tcne0",
            "wireguard_interface": "wg0",
            "peer_transit": False,
            "podman_secret_name": "short-circuit-nordvpn-token",
            "podman_secret_target": "/run/secrets/nordvpn-token",
            "nord_connect": "fastest",
            "network_mode": "isolated-bridge",
            "fail_closed": True,
            "ipv6_policy": "disabled-drop",
            "crud_leadership": "none",
        },
    }


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _repository_private_path(path: Path) -> Path:
    absolute = _absolute(path)
    try:
        relative = absolute.relative_to(REPO_ROOT)
    except ValueError as error:
        raise NordEgressError("local Nord egress state must stay inside this repository") from error
    if not relative.parts or relative.parts[0] != "runtime":
        raise NordEgressError("local Nord egress state must stay under the ignored runtime/ tree")

    current = REPO_ROOT
    for part in relative.parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise NordEgressError(f"local path must not traverse a symlink: {current}")
        if metadata.st_uid != os.geteuid():
            raise NordEgressError(f"local path must be owned by the current user: {current}")
        if stat.S_ISDIR(metadata.st_mode) and metadata.st_mode & 0o022:
            raise NordEgressError(
                f"local path must not traverse a group/world-writable directory: {current}"
            )

    command = ["git", "-C", os.fspath(REPO_ROOT)]
    try:
        tracked = subprocess.run(
            [*command, "ls-files", "--error-unmatch", "--", os.fspath(relative)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
        ignored = subprocess.run(
            [*command, "check-ignore", "--no-index", "-q", "--", os.fspath(relative)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise NordEgressError("git is required to verify private runtime paths") from error
    if tracked.returncode == 0:
        raise NordEgressError(f"local Nord egress state must be untracked: {relative}")
    if tracked.returncode not in {0, 1} or ignored.returncode != 0:
        raise NordEgressError(f"local Nord egress state must be ignored by Git: {relative}")
    return absolute


def _ensure_owner_only_directory(path: Path) -> Path:
    absolute = _repository_private_path(path)
    missing: list[Path] = []
    current = absolute
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError as error:
            raise NordEgressError(
                f"local directory changed while being created: {directory}"
            ) from error
    metadata = absolute.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NordEgressError(f"local output path must be a real directory: {absolute}")
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise NordEgressError(f"local output directory must be owner-only: {absolute}")
    return absolute


def _assert_new_target(path: Path) -> Path:
    absolute = _repository_private_path(path)
    try:
        absolute.lstat()
    except FileNotFoundError:
        return absolute
    raise NordEgressError(f"refusing to overwrite existing path: {absolute}")


def _write_owner_only_new(path: Path, contents: bytes) -> Path:
    absolute = _assert_new_target(path)
    _ensure_owner_only_directory(absolute.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags, 0o600)
    except OSError as error:
        raise NordEgressError(f"could not securely create local file: {absolute}") from error
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


def _read_owner_only_file(path: Path) -> bytes:
    absolute = _repository_private_path(path)
    try:
        expected = absolute.lstat()
    except FileNotFoundError as error:
        raise NordEgressError(f"local config does not exist: {absolute}") from error
    if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):
        raise NordEgressError("local config must be a regular file, not a symlink")
    if expected.st_uid != os.geteuid() or expected.st_mode & 0o077:
        raise NordEgressError("local config must be owner-only")
    if expected.st_size > MAX_CONFIG_BYTES:
        raise NordEgressError("local config exceeds its maximum allowed size")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(absolute, flags)
    try:
        actual = os.fstat(descriptor)
        if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
            raise NordEgressError("local config changed while being opened")
        contents = os.read(descriptor, MAX_CONFIG_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(contents) > MAX_CONFIG_BYTES:
        raise NordEgressError("local config exceeds its maximum allowed size")
    return contents


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NordEgressError(f"Nord egress config contains duplicate JSON key: {key}")
        result[key] = value
    return result


def load_document(path: Path) -> dict[str, Any]:
    raw = _read_owner_only_file(path)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NordEgressError("Nord egress config must be valid UTF-8 JSON") from error
    return validate_document(document)


def _load_mesh_renderer() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_short_circuit_wireguard_mesh_binding", MESH_RENDERER_PATH
    )
    if spec is None or spec.loader is None:
        raise NordEgressError("could not load the WireGuard mesh validator")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError) as error:
        raise NordEgressError("could not load the WireGuard mesh validator") from error
    return module


def load_mesh_document(path: Path) -> dict[str, Any]:
    """Load a private mesh declaration through its authoritative validator."""
    mesh_renderer = _load_mesh_renderer()
    try:
        return mesh_renderer.load_document(path)
    except mesh_renderer.MeshError as error:
        raise NordEgressError(f"WireGuard mesh binding failed: {error}") from error


def bind_mesh_document(
    document: dict[str, Any], mesh_document: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Cross-check egress policy against one canonical active mesh generation."""
    normalized = validate_document(document)
    if not normalized["enabled"] or normalized["generation"] == 0:
        raise NordEgressError("generation 0 is inert and cannot be mesh-bound")

    mesh_renderer = _load_mesh_renderer()
    try:
        mesh = mesh_renderer.validate_document(mesh_document)
        mesh_binding = mesh_renderer.build_mesh_binding(mesh)
    except mesh_renderer.MeshError as error:
        raise NordEgressError(f"WireGuard mesh binding failed: {error}") from error

    if mesh["generation"] == 0:
        raise NordEgressError("Nord egress requires an active WireGuard mesh generation")
    if normalized["generation"] != mesh["generation"]:
        raise NordEgressError("Nord egress generation must equal the WireGuard mesh generation")
    if mesh_binding["egress_mode"] != "nord-vpn":
        raise NordEgressError("WireGuard mesh egress.mode must be nord-vpn")
    if mesh_binding["peer_transit"]:
        raise NordEgressError("Nord egress requires WireGuard mesh peer_transit to remain false")

    gateway_node_id = mesh_binding["gateway_node_id"]
    gateway_node = next(
        (node for node in mesh["nodes"] if node["id"] == gateway_node_id),
        None,
    )
    if gateway_node is None or gateway_node["role"] != "hub":
        raise NordEgressError("WireGuard mesh egress gateway must identify the sole hub")
    if gateway_node["platform"] != "linux":
        raise NordEgressError("Nord egress requires the bound WireGuard hub to run Linux")

    gateway = normalized["gateway"]
    if gateway["wireguard_interface"] != mesh_binding["wireguard_interface"]:
        raise NordEgressError(
            "gateway.wireguard_interface must equal the bound mesh gateway node id"
        )
    if gateway["mesh_source_subnet"] != mesh_binding["mesh_subnet"]:
        raise NordEgressError("gateway.mesh_source_subnet must equal the bound mesh subnet")
    if gateway["peer_transit"] != mesh_binding["peer_transit"]:
        raise NordEgressError("gateway.peer_transit must equal the bound mesh policy")
    if gateway["authorized_source_addresses"] != mesh_binding["authorized_source_addresses"]:
        raise NordEgressError(
            "gateway.authorized_source_addresses must exactly equal the bound authorized leaves"
        )
    if mesh_binding["egress_ipv6_policy"] != "block":
        raise NordEgressError("the bound mesh must keep egress IPv6 policy set to block")

    return normalized, mesh_binding


def initialize(path: Path) -> Path:
    payload = (json.dumps(inert_document(), indent=2, sort_keys=True) + "\n").encode()
    return _write_owner_only_new(path, payload)


def _root_generation_directory(stem: str) -> Path:
    return ROOT_INSTALL_BASE / stem


def _expiry_epoch(expires_at: str) -> int:
    return int(
        dt.datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=dt.timezone.utc)
        .timestamp()
    )


def _systemd_expiry_calendar(expires_at: str) -> str:
    return expires_at.replace("T", " ").removesuffix("Z") + " UTC"


def _render_build(document: dict[str, Any], stem: str) -> str:
    build_context = _root_generation_directory(stem) / "build-context"
    containerfile = build_context / "Containerfile"
    image_tag = f"{document['build']['image_name']}:generation-{document['generation']}"
    return "\n".join(
        [
            "[Unit]",
            "Description=Build the isolated short-circuit NordVPN egress image",
            "",
            "[Build]",
            f"ImageTag={image_tag}",
            f"File={containerfile}",
            f"SetWorkingDirectory={build_context}",
            f"BuildArg=BASE_IMAGE={document['build']['base_image']}",
            f"BuildArg=NORDVPN_PACKAGE_VERSION={document['build']['nordvpn_package_version']}",
            "Pull=always",
            "TLSVerify=true",
            "",
            "[Service]",
            "TimeoutStartSec=900",
            "",
        ]
    )


def _render_network(document: dict[str, Any], stem: str) -> str:
    gateway = document["gateway"]
    return "\n".join(
        [
            "[Unit]",
            "Description=Dedicated bridge for the short-circuit NordVPN egress namespace",
            "",
            "[Network]",
            f"NetworkName={stem}",
            "Driver=bridge",
            f"Subnet={gateway['bridge_subnet']}",
            f"Gateway={gateway['bridge_gateway']}",
            f"InterfaceName={gateway['bridge_interface']}",
            "DisableDNS=true",
            "IPv6=false",
            "Options=isolate=true",
            "",
        ]
    )


def _render_container(document: dict[str, Any], stem: str, mesh_binding: dict[str, Any]) -> str:
    gateway = document["gateway"]
    authorized_sources = ",".join(gateway["authorized_source_addresses"])
    secret = (
        f"{gateway['podman_secret_name']},type=mount,"
        f"target={gateway['podman_secret_target']},uid=0,gid=0,mode=0400"
    )
    return "\n".join(
        [
            "[Unit]",
            "Description=Fail-closed NordLynx egress for the allowlisted WireGuard mesh subnet",
            f"Requires={stem}-host-guard.service",
            f"After={stem}-host-guard.service",
            f"Wants={stem}-route-enable.service",
            "After=network-online.target",
            "Wants=network-online.target",
            "AssertPathExists=/usr/bin/podman",
            "AssertPathExists=/dev/net/tun",
            "",
            "[Container]",
            f"Image={stem}.build",
            f"ContainerName={stem}",
            f"HostName={gateway['hostname']}",
            f"Network={stem}.network",
            f"IP={gateway['bridge_address']}",
            *[f"DNS={address}" for address in mesh_binding["egress_dns_servers"]],
            "User=0",
            "UserNS=host",
            "AddCapability=NET_ADMIN",
            "AddDevice=/dev/net/tun:/dev/net/tun:rwm",
            f"Secret={secret}",
            f"Environment=TC_MESH_SOURCE_SUBNET={gateway['mesh_source_subnet']}",
            f"Environment=TC_AUTHORIZED_SOURCE_ADDRESSES={authorized_sources}",
            "Environment=TC_INGRESS_INTERFACE=eth0",
            "Environment=TC_NORD_INTERFACE=nordlynx",
            f"Environment=TC_NORD_TOKEN_FILE={gateway['podman_secret_target']}",
            f"Environment=TC_NORD_CONNECT={gateway['nord_connect']}",
            "Environment=TC_EGRESS_FAIL_CLOSED=true",
            "Environment=TC_IPV6_POLICY=disabled-drop",
            "Environment=TC_CRUD_LEADERSHIP=none",
            "Sysctl=net.ipv4.ip_forward=0",
            "Sysctl=net.ipv6.conf.all.disable_ipv6=1",
            "Sysctl=net.ipv6.conf.default.disable_ipv6=1",
            "NoNewPrivileges=true",
            "RunInit=true",
            "Notify=healthy",
            "HealthCmd=/usr/local/sbin/nord-egress-entrypoint --healthcheck",
            "HealthInterval=15s",
            "HealthRetries=3",
            "HealthStartPeriod=120s",
            "HealthStartupCmd=/usr/local/sbin/nord-egress-entrypoint --healthcheck",
            "HealthStartupInterval=5s",
            "HealthStartupRetries=30",
            "HealthStartupSuccess=1",
            "HealthStartupTimeout=5s",
            "HealthTimeout=5s",
            "HealthOnFailure=kill",
            "",
            "[Service]",
            f"ExecStartPre=/bin/sh {_root_generation_directory(stem) / f'{stem}-host-guard.sh'} verify",
            (
                'ExecStartPre=/usr/bin/sh -ec \'test "$(id -u)" = 0 && '
                'test "$(podman info --format={{.Host.Security.Rootless}})" = false\''
            ),
            "Restart=on-failure",
            "RestartSec=5s",
            "TimeoutStartSec=180",
            "TimeoutStopSec=30",
            "",
        ]
    )


def _render_host_guard_script(
    document: dict[str, Any], stem: str, mesh_binding: dict[str, Any]
) -> str:
    gateway = document["gateway"]
    authorized_sources = ",".join(gateway["authorized_source_addresses"])
    authorized_nft_elements = ", ".join(gateway["authorized_source_addresses"])
    nft_table = f"sc_{stem.replace('-', '_')}"
    return "\n".join(
        [
            "#!/bin/sh",
            "",
            "set -eu",
            "LC_ALL=C",
            "export LC_ALL",
            "",
            f"WIREGUARD_INTERFACE={gateway['wireguard_interface']}",
            f"WIREGUARD_UNIT=wg-quick@{gateway['wireguard_interface']}.service",
            f"BRIDGE_INTERFACE={gateway['bridge_interface']}",
            f"BRIDGE_SUBNET={gateway['bridge_subnet']}",
            f"BRIDGE_GATEWAY={gateway['bridge_gateway']}",
            f"GATEWAY_ADDRESS={gateway['bridge_address']}",
            f"AUTHORIZED_SOURCES={authorized_sources}",
            f"NFT_AUTHORIZED_SOURCES='{authorized_nft_elements}'",
            f"NFT_TABLE={nft_table}",
            f"ROUTE_TABLE={HOST_ROUTE_TABLE}",
            f"RULE_PRIORITY_BASE={HOST_RULE_PRIORITY_BASE}",
            "INTERFACE_PROHIBIT_PRIORITY=$((RULE_PRIORITY_BASE + 512))",
            f"MINIMUM_PODMAN_VERSION={MINIMUM_PODMAN_VERSION}",
            f"MESH_EXPIRES_EPOCH={_expiry_epoch(mesh_binding['expires_at'])}",
            "",
            "fail() {",
            "    printf '%s\\n' \"nord-egress-host-policy: $1\" >&2",
            "    exit 1",
            "}",
            "",
            "verify_mesh_expiry() {",
            '    current_epoch=$(date -u +%s) || fail "could not read the current UTC epoch"',
            '    test "$current_epoch" -lt "$MESH_EXPIRES_EPOCH" || fail "the bound mesh generation has expired"',
            "}",
            "",
            "require_root_linux() {",
            '    test "$(uname -s)" = Linux || fail "Linux is required"',
            '    test "$(id -u)" = 0 || fail "root is required"',
            '    command -v ip >/dev/null 2>&1 || fail "iproute2 is required"',
            '    command -v nft >/dev/null 2>&1 || fail "nftables is required"',
            '    command -v podman >/dev/null 2>&1 || fail "Podman is required"',
            '    command -v sort >/dev/null 2>&1 || fail "version-aware sort is required"',
            '    test "$(podman info --format={{.Host.Security.Rootless}})" = false || fail "rootful Podman is required"',
            "    podman_version=$(podman version --format={{.Client.Version}})",
            '    oldest_version=$(printf \'%s\\n%s\\n\' "$MINIMUM_PODMAN_VERSION" "$podman_version" | sort -V | head -n 1)',
            '    test "$oldest_version" = "$MINIMUM_PODMAN_VERSION" || fail "Podman $MINIMUM_PODMAN_VERSION or newer is required"',
            "}",
            "",
            "for_each_source() {",
            "    action=$1",
            "    saved_ifs=$IFS",
            "    IFS=,",
            "    set -- $AUTHORIZED_SOURCES",
            "    IFS=$saved_ifs",
            "    source_index=0",
            "    for source_address do",
            "        lookup_priority=$((RULE_PRIORITY_BASE + (source_index * 2)))",
            "        prohibit_priority=$((lookup_priority + 1))",
            '        $action "$source_address" "$lookup_priority" "$prohibit_priority"',
            "        source_index=$((source_index + 1))",
            "    done",
            "}",
            "",
            "add_source_rules() {",
            "    source_address=$1",
            "    lookup_priority=$2",
            "    prohibit_priority=$3",
            '    ip -4 rule add priority "$prohibit_priority" iif "$WIREGUARD_INTERFACE" from "$source_address" prohibit',
            '    ip -4 rule add priority "$lookup_priority" iif "$WIREGUARD_INTERFACE" from "$source_address" lookup "$ROUTE_TABLE"',
            "}",
            "",
            "delete_lookup_rule() {",
            "    source_address=$1",
            "    lookup_priority=$2",
            '    ip -4 rule del priority "$lookup_priority" iif "$WIREGUARD_INTERFACE" from "$source_address" lookup "$ROUTE_TABLE" >/dev/null 2>&1 || true',
            "}",
            "",
            "delete_prohibit_rule() {",
            "    source_address=$1",
            "    prohibit_priority=$3",
            '    ip -4 rule del priority "$prohibit_priority" iif "$WIREGUARD_INTERFACE" from "$source_address" prohibit >/dev/null 2>&1 || true',
            "}",
            "",
            "verify_source_rules() {",
            "    source_address=$1",
            "    lookup_priority=$2",
            "    prohibit_priority=$3",
            "    source_ip=${source_address%/32}",
            '    ip -4 rule show priority "$lookup_priority" | awk -v priority="$lookup_priority:" -v source="$source_ip" -v interface="$WIREGUARD_INTERFACE" -v table="$ROUTE_TABLE" \'',
            '        NF == 7 && $1 == priority && $2 == "from" && $3 == source && $4 == "iif" && $5 == interface && $6 == "lookup" && $7 == table { count++ }',
            '        NF == 8 && $1 == priority && $2 == "from" && $3 == source && $4 == "iif" && $5 == interface && $6 == "[detached]" && $7 == "lookup" && $8 == table { count++ }',
            '        END { exit count == 1 ? 0 : 1 }\' || fail "preferred lookup guard is absent for $source_address"',
            '    ip -4 rule show priority "$prohibit_priority" | awk -v priority="$prohibit_priority:" -v source="$source_ip" -v interface="$WIREGUARD_INTERFACE" \'',
            '        NF == 6 && $1 == priority && $2 == "from" && $3 == source && $4 == "iif" && $5 == interface && $6 == "prohibit" { count++ }',
            '        NF == 7 && $1 == priority && $2 == "from" && $3 == source && $4 == "iif" && $5 == interface && $6 == "[detached]" && $7 == "prohibit" { count++ }',
            '        END { exit count == 1 ? 0 : 1 }\' || fail "terminal source prohibit is absent for $source_address"',
            "}",
            "",
            "verify_interface_prohibit_rule() {",
            "    address_family=$1",
            '    ip "$address_family" rule show priority "$INTERFACE_PROHIBIT_PRIORITY" | awk -v priority="$INTERFACE_PROHIBIT_PRIORITY:" -v interface="$WIREGUARD_INTERFACE" \'',
            '        NF == 6 && $1 == priority && $2 == "from" && $3 == "all" && $4 == "iif" && $5 == interface && $6 == "prohibit" { count++ }',
            '        NF == 7 && $1 == priority && $2 == "from" && $3 == "all" && $4 == "iif" && $5 == interface && $6 == "[detached]" && $7 == "prohibit" { count++ }',
            '        END { exit count == 1 ? 0 : 1 }\' || fail "terminal $address_family WireGuard interface prohibit is absent"',
            "}",
            "",
            "verify_terminal_prohibit_route() {",
            '    ip -4 route show table "$ROUTE_TABLE" | awk \'',
            '        NF == 4 && $1 == "prohibit" && $2 == "default" && $3 == "metric" && $4 == "32767" { count++ }',
            '        END { exit count == 1 ? 0 : 1 }\' || fail "terminal prohibit route is absent"',
            "}",
            "",
            "verify_guard() {",
            "    verify_mesh_expiry",
            '    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || fail "nftables guard is absent"',
            "    verify_terminal_prohibit_route",
            "    for_each_source verify_source_rules",
            "    verify_interface_prohibit_rule -4",
            "    verify_interface_prohibit_rule -6",
            "}",
            "",
            "install_guard() {",
            "    verify_mesh_expiry",
            '    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then',
            '        fail "refusing to replace an existing nftables policy table"',
            "    fi",
            "    for address_family in -4 -6; do",
            '        if ip "$address_family" rule show | awk -F: -v first="$RULE_PRIORITY_BASE" -v last="$INTERFACE_PROHIBIT_PRIORITY" \'',
            "            { priority = $1 + 0; if (priority >= first && priority <= last) exit 1 }'",
            "        then",
            "            :",
            "        else",
            '            fail "reserved $address_family policy-rule priorities are already in use"',
            "        fi",
            "    done",
            '    if ip -4 route show table "$ROUTE_TABLE" 2>/dev/null | grep -q .; then',
            '        fail "reserved policy-routing table is already in use"',
            "    fi",
            "",
            "    nft -f - <<EOF",
            "table inet $NFT_TABLE {",
            "    set authorized_sources {",
            "        type ipv4_addr",
            "        flags interval",
            "        elements = { $NFT_AUTHORIZED_SOURCES }",
            "    }",
            "    set blocked_destinations {",
            "        type ipv4_addr",
            "        flags interval",
            "        elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 }",
            "    }",
            "    chain forward {",
            "        type filter hook forward priority -20; policy accept;",
            '        iifname "$WIREGUARD_INTERFACE" jump wireguard_egress',
            '        iifname "$BRIDGE_INTERFACE" oifname "$WIREGUARD_INTERFACE" ip daddr @authorized_sources ct state established,related accept',
            '        iifname "$BRIDGE_INTERFACE" ip saddr $GATEWAY_ADDRESS ip daddr @blocked_destinations drop',
            '        iifname "$BRIDGE_INTERFACE" ip saddr $GATEWAY_ADDRESS oifname != "$BRIDGE_INTERFACE" oifname != "$WIREGUARD_INTERFACE" accept',
            '        iifname != "$BRIDGE_INTERFACE" iifname != "$WIREGUARD_INTERFACE" oifname "$BRIDGE_INTERFACE" ip daddr $GATEWAY_ADDRESS ct state established,related accept',
            '        oifname "$BRIDGE_INTERFACE" drop',
            '        iifname "$BRIDGE_INTERFACE" drop',
            "    }",
            "    chain input {",
            "        type filter hook input priority -20; policy accept;",
            '        iifname "$BRIDGE_INTERFACE" ip saddr $GATEWAY_ADDRESS drop',
            '        iifname "$BRIDGE_INTERFACE" drop',
            "    }",
            "    chain wireguard_egress {",
            "        meta nfproto ipv6 drop",
            '        oifname "$WIREGUARD_INTERFACE" drop',
            "        ip daddr @blocked_destinations drop",
            '        ip saddr @authorized_sources oifname "$BRIDGE_INTERFACE" accept',
            "        drop",
            "    }",
            "}",
            "EOF",
            "",
            '    ip -4 route add table "$ROUTE_TABLE" prohibit default metric 32767',
            "    for_each_source add_source_rules",
            '    ip -4 rule add priority "$INTERFACE_PROHIBIT_PRIORITY" iif "$WIREGUARD_INTERFACE" prohibit',
            '    ip -6 rule add priority "$INTERFACE_PROHIBIT_PRIORITY" iif "$WIREGUARD_INTERFACE" prohibit',
            "    verify_guard",
            "}",
            "",
            "decommission_guard() {",
            '    command -v systemctl >/dev/null 2>&1 || fail "systemd is required for guarded decommission"',
            '    wireguard_enablement=$(systemctl is-enabled "$WIREGUARD_UNIT" 2>/dev/null || true)',
            '    case "$wireguard_enablement" in',
            "        masked|masked-runtime) ;;",
            '        *) fail "mask and stop $WIREGUARD_UNIT before guarded decommission" ;;',
            "    esac",
            '    if systemctl is-active --quiet "$WIREGUARD_UNIT"; then',
            '        fail "stop $WIREGUARD_UNIT before guarded decommission"',
            "    fi",
            '    if ip link show "$WIREGUARD_INTERFACE" >/dev/null 2>&1; then',
            '        fail "refusing decommission while the WireGuard interface still exists"',
            "    fi",
            '    if ip -4 route show table "$ROUTE_TABLE" | grep -v "^prohibit default" | grep -q .; then',
            '        fail "refusing decommission while preferred gateway routes remain"',
            "    fi",
            "    for_each_source delete_lookup_rule",
            '    if ip link show "$WIREGUARD_INTERFACE" >/dev/null 2>&1; then',
            '        fail "WireGuard returned during cleanup; terminal prohibit rules remain"',
            "    fi",
            "    for_each_source delete_prohibit_rule",
            '    ip -4 route del table "$ROUTE_TABLE" prohibit default metric 32767 >/dev/null 2>&1 || true',
            '    if ip link show "$WIREGUARD_INTERFACE" >/dev/null 2>&1; then',
            '        fail "WireGuard returned during cleanup; the nftables drop policy remains"',
            "    fi",
            '    nft delete table inet "$NFT_TABLE" >/dev/null 2>&1 || true',
            '    ip -4 rule del priority "$INTERFACE_PROHIBIT_PRIORITY" iif "$WIREGUARD_INTERFACE" prohibit >/dev/null 2>&1 || true',
            '    ip -6 rule del priority "$INTERFACE_PROHIBIT_PRIORITY" iif "$WIREGUARD_INTERFACE" prohibit >/dev/null 2>&1 || true',
            "}",
            "",
            "require_root_linux",
            'case "${1:-}" in',
            "    install)",
            "        install_guard",
            "        ;;",
            "    verify)",
            "        verify_guard",
            "        ;;",
            "    decommission)",
            "        decommission_guard",
            "        ;;",
            "    *)",
            '        fail "usage: $0 install|verify|decommission"',
            "        ;;",
            "esac",
            "",
        ]
    )


def _render_host_guard_service(stem: str, gateway: dict[str, Any]) -> str:
    script_path = _root_generation_directory(stem) / f"{stem}-host-guard.sh"
    return "\n".join(
        [
            "[Unit]",
            "Description=Persistent fail-closed host guard for WireGuard-to-Nord egress",
            f"Requires={stem}-network.service",
            f"After={stem}-network.service",
            f"Before=wg-quick@{gateway['wireguard_interface']}.service",
            f"Before={stem}.service",
            "AssertPathExists=/usr/bin/podman",
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
            "ExecStartPre=/usr/bin/sh -ec 'test \"$(id -u)\" = 0'",
            f"ExecStart=/bin/sh {script_path} install",
            "TimeoutStartSec=30",
            "",
        ]
    )


def _render_route_enable_script(
    document: dict[str, Any], stem: str, mesh_binding: dict[str, Any]
) -> str:
    gateway = document["gateway"]
    nft_table = f"sc_{stem.replace('-', '_')}"
    expected_wireguard_peers = "\n".join(
        sorted(
            f"{peer['public_key']} {peer['address']}"
            for peer in mesh_binding["wireguard_peer_bindings"]
        )
    )
    return "\n".join(
        [
            "#!/bin/sh",
            "",
            "set -eu",
            "LC_ALL=C",
            "export LC_ALL",
            "",
            f"BRIDGE_INTERFACE={gateway['bridge_interface']}",
            f"BRIDGE_SUBNET={gateway['bridge_subnet']}",
            f"BRIDGE_GATEWAY={gateway['bridge_gateway']}",
            f"GATEWAY_ADDRESS={gateway['bridge_address']}",
            f"WIREGUARD_INTERFACE={gateway['wireguard_interface']}",
            f"EXPECTED_WIREGUARD_PUBLIC_KEY={mesh_binding['gateway_public_key']}",
            f"EXPECTED_WIREGUARD_ADDRESS={mesh_binding['gateway_address']}",
            f"EXPECTED_WIREGUARD_LISTEN_PORT={mesh_binding['gateway_listen_port']}",
            f"AUTHORIZED_SOURCES={','.join(gateway['authorized_source_addresses'])}",
            f"EXPECTED_WIREGUARD_PEERS='{expected_wireguard_peers}'",
            f"NFT_TABLE={nft_table}",
            f"ROUTE_TABLE={HOST_ROUTE_TABLE}",
            "",
            "fail() {",
            "    printf '%s\\n' \"nord-egress-route-enable: $1\" >&2",
            "    exit 1",
            "}",
            "",
            "require_root_linux() {",
            '    test "$(uname -s)" = Linux || fail "Linux is required"',
            '    test "$(id -u)" = 0 || fail "root is required"',
            '    command -v ip >/dev/null 2>&1 || fail "iproute2 is required"',
            '    command -v nft >/dev/null 2>&1 || fail "nftables is required"',
            '    command -v wg >/dev/null 2>&1 || fail "wireguard-tools is required"',
            "}",
            "",
            "verify_host_forwarding() {",
            '    test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 || fail "host IPv4 forwarding must already be enabled"',
            '    for rp_filter_path in /proc/sys/net/ipv4/conf/all/rp_filter "/proc/sys/net/ipv4/conf/$BRIDGE_INTERFACE/rp_filter"; do',
            '        test -r "$rp_filter_path" || fail "host rp_filter state is unavailable"',
            '        rp_filter_value=$(cat "$rp_filter_path")',
            '        case "$rp_filter_value" in',
            "            0|2) ;;",
            '            *) fail "strict rp_filter would reject the asymmetric Nord return path" ;;',
            "        esac",
            "    done",
            "}",
            "",
            "verify_wireguard_cryptokey_routes() {",
            '    ip link show "$WIREGUARD_INTERFACE" >/dev/null 2>&1 || fail "WireGuard interface is absent"',
            '    runtime_public_key=$(wg show "$WIREGUARD_INTERFACE" public-key) || fail "could not read WireGuard interface public key"',
            '    test "$runtime_public_key" = "$EXPECTED_WIREGUARD_PUBLIC_KEY" || fail "runtime WireGuard gateway public key differs from the bound mesh generation"',
            '    runtime_listen_port=$(wg show "$WIREGUARD_INTERFACE" listen-port) || fail "could not read WireGuard listen port"',
            '    test "$runtime_listen_port" = "$EXPECTED_WIREGUARD_LISTEN_PORT" || fail "runtime WireGuard listen port differs from the bound mesh generation"',
            '    ip -4 -o address show dev "$WIREGUARD_INTERFACE" scope global | awk -v expected="$EXPECTED_WIREGUARD_ADDRESS" \'',
            "        $4 == expected { matches++ }",
            "        { addresses++ }",
            '        END { exit addresses == 1 && matches == 1 ? 0 : 1 }\' || fail "runtime WireGuard IPv4 identity differs from the bound mesh generation"',
            '    test -z "$(ip -6 -o address show dev "$WIREGUARD_INTERFACE" scope global)" || fail "runtime WireGuard interface has an unexpected global IPv6 address"',
            '    allowed_ips=$(wg show "$WIREGUARD_INTERFACE" allowed-ips) || fail "could not read WireGuard cryptokey routes"',
            "    runtime_wireguard_peers=$(printf '%s\\n' \"$allowed_ips\" | awk '",
            "        NF != 2 { exit 1 }",
            "        $2 !~ /^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\\/32$/ { exit 1 }",
            '        { print $1 " " $2 }\' | sort) || fail "runtime WireGuard peer map is malformed"',
            '    test "$runtime_wireguard_peers" = "$EXPECTED_WIREGUARD_PEERS" || fail "runtime WireGuard peer keys and exact /32 routes differ from the bound mesh generation"',
            "}",
            "",
            "verify_terminal_prohibit_route() {",
            '    ip -4 route show table "$ROUTE_TABLE" | awk \'',
            '        NF == 4 && $1 == "prohibit" && $2 == "default" && $3 == "metric" && $4 == "32767" { count++ }',
            '        END { exit count == 1 ? 0 : 1 }\' || fail "terminal prohibit route is absent"',
            "}",
            "",
            "enable_route() {",
            '    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || fail "host guard is absent"',
            '    ip link show "$BRIDGE_INTERFACE" >/dev/null 2>&1 || fail "gateway bridge is absent"',
            "    bridge_prefix=${BRIDGE_SUBNET#*/}",
            '    ip -4 address show dev "$BRIDGE_INTERFACE" | awk -v expected="$BRIDGE_GATEWAY/$bridge_prefix" \'$1 == "inet" && $2 == expected { found = 1 } END { exit found ? 0 : 1 }\' || fail "gateway bridge address or prefix is wrong"',
            "    verify_host_forwarding",
            "    verify_wireguard_cryptokey_routes",
            "    verify_terminal_prohibit_route",
            '    if ip -4 route show table "$ROUTE_TABLE" | grep -v "^prohibit default" | grep -q .; then',
            '        fail "refusing to replace existing preferred gateway routes"',
            "    fi",
            '    ip -4 route add table "$ROUTE_TABLE" "$BRIDGE_SUBNET" dev "$BRIDGE_INTERFACE" src "$BRIDGE_GATEWAY"',
            '    ip -4 route add table "$ROUTE_TABLE" default via "$GATEWAY_ADDRESS" dev "$BRIDGE_INTERFACE" metric 100',
            "}",
            "",
            "disable_route() {",
            '    ip -4 route del table "$ROUTE_TABLE" default via "$GATEWAY_ADDRESS" dev "$BRIDGE_INTERFACE" metric 100 >/dev/null 2>&1 || true',
            '    ip -4 route del table "$ROUTE_TABLE" "$BRIDGE_SUBNET" dev "$BRIDGE_INTERFACE" src "$BRIDGE_GATEWAY" >/dev/null 2>&1 || true',
            "}",
            "",
            "require_root_linux",
            'case "${1:-}" in',
            "    up)",
            "        enable_route",
            "        ;;",
            "    down)",
            "        disable_route",
            "        ;;",
            "    verify-wireguard)",
            "        verify_wireguard_cryptokey_routes",
            "        ;;",
            "    *)",
            '        fail "usage: $0 up|down|verify-wireguard"',
            "        ;;",
            "esac",
            "",
        ]
    )


def _render_route_enable_service(stem: str, gateway: dict[str, Any]) -> str:
    script_path = _root_generation_directory(stem) / f"{stem}-route-enable.sh"
    guard_script_path = _root_generation_directory(stem) / f"{stem}-host-guard.sh"
    return "\n".join(
        [
            "[Unit]",
            "Description=Enable preferred routing only while the Nord egress container is healthy",
            f"BindsTo={stem}.service",
            f"BindsTo={stem}-network.service",
            f"BindsTo=wg-quick@{gateway['wireguard_interface']}.service",
            f"Requires={stem}-host-guard.service",
            f"After={stem}.service",
            f"After={stem}-network.service",
            f"After=wg-quick@{gateway['wireguard_interface']}.service",
            f"After={stem}-host-guard.service",
            "AssertPathExists=/usr/bin/podman",
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
            "ExecStartPre=/usr/bin/sh -ec 'test \"$(id -u)\" = 0'",
            f"ExecStartPre=/bin/sh {guard_script_path} verify",
            f"ExecStart=/bin/sh {script_path} up",
            f"ExecStop=/bin/sh {script_path} down",
            "TimeoutStartSec=30",
            "TimeoutStopSec=30",
            "",
        ]
    )


def _render_wg_dependency_dropin(stem: str) -> str:
    guard_script_path = _root_generation_directory(stem) / f"{stem}-host-guard.sh"
    route_script_path = _root_generation_directory(stem) / f"{stem}-route-enable.sh"
    return "\n".join(
        [
            "[Unit]",
            f"Requires={stem}-host-guard.service",
            f"After={stem}-host-guard.service",
            f"Wants={stem}-route-enable.service",
            f"Requires={stem}-expiry.timer",
            f"After={stem}-expiry.timer",
            "",
            "[Service]",
            f"ExecStartPre=/bin/sh {guard_script_path} verify",
            f"ExecStartPost=/bin/sh {route_script_path} verify-wireguard",
            # wg-quick@.service does not run ExecStop when ExecStartPost fails.
            # Always-running, error-tolerant cleanup makes a rejected live peer
            # map tear the interface down instead of leaving a failed-but-live
            # generation behind.  A normal stop simply attempts a harmless
            # second down after the template's own ExecStop.
            "ExecStopPost=-/usr/bin/wg-quick down %i",
            "",
        ]
    )


def _render_expiry_stop_service(stem: str, gateway: dict[str, Any]) -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Stop expired short-circuit WireGuard mesh generation",
            "RefuseManualStart=yes",
            "AssertPathExists=/usr/bin/systemctl",
            "",
            "[Service]",
            "Type=oneshot",
            f"ExecStart=/usr/bin/systemctl --no-block stop wg-quick@{gateway['wireguard_interface']}.service",
            "",
        ]
    )


def _render_expiry_timer(stem: str, gateway: dict[str, Any], expires_at: str) -> str:
    wireguard_unit = f"wg-quick@{gateway['wireguard_interface']}.service"
    return "\n".join(
        [
            "[Unit]",
            "Description=Expire short-circuit WireGuard mesh generation at its bound UTC deadline",
            f"BindsTo={wireguard_unit}",
            f"PartOf={wireguard_unit}",
            "",
            "[Timer]",
            f"OnCalendar={_systemd_expiry_calendar(expires_at)}",
            "AccuracySec=1s",
            "Persistent=true",
            f"Unit={stem}-expiry-stop.service",
            "",
        ]
    )


def _render_manifest(
    document: dict[str, Any],
    stem: str,
    install_map: list[dict[str, str]],
    mesh_binding: dict[str, Any],
) -> str:
    gateway = document["gateway"]
    root_generation = _root_generation_directory(stem)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generation": document["generation"],
        "gateway_id": gateway["id"],
        "unit_stem": stem,
        "quadlet_install_target": document["target"]["quadlet_directory"],
        "systemd_install_target": "/etc/systemd/system",
        "root_generation_install_target": str(root_generation),
        "install_map": install_map,
        "target_os": "linux",
        "podman_scope": "rootful",
        "podman_min_version": MINIMUM_PODMAN_VERSION,
        "network_mode": "isolated-bridge",
        "host_network_allowed": False,
        "mesh_source_subnet": gateway["mesh_source_subnet"],
        "authorized_source_addresses": gateway["authorized_source_addresses"],
        "mesh_binding": mesh_binding,
        "mesh_document_sha256": mesh_binding["document_sha256"],
        "mesh_cutover_epoch": mesh_binding["cutover_epoch"],
        "mesh_expires_at": mesh_binding["expires_at"],
        "authorized_leaf_ids": mesh_binding["authorized_leaf_ids"],
        "bootstrap_dns_servers": mesh_binding["egress_dns_servers"],
        "anti_spoof_boundary": "wireguard-cryptokey-routing",
        "gateway_bridge_address": gateway["bridge_address"],
        "gateway_bridge_interface": gateway["bridge_interface"],
        "wireguard_interface": gateway["wireguard_interface"],
        "peer_transit": gateway["peer_transit"],
        "credential_delivery": "podman-secret-file",
        "credential_process_visibility": "pr-set-dumpable-zero-wrapper",
        "credential_value_present": False,
        "base_image_digest_pinned": True,
        "base_image_digest_validation": "syntactic-only",
        "nordvpn_package_version": NORDVPN_PACKAGE_VERSION,
        "nordvpn_package_sha256": NORDVPN_PACKAGE_SHA256,
        "net_admin_required": True,
        "tun_device_required": True,
        "fail_closed": True,
        "ipv6_policy": "disabled-drop",
        "crud_leadership": "none",
        "activation_performed": False,
        "image_build_performed": False,
        "secret_created": False,
        "host_route_artifact_rendered": True,
        "host_forwarding_policy_artifact_rendered": True,
        "host_route_table": HOST_ROUTE_TABLE,
        "host_rule_priority_base": HOST_RULE_PRIORITY_BASE,
        "host_policy_activation_performed": False,
        "host_guard_persistent": True,
        "host_guard_automatic_removal": False,
        "interface_wide_terminal_prohibit_ipv4_ipv6": True,
        "preferred_route_bound_to_container_lifecycle": True,
        "wireguard_activation_contract": "systemd-wg-quick-only",
        "wireguard_failed_start_cleanup": "exec-stop-post-wg-quick-down",
        "generation_cutover_requires_previous_decommission": True,
        "managed_dropin_replacement": "fixed-target-atomic-replacement-required",
        "mesh_expiry_enforcement": "utc-startup-gate-and-systemd-timer",
        "root_owned_install_required": True,
        "installation_performed": False,
        "linux_integration_test_required": True,
    }
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def render(
    document: dict[str, Any],
    output_dir: Path,
    *,
    mesh_document: dict[str, Any],
) -> tuple[Path, ...]:
    normalized, mesh_binding = bind_mesh_document(document, mesh_document)

    gateway_id = normalized["gateway"]["id"]
    stem = f"{gateway_id}-g{normalized['generation']}"
    output = _ensure_owner_only_directory(output_dir)
    build_path = output / f"{stem}.build"
    network_path = output / f"{stem}.network"
    container_path = output / f"{stem}.container"
    host_guard_path = output / f"{stem}-host-guard.sh"
    host_guard_service_path = output / f"{stem}-host-guard.service"
    route_enable_path = output / f"{stem}-route-enable.sh"
    route_enable_service_path = output / f"{stem}-route-enable.service"
    wg_dependency_path = output / f"{stem}-wg-quick-dependency.conf"
    expiry_stop_service_path = output / f"{stem}-expiry-stop.service"
    expiry_timer_path = output / f"{stem}-expiry.timer"
    mesh_binding_path = output / "mesh-binding.json"
    staged_containerfile_path = output / "build-context" / "Containerfile"
    staged_entrypoint_path = output / "build-context" / "nord-egress-entrypoint.sh"
    staged_token_helper_path = output / "build-context" / "nord-token-login.c"
    manifest_path = output / "manifest.json"
    targets = [
        build_path,
        network_path,
        container_path,
        host_guard_path,
        host_guard_service_path,
        route_enable_path,
        route_enable_service_path,
        wg_dependency_path,
        expiry_stop_service_path,
        expiry_timer_path,
        mesh_binding_path,
        staged_containerfile_path,
        staged_entrypoint_path,
        staged_token_helper_path,
        manifest_path,
    ]
    for target in targets:
        _assert_new_target(target)

    root_generation = _root_generation_directory(stem)
    install_map = [
        {
            "source": build_path.name,
            "target": str(Path(normalized["target"]["quadlet_directory"]) / build_path.name),
        },
        {
            "source": network_path.name,
            "target": str(Path(normalized["target"]["quadlet_directory"]) / network_path.name),
        },
        {
            "source": container_path.name,
            "target": str(Path(normalized["target"]["quadlet_directory"]) / container_path.name),
        },
        {
            "source": host_guard_path.name,
            "target": str(root_generation / host_guard_path.name),
        },
        {
            "source": host_guard_service_path.name,
            "target": str(Path("/etc/systemd/system") / host_guard_service_path.name),
        },
        {
            "source": route_enable_path.name,
            "target": str(root_generation / route_enable_path.name),
        },
        {
            "source": route_enable_service_path.name,
            "target": str(Path("/etc/systemd/system") / route_enable_service_path.name),
        },
        {
            "source": wg_dependency_path.name,
            "target": str(
                Path("/etc/systemd/system")
                / f"wg-quick@{normalized['gateway']['wireguard_interface']}.service.d"
                / "50-short-circuit-nord-egress.conf"
            ),
        },
        {
            "source": expiry_stop_service_path.name,
            "target": str(Path("/etc/systemd/system") / expiry_stop_service_path.name),
        },
        {
            "source": expiry_timer_path.name,
            "target": str(Path("/etc/systemd/system") / expiry_timer_path.name),
        },
        {
            "source": mesh_binding_path.name,
            "target": str(root_generation / mesh_binding_path.name),
        },
        {
            "source": "build-context/Containerfile",
            "target": str(root_generation / "build-context" / "Containerfile"),
        },
        {
            "source": "build-context/nord-egress-entrypoint.sh",
            "target": str(root_generation / "build-context" / "nord-egress-entrypoint.sh"),
        },
        {
            "source": "build-context/nord-token-login.c",
            "target": str(root_generation / "build-context" / "nord-token-login.c"),
        },
    ]
    payloads = [
        _render_build(normalized, stem).encode(),
        _render_network(normalized, stem).encode(),
        _render_container(normalized, stem, mesh_binding).encode(),
        _render_host_guard_script(normalized, stem, mesh_binding).encode(),
        _render_host_guard_service(stem, normalized["gateway"]).encode(),
        _render_route_enable_script(normalized, stem, mesh_binding).encode(),
        _render_route_enable_service(stem, normalized["gateway"]).encode(),
        _render_wg_dependency_dropin(stem).encode(),
        _render_expiry_stop_service(stem, normalized["gateway"]).encode(),
        _render_expiry_timer(stem, normalized["gateway"], mesh_binding["expires_at"]).encode(),
        (json.dumps(mesh_binding, indent=2, sort_keys=True) + "\n").encode(),
        (REPO_ROOT / normalized["build"]["containerfile"]).read_bytes(),
        (REPO_ROOT / "containers/nord-egress/nord-egress-entrypoint.sh").read_bytes(),
        (REPO_ROOT / "containers/nord-egress/nord-token-login.c").read_bytes(),
        _render_manifest(normalized, stem, install_map, mesh_binding).encode(),
    ]
    created: list[Path] = []
    try:
        for target, payload in zip(targets, payloads, strict=True):
            created.append(_write_owner_only_new(target, payload))
    except Exception:
        for path in created:
            with contextlib.suppress(OSError):
                path.unlink()
        raise
    return tuple(created)


def _default_output(document: dict[str, Any]) -> Path:
    return DEFAULT_OUTPUT_ROOT / f"generation-{document['generation']}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render owner-only rootful Linux Quadlets for isolated NordVPN mesh egress."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="write an inert ignored local config")
    init_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)

    validate_parser = subparsers.add_parser("validate", help="validate an ignored local config")
    validate_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    validate_parser.add_argument(
        "--mesh-config",
        type=Path,
        help="required for enabled configs; binds policy to the active WireGuard mesh",
    )

    render_parser = subparsers.add_parser("render", help="render Quadlets without activation")
    render_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    render_parser.add_argument(
        "--mesh-config",
        type=Path,
        required=True,
        help="owner-only active WireGuard mesh declaration to bind",
    )
    render_parser.add_argument("--output-dir", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            created = initialize(args.config)
            print(f"initialized inert owner-only config: {created}")
        elif args.command == "validate":
            document = load_document(args.config)
            if document["enabled"]:
                if args.mesh_config is None:
                    raise NordEgressError("enabled config validation requires --mesh-config")
                mesh_document = load_mesh_document(args.mesh_config)
                bind_mesh_document(document, mesh_document)
            state = "enabled" if document["enabled"] else "inert"
            print(
                f"valid Nord egress schema-v{SCHEMA_VERSION} config "
                f"({state}, generation {document['generation']})"
            )
        elif args.command == "render":
            document = load_document(args.config)
            mesh_document = load_mesh_document(args.mesh_config)
            output = args.output_dir or _default_output(document)
            created = render(document, output, mesh_document=mesh_document)
            for path in created:
                print(f"rendered owner-only inactive artifact: {path}")
        else:  # pragma: no cover
            parser.error("unknown command")
    except NordEgressError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
