#!/usr/bin/env python3
"""Validate and render an inert WireGuard roaming-path policy.

The policy inventories transport paths for a separately declared WireGuard
mesh.  Rendering never changes a route, router, interface, firewall, VPN, or
Nord configuration, and ``stable-primary`` never implies automatic failover.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import ipaddress
import json
import os
import re
import socket
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 1024 * 1024
REPO_ROOT = Path(__file__).resolve().parents[1]
MESH_RENDERER_PATH = REPO_ROOT / "scripts" / "render_wireguard_mesh.py"
DEFAULT_CONFIG = Path("config/wireguard/roaming-policy.local.json")
DEFAULT_MESH_CONFIG = Path("config/wireguard/mesh.local.json")
DEFAULT_OUTPUT_ROOT = Path("config/wireguard/mesh.local.d/roaming")

TOP_LEVEL_FIELDS = {
    "schema_version",
    "generation",
    "enforcement",
    "nord_role",
    "mesh_generation",
    "hub_node_id",
    "network_classes",
    "paths",
    "selection",
}
NETWORK_CLASS_FIELDS = {"id", "local_peer_access"}
PATH_FIELDS = {"id", "kind", "endpoint", "available_on"}
SELECTION_FIELDS = {"strategy", "primary_path_id"}

NETWORK_CLASS_ORDER = ("trusted-wlan", "isolated-wlan", "offsite")
NETWORK_CLASS_ACCESS = {
    "trusted-wlan": True,
    "isolated-wlan": False,
    "offsite": False,
}
PATH_KINDS = {"lan-direct", "public-direct", "opaque-udp-relay"}
NON_PUBLIC_DNS_SUFFIXES = (
    "example",
    "home.arpa",
    "internal",
    "invalid",
    "local",
    "localhost",
    "onion",
    "test",
)
SAFE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
RFC6598_NETWORK = ipaddress.ip_network("100.64.0.0/10")
IPV6_ULA_NETWORK = ipaddress.ip_network("fc00::/7")


class RoamingPolicyError(Exception):
    """A safe, user-facing validation or rendering failure."""


def _load_mesh_renderer() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_short_circuit_wireguard_mesh_for_roaming", MESH_RENDERER_PATH
    )
    if spec is None or spec.loader is None:
        raise RoamingPolicyError("could not load the WireGuard mesh validator")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError) as error:
        raise RoamingPolicyError("could not load the WireGuard mesh validator") from error
    return module


MESH = _load_mesh_renderer()


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RoamingPolicyError(f"{label} must be a JSON object")
    return value


def _require_exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    unknown = value.keys() - expected
    if missing:
        raise RoamingPolicyError(f"{label} is missing field(s): {', '.join(sorted(missing))}")
    if unknown:
        raise RoamingPolicyError(
            f"{label} contains unsupported field(s): {', '.join(sorted(unknown))}"
        )


def _require_generation(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RoamingPolicyError(f"{label} must be an integer of zero or greater")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RoamingPolicyError(f"{label} must be a non-empty string")
    if any(character.isspace() or character == "\0" for character in value):
        raise RoamingPolicyError(f"{label} must not contain whitespace or NUL")
    return value


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise RoamingPolicyError(f"{label} must be a boolean")
    return value


def _validate_id(value: Any, label: str) -> str:
    identifier = _require_string(value, label)
    if not SAFE_ID_RE.fullmatch(identifier):
        raise RoamingPolicyError(f"{label} must match {SAFE_ID_RE.pattern}")
    return identifier


def _split_endpoint(value: Any, label: str) -> tuple[str, bool, int]:
    endpoint = _require_string(value, label)
    if any(marker in endpoint for marker in ("://", "/", "@", "?", "#")):
        raise RoamingPolicyError(f"{label} must contain only a host and port")
    bracketed = endpoint.startswith("[")
    if bracketed:
        closing = endpoint.find("]")
        if closing < 0 or endpoint[closing + 1 : closing + 2] != ":":
            raise RoamingPolicyError(f"{label} must use [IPv6]:port or host:port form")
        host = endpoint[1:closing]
        port_text = endpoint[closing + 2 :]
        if "]" in endpoint[closing + 1 :]:
            raise RoamingPolicyError(f"{label} must use [IPv6]:port or host:port form")
    else:
        host, separator, port_text = endpoint.rpartition(":")
        if not separator or ":" in host:
            raise RoamingPolicyError(f"{label} must put an IPv6 address inside brackets")
    if not host:
        raise RoamingPolicyError(f"{label} host must not be empty")
    if not port_text.isascii() or not port_text.isdecimal():
        raise RoamingPolicyError(f"{label} port must be an integer")
    port = int(port_text)
    if port < 1 or port > 65535 or port_text != str(port):
        raise RoamingPolicyError(
            f"{label} port must be a canonical integer from 1 through 65535"
        )
    return host, bracketed, port


def _canonical_fqdn(host: str, label: str) -> str:
    if not host.isascii() or host != host.lower():
        raise RoamingPolicyError(f"{label} DNS host must be lowercase ASCII")
    if len(host) > 253 or host.endswith(".") or "." not in host:
        raise RoamingPolicyError(
            f"{label} DNS host must be a fully qualified name without a trailing dot"
        )
    labels = host.split(".")
    if not all(DNS_LABEL_RE.fullmatch(part) for part in labels):
        raise RoamingPolicyError(f"{label} DNS host is not a canonical DNS name")
    try:
        socket.inet_aton(host)
    except OSError:
        pass
    else:
        raise RoamingPolicyError(f"{label} must not disguise a non-canonical IP as DNS")
    if any(
        host == suffix or host.endswith(f".{suffix}")
        for suffix in NON_PUBLIC_DNS_SUFFIXES
    ):
        raise RoamingPolicyError(f"{label} DNS host must not use a special-use suffix")
    return host


def _canonical_endpoint(value: Any, label: str, kind: str, listen_port: int) -> str:
    if isinstance(value, str) and "%" in value:
        raise RoamingPolicyError(f"{label} must not use an interface-scoped endpoint")
    host, bracketed, port = _split_endpoint(value, label)
    if kind == "lan-direct" and port != listen_port:
        raise RoamingPolicyError(f"{label} port for lan-direct must equal mesh.listen_port")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if bracketed:
            raise RoamingPolicyError(f"{label} may put only an IPv6 literal inside brackets")
        if kind == "lan-direct":
            raise RoamingPolicyError(f"{label} for lan-direct must use a literal RFC1918/ULA IP")
        return f"{_canonical_fqdn(host, label)}:{port}"

    if address.compressed != host:
        raise RoamingPolicyError(f"{label} IP address must use canonical form")
    if isinstance(address, ipaddress.IPv4Address) and bracketed:
        raise RoamingPolicyError(f"{label} must not put an IPv4 address inside brackets")
    if isinstance(address, ipaddress.IPv6Address) and not bracketed:
        raise RoamingPolicyError(f"{label} must put an IPv6 address inside brackets")

    is_lan = (
        isinstance(address, ipaddress.IPv4Address)
        and any(address in network for network in RFC1918_NETWORKS)
    ) or (isinstance(address, ipaddress.IPv6Address) and address in IPV6_ULA_NETWORK)
    if kind == "lan-direct":
        if not is_lan:
            raise RoamingPolicyError(f"{label} for lan-direct must use a literal RFC1918/ULA IP")
    elif (
        is_lan
        or address in RFC6598_NETWORK
        or not address.is_global
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        raise RoamingPolicyError(
            f"{label} for {kind} must use a global IP or canonical FQDN, never private/RFC6598"
        )
    normalized_host = f"[{address.compressed}]" if bracketed else address.compressed
    return f"{normalized_host}:{port}"


def _validate_network_classes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RoamingPolicyError("network_classes must be a JSON array")
    normalized: dict[str, dict[str, Any]] = {}
    for index, raw_class in enumerate(value):
        label = f"network_classes[{index}]"
        network_class = _require_object(raw_class, label)
        _require_exact_fields(network_class, NETWORK_CLASS_FIELDS, label)
        class_id = _require_string(network_class["id"], f"{label}.id")
        if class_id not in NETWORK_CLASS_ACCESS:
            raise RoamingPolicyError(f"{label}.id is not a supported network class")
        if class_id in normalized:
            raise RoamingPolicyError("network_classes must not contain duplicate IDs")
        local_access = _require_bool(
            network_class["local_peer_access"], f"{label}.local_peer_access"
        )
        if local_access is not NETWORK_CLASS_ACCESS[class_id]:
            expected = str(NETWORK_CLASS_ACCESS[class_id]).lower()
            raise RoamingPolicyError(
                f"{label}.local_peer_access must be {expected} for {class_id}"
            )
        normalized[class_id] = {"id": class_id, "local_peer_access": local_access}
    if set(normalized) != set(NETWORK_CLASS_ORDER):
        raise RoamingPolicyError(
            "an active policy requires exactly trusted-wlan, isolated-wlan, and offsite"
        )
    return [normalized[class_id] for class_id in NETWORK_CLASS_ORDER]


def _validate_paths(value: Any, *, listen_port: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RoamingPolicyError("paths must be a JSON array")
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_path in enumerate(value):
        label = f"paths[{index}]"
        path = _require_object(raw_path, label)
        _require_exact_fields(path, PATH_FIELDS, label)
        path_id = _validate_id(path["id"], f"{label}.id")
        if path_id in seen_ids:
            raise RoamingPolicyError("paths must not contain duplicate IDs")
        seen_ids.add(path_id)
        kind = _require_string(path["kind"], f"{label}.kind")
        if kind not in PATH_KINDS:
            raise RoamingPolicyError(
                f"{label}.kind must be lan-direct, public-direct, or opaque-udp-relay"
            )
        endpoint = _canonical_endpoint(path["endpoint"], f"{label}.endpoint", kind, listen_port)
        available_value = path["available_on"]
        if not isinstance(available_value, list) or not available_value:
            raise RoamingPolicyError(f"{label}.available_on must be a non-empty JSON array")
        available: set[str] = set()
        for class_index, raw_class_id in enumerate(available_value):
            class_id = _require_string(
                raw_class_id, f"{label}.available_on[{class_index}]"
            )
            if class_id not in NETWORK_CLASS_ACCESS:
                raise RoamingPolicyError(
                    f"{label}.available_on contains unsupported network class {class_id!r}"
                )
            if class_id in available:
                raise RoamingPolicyError(f"{label}.available_on must not contain duplicates")
            available.add(class_id)
        if kind == "lan-direct" and available != {"trusted-wlan"}:
            raise RoamingPolicyError(
                f"{label}.available_on for lan-direct must be exactly trusted-wlan"
            )
        normalized.append(
            {
                "id": path_id,
                "kind": kind,
                "endpoint": endpoint,
                "available_on": [
                    class_id for class_id in NETWORK_CLASS_ORDER if class_id in available
                ],
            }
        )
    return sorted(normalized, key=lambda item: item["id"])


def _validate_selection(
    value: Any, paths: list[dict[str, Any]], enforcement: str
) -> dict[str, Any]:
    selection = _require_object(value, "selection")
    _require_exact_fields(selection, SELECTION_FIELDS, "selection")
    if selection["strategy"] != "stable-primary":
        raise RoamingPolicyError("selection.strategy must be stable-primary")
    primary = selection["primary_path_id"]
    if primary is not None:
        primary = _validate_id(primary, "selection.primary_path_id")
    by_id = {path["id"]: path for path in paths}
    if primary is not None and primary not in by_id:
        raise RoamingPolicyError("selection.primary_path_id must identify a declared path")
    if enforcement == "required":
        if primary is None:
            raise RoamingPolicyError("required enforcement requires a primary path")
        if set(by_id[primary]["available_on"]) != set(NETWORK_CLASS_ORDER):
            raise RoamingPolicyError(
                "the required primary path must be available on every network class"
            )
    return {"strategy": "stable-primary", "primary_path_id": primary}


def _mesh_transport_alignment(
    paths: list[dict[str, Any]],
    selection: dict[str, Any],
    mesh_document: dict[str, Any],
) -> dict[str, Any]:
    """Compare the declared primary with leaf transports, without probing it."""

    primary_id = selection["primary_path_id"]
    primary = next((path for path in paths if path["id"] == primary_id), None)
    if primary is None:
        return {
            "evaluated": False,
            "all_mesh_leaf_transports_select_primary": False,
            "endpoint_mismatch_leaf_ids": [],
            "transport_mode_mismatch_leaf_ids": [],
        }
    endpoint_mismatches: list[str] = []
    transport_mode_mismatches: list[str] = []
    expected_mode = (
        "opaque-udp-relay" if primary["kind"] == "opaque-udp-relay" else "direct"
    )
    for node in mesh_document["nodes"]:
        if node["role"] != "leaf":
            continue
        transport = node["hub_transport"]
        if transport["mode"] != expected_mode:
            transport_mode_mismatches.append(node["id"])
        elif transport["endpoint"] != primary["endpoint"]:
            endpoint_mismatches.append(node["id"])
    return {
        "evaluated": True,
        "all_mesh_leaf_transports_select_primary": not endpoint_mismatches
        and not transport_mode_mismatches,
        "endpoint_mismatch_leaf_ids": sorted(endpoint_mismatches),
        "transport_mode_mismatch_leaf_ids": sorted(transport_mode_mismatches),
    }


def inert_document() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generation": 0,
        "enforcement": "audit-only",
        "nord_role": "egress-only",
        "mesh_generation": 0,
        "hub_node_id": None,
        "network_classes": [],
        "paths": [],
        "selection": {"strategy": "stable-primary", "primary_path_id": None},
    }


def validate_document(
    document: Any, *, mesh_document: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Strictly validate schema v1 and bind active policy to a normalized mesh."""

    root = _require_object(document, "document")
    _require_exact_fields(root, TOP_LEVEL_FIELDS, "document")
    if (
        isinstance(root["schema_version"], bool)
        or not isinstance(root["schema_version"], int)
        or root["schema_version"] != SCHEMA_VERSION
    ):
        raise RoamingPolicyError(f"schema_version must be {SCHEMA_VERSION}")
    generation = _require_generation(root["generation"], "generation")
    enforcement = _require_string(root["enforcement"], "enforcement")
    if enforcement not in {"audit-only", "required"}:
        raise RoamingPolicyError("enforcement must be audit-only or required")
    if root["nord_role"] != "egress-only":
        raise RoamingPolicyError("nord_role must be egress-only")
    mesh_generation = _require_generation(root["mesh_generation"], "mesh_generation")

    if generation == 0:
        if root != inert_document():
            raise RoamingPolicyError(
                "generation 0 must be inert: audit-only, mesh generation 0, null hub/primary, "
                "and empty network classes/paths"
            )
        return inert_document()

    if mesh_document is None:
        raise RoamingPolicyError("an active roaming policy requires a WireGuard mesh document")
    try:
        mesh_normalized = MESH.validate_document(mesh_document)
    except MESH.MeshError as error:
        raise RoamingPolicyError(f"WireGuard mesh validation failed: {error}") from error
    if mesh_normalized["generation"] == 0:
        raise RoamingPolicyError("an active roaming policy requires an active WireGuard mesh")
    if mesh_generation != mesh_normalized["generation"]:
        raise RoamingPolicyError("mesh_generation must match the WireGuard mesh generation")
    hub = next(node for node in mesh_normalized["nodes"] if node["role"] == "hub")
    hub_node_id = _validate_id(root["hub_node_id"], "hub_node_id")
    if hub_node_id != hub["id"]:
        raise RoamingPolicyError("hub_node_id must identify the WireGuard mesh hub")

    network_classes = _validate_network_classes(root["network_classes"])
    paths = _validate_paths(root["paths"], listen_port=mesh_normalized["mesh"]["listen_port"])
    selection = _validate_selection(root["selection"], paths, enforcement)
    alignment = _mesh_transport_alignment(paths, selection, mesh_normalized)
    if enforcement == "required" and not alignment[
        "all_mesh_leaf_transports_select_primary"
    ]:
        affected = sorted(
            alignment["endpoint_mismatch_leaf_ids"]
            + alignment["transport_mode_mismatch_leaf_ids"]
        )
        detail = ", ".join(affected) or "no primary selected"
        raise RoamingPolicyError(
            "required enforcement requires every mesh leaf hub_transport mode and "
            f"endpoint to equal the stable primary path; affected leaf IDs: {detail}"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generation": generation,
        "enforcement": enforcement,
        "nord_role": "egress-only",
        "mesh_generation": mesh_generation,
        "hub_node_id": hub_node_id,
        "network_classes": network_classes,
        "paths": paths,
        "selection": selection,
    }


def coverage_report(document: dict[str, Any]) -> dict[str, Any]:
    """Return honest path and selected-primary coverage for a validated policy."""

    if document["generation"] == 0:
        return {
            "coverage_evaluated": False,
            "uncovered_network_classes": [],
            "primary_unavailable_on": [],
            "all_classes_have_a_declared_path": False,
            "primary_available_on_all_classes": False,
            "automatic_failover": False,
        }
    covered = {
        class_id
        for path in document["paths"]
        for class_id in path["available_on"]
    }
    uncovered = [class_id for class_id in NETWORK_CLASS_ORDER if class_id not in covered]
    primary_id = document["selection"]["primary_path_id"]
    primary = next(
        (path for path in document["paths"] if path["id"] == primary_id), None
    )
    primary_available = set(primary["available_on"]) if primary is not None else set()
    primary_gaps = [
        class_id for class_id in NETWORK_CLASS_ORDER if class_id not in primary_available
    ]
    return {
        "coverage_evaluated": True,
        "uncovered_network_classes": uncovered,
        "primary_unavailable_on": primary_gaps,
        "all_classes_have_a_declared_path": not uncovered,
        "primary_available_on_all_classes": not primary_gaps,
        "automatic_failover": False,
    }


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RoamingPolicyError(f"roaming policy contains duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_raw_document(path: Path) -> dict[str, Any]:
    try:
        raw = MESH._read_owner_only_file(path, maximum_bytes=MAX_CONFIG_BYTES)
    except MESH.MeshError as error:
        raise RoamingPolicyError(str(error)) from error
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RoamingPolicyError("roaming policy must be valid UTF-8 JSON") from error
    return _require_object(document, "document")


def load_document(
    path: Path, *, mesh_document: dict[str, Any] | None = None
) -> dict[str, Any]:
    return validate_document(_read_raw_document(path), mesh_document=mesh_document)


def load_mesh_document(path: Path) -> dict[str, Any]:
    try:
        return MESH.load_document(path)
    except MESH.MeshError as error:
        raise RoamingPolicyError(f"WireGuard mesh validation failed: {error}") from error


def initialize(path: Path) -> Path:
    payload = (json.dumps(inert_document(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        return MESH._write_owner_only_new(path, payload, require_owner_only_parent=False)
    except MESH.MeshError as error:
        raise RoamingPolicyError(str(error)) from error


def _build_plan(document: dict[str, Any], mesh_document: dict[str, Any]) -> dict[str, Any]:
    try:
        mesh_binding = MESH.build_mesh_binding(mesh_document)
    except MESH.MeshError as error:
        raise RoamingPolicyError(f"WireGuard mesh validation failed: {error}") from error
    coverage = coverage_report(document)
    alignment = _mesh_transport_alignment(
        document["paths"], document["selection"], mesh_document
    )
    return {
        **document,
        "mesh_document_sha256": mesh_binding["document_sha256"],
        "mesh_binding": mesh_binding,
        "coverage": coverage,
        "mesh_transport_alignment": alignment,
        "reachability_verified": False,
        "wireguard_profiles_updated": False,
        "activation_performed": False,
        "router_changes_performed": False,
        "nord_carrier": False,
    }


def _render_markdown(plan: dict[str, Any]) -> str:
    coverage = plan["coverage"]
    primary = plan["selection"]["primary_path_id"] or "none"
    gaps = ", ".join(coverage["uncovered_network_classes"]) or "none"
    primary_gaps = ", ".join(coverage["primary_unavailable_on"]) or "none"
    transports_aligned = str(
        plan["mesh_transport_alignment"]["all_mesh_leaf_transports_select_primary"]
    ).lower()
    lines = [
        "# WireGuard roaming plan",
        "",
        f"- Policy generation: {plan['generation']}",
        f"- Mesh generation: {plan['mesh_generation']}",
        f"- Mesh document SHA-256: `{plan['mesh_document_sha256']}`",
        f"- Hub: `{plan['hub_node_id']}`",
        f"- Enforcement: `{plan['enforcement']}`",
        f"- Selection strategy: `stable-primary`",
        f"- Primary path: `{primary}`",
        f"- Classes with no declared path: {gaps}",
        f"- Classes not declared on primary: {primary_gaps}",
        f"- Mesh leaf transports select primary: `{transports_aligned}`",
        "- Reachability verified: `false`",
        "- WireGuard profiles updated: `false`",
        "- Automatic failover: `false`",
        "- Nord role: outbound egress only; it is not a mesh carrier",
        "- Activation performed: `false`",
        "- Router changes performed: `false`",
        "",
        "## Declared paths",
        "",
    ]
    for path in plan["paths"]:
        classes = ", ".join(path["available_on"])
        lines.append(
            f"- `{path['id']}`: `{path['kind']}` via `{path['endpoint']}`; available on {classes}"
        )
    lines.extend(
        [
            "",
            "This render is an inventory and selection contract only. Any path switch is a",
            "separate, explicit operation after reachability and WireGuard-handshake checks.",
            "",
        ]
    )
    return "\n".join(lines)


def render(
    *, document: dict[str, Any], mesh_document: dict[str, Any], output_dir: Path
) -> tuple[Path, Path]:
    normalized = validate_document(document, mesh_document=mesh_document)
    if normalized["generation"] == 0:
        raise RoamingPolicyError("generation 0 is inert and cannot be rendered")
    try:
        mesh_normalized = MESH.validate_document(mesh_document)
    except MESH.MeshError as error:
        raise RoamingPolicyError(f"WireGuard mesh validation failed: {error}") from error
    plan = _build_plan(normalized, mesh_normalized)
    output = Path(os.path.abspath(os.fspath(output_dir)))
    json_path = output / "roaming-plan.json"
    markdown_path = output / "roaming-plan.md"
    try:
        MESH._ensure_private_directory(output)
        MESH._assert_target_available(json_path)
        MESH._assert_target_available(markdown_path)
    except MESH.MeshError as error:
        raise RoamingPolicyError(str(error)) from error

    json_payload = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode("utf-8")
    markdown_payload = _render_markdown(plan).encode("utf-8")
    json_created: Path | None = None
    try:
        json_created = MESH._write_owner_only_new(json_path, json_payload)
        markdown_created = MESH._write_owner_only_new(markdown_path, markdown_payload)
    except (MESH.MeshError, OSError) as error:
        if json_created is not None:
            with contextlib.suppress(OSError):
                json_created.unlink()
        message = (
            str(error)
            if isinstance(error, MESH.MeshError)
            else "could not write roaming plan"
        )
        raise RoamingPolicyError(message) from error
    return json_created, markdown_created


def _load_for_command(
    config: Path, mesh_config: Path
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    raw = _read_raw_document(config)
    if raw.get("generation") == 0:
        return validate_document(raw), None
    mesh_document = load_mesh_document(mesh_config)
    return validate_document(raw, mesh_document=mesh_document), mesh_document


def _default_output_dir(generation: int) -> Path:
    return DEFAULT_OUTPUT_ROOT / f"generation-{generation}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render a mesh-bound roaming-path inventory without changing the network."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser("init", help="write an inert generation-0 policy")
    init_parser.add_argument("--policy", type=Path, default=DEFAULT_CONFIG)
    validate_parser = subparsers.add_parser("validate", help="validate a local roaming policy")
    validate_parser.add_argument("--policy", type=Path, default=DEFAULT_CONFIG)
    validate_parser.add_argument("--mesh-config", type=Path, default=DEFAULT_MESH_CONFIG)
    render_parser = subparsers.add_parser("render", help="render an inactive roaming plan")
    render_parser.add_argument("--policy", type=Path, default=DEFAULT_CONFIG)
    render_parser.add_argument("--mesh-config", type=Path, default=DEFAULT_MESH_CONFIG)
    render_parser.add_argument("--output-dir", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            created = initialize(args.policy)
            print(f"initialized inert owner-only roaming policy: {created}")
        elif args.command == "validate":
            document, mesh_document = _load_for_command(args.policy, args.mesh_config)
            state = "inert" if document["generation"] == 0 else "active"
            if state == "inert":
                print(
                    "valid schema-v1 roaming policy (inert, generation 0; "
                    "coverage: not evaluated; reachability verified: false; "
                    "automatic failover: false)"
                )
            else:
                assert mesh_document is not None
                coverage = coverage_report(document)
                alignment = _mesh_transport_alignment(
                    document["paths"], document["selection"], mesh_document
                )
                declared_gaps = (
                    ",".join(coverage["uncovered_network_classes"]) or "none"
                )
                primary_gaps = ",".join(coverage["primary_unavailable_on"]) or "none"
                transports_aligned = str(
                    alignment["all_mesh_leaf_transports_select_primary"]
                ).lower()
                print(
                    f"valid schema-v1 roaming policy ({state}, generation "
                    f"{document['generation']}; declared path gaps: {declared_gaps}; "
                    f"primary path gaps: {primary_gaps}; mesh transports select primary: "
                    f"{transports_aligned}; reachability verified: false; "
                    "automatic failover: false)"
                )
        elif args.command == "render":
            document, mesh_document = _load_for_command(args.policy, args.mesh_config)
            if mesh_document is None:
                raise RoamingPolicyError("generation 0 is inert and cannot be rendered")
            output = args.output_dir or _default_output_dir(document["generation"])
            json_path, markdown_path = render(
                document=document, mesh_document=mesh_document, output_dir=output
            )
            print(f"rendered owner-only roaming plan: {json_path}")
            print(f"rendered owner-only roaming summary: {markdown_path}")
        else:  # pragma: no cover - argparse enforces a known subcommand.
            parser.error("unknown command")
    except RoamingPolicyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
