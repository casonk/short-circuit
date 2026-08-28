#!/usr/bin/env python3
"""Render one iOS WireGuard profile for disjoint temporary and canonical peers.

The bundle is render-only. It does not import a profile, activate WireGuard,
change routes, or choose an application writer. A temporary mesh peer is bound
to the authoritative mesh declaration; canonical peers are distinct exact /32
destinations supplied in the owner-only bundle declaration.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import ipaddress
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[1]
MESH_RENDERER_PATH = REPO_ROOT / "scripts" / "render_wireguard_mesh.py"
DEFAULT_CONFIG = Path("config/wireguard/access-bundle.local.json")
DEFAULT_MESH_CONFIG = Path("config/wireguard/mesh.local.json")
DEFAULT_OUTPUT_ROOT = Path("config/wireguard/mesh.local.d/access-bundles")

TOP_LEVEL_FIELDS = {"schema_version", "generation", "expires_at", "client", "peers"}
CLIENT_FIELDS = {"id", "address", "public_key"}
PEER_FIELDS = {"id", "kind", "address", "public_key", "endpoint"}
PEER_KINDS = {"temporary-mesh", "canonical-service"}


class AccessBundleError(Exception):
    """A safe, user-facing access-bundle validation or rendering failure."""


def _load_mesh_renderer() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_short_circuit_wireguard_mesh_for_access_bundle", MESH_RENDERER_PATH
    )
    if spec is None or spec.loader is None:
        raise AccessBundleError("could not load the WireGuard mesh validator")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError) as error:
        raise AccessBundleError("could not load the WireGuard mesh validator") from error
    return module


MESH = _load_mesh_renderer()


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AccessBundleError(f"{label} must be a JSON object")
    return value


def _require_exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    unknown = value.keys() - expected
    if missing:
        raise AccessBundleError(f"{label} is missing field(s): {', '.join(sorted(missing))}")
    if unknown:
        raise AccessBundleError(
            f"{label} contains unsupported field(s): {', '.join(sorted(unknown))}"
        )


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        raise AccessBundleError(f"{label} must be a non-empty string without whitespace")
    return value


def _parse_address(value: Any, label: str) -> str:
    raw = _require_string(value, label)
    try:
        interface = ipaddress.ip_interface(raw)
    except ValueError as error:
        raise AccessBundleError(f"{label} must be a canonical IPv4 /32") from error
    if not isinstance(interface.ip, ipaddress.IPv4Address) or interface.network.prefixlen != 32:
        raise AccessBundleError(f"{label} must be a canonical IPv4 /32")
    normalized = f"{interface.ip.compressed}/32"
    if raw != normalized:
        raise AccessBundleError(f"{label} must be a canonical IPv4 /32")
    return normalized


def _parse_endpoint(value: Any, label: str) -> str:
    try:
        host, bracketed, port = MESH._split_endpoint(value, label)
    except MESH.MeshError as error:
        raise AccessBundleError(str(error)) from error
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if bracketed:
            raise AccessBundleError(
                f"{label} may put only an IPv6 literal inside brackets"
            ) from None
        try:
            normalized = MESH._validate_direct_dns_name(host, label)
        except MESH.MeshError as error:
            raise AccessBundleError(str(error)) from error
        return f"{normalized}:{port}"
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
    ):
        raise AccessBundleError(f"{label} must use a routable unicast address")
    normalized = address.compressed
    if isinstance(address, ipaddress.IPv6Address):
        if not bracketed:
            raise AccessBundleError(f"{label} must put an IPv6 address inside brackets")
        normalized = f"[{normalized}]"
    elif bracketed:
        raise AccessBundleError(f"{label} must not put an IPv4 address inside brackets")
    return f"{normalized}:{port}"


def _parse_public_key(value: Any, label: str) -> str:
    key = _require_string(value, label)
    try:
        MESH._decode_wireguard_key(key, label)
    except MESH.MeshError as error:
        raise AccessBundleError(str(error)) from error
    return key


def _parse_node_id(value: Any, label: str) -> str:
    try:
        return MESH._validate_node_id(value, label)
    except MESH.MeshError as error:
        raise AccessBundleError(str(error)) from error


def inert_document() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generation": 0,
        "expires_at": None,
        "client": {},
        "peers": [],
    }


def validate_document(document: Any, *, mesh_document: dict[str, Any]) -> dict[str, Any]:
    root = _require_object(document, "document")
    _require_exact_fields(root, TOP_LEVEL_FIELDS, "document")
    if root["schema_version"] != SCHEMA_VERSION:
        raise AccessBundleError(f"schema_version must be {SCHEMA_VERSION}")
    generation = root["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise AccessBundleError("generation must be an integer of zero or greater")
    mesh_document = MESH.validate_document(mesh_document)
    if generation == 0:
        if root["expires_at"] is not None or root["client"] or root["peers"]:
            raise AccessBundleError(
                "generation 0 must be inert: null expiry, empty client, and no peers"
            )
        return inert_document()
    if mesh_document["generation"] == 0:
        raise AccessBundleError("an active access bundle requires an active mesh declaration")
    if generation != mesh_document["generation"]:
        raise AccessBundleError("bundle generation must equal the active mesh generation")
    if root["expires_at"] != mesh_document["expires_at"]:
        raise AccessBundleError("bundle expiry must equal the active mesh expiry")

    client_raw = _require_object(root["client"], "client")
    _require_exact_fields(client_raw, CLIENT_FIELDS, "client")
    client = {
        "id": _parse_node_id(client_raw["id"], "client.id"),
        "address": _parse_address(client_raw["address"], "client.address"),
        "public_key": _parse_public_key(client_raw["public_key"], "client.public_key"),
    }
    mesh_client = next(
        (node for node in mesh_document["nodes"] if node["id"] == client["id"]), None
    )
    if mesh_client is None or mesh_client["role"] != "leaf":
        raise AccessBundleError("client.id must identify a leaf in the active mesh")
    if (
        client["address"] != mesh_client["address"]
        or client["public_key"] != mesh_client["public_key"]
    ):
        raise AccessBundleError("client identity must exactly match the active mesh leaf")

    peers_raw = root["peers"]
    if not isinstance(peers_raw, list) or len(peers_raw) < 2:
        raise AccessBundleError("an active access bundle requires at least two peers")
    peer_ids: set[str] = set()
    peer_addresses: set[str] = set()
    peer_keys: set[str] = set()
    normalized_peers: list[dict[str, str]] = []
    temporary_count = 0
    canonical_count = 0
    mesh_hub = next(node for node in mesh_document["nodes"] if node["role"] == "hub")
    mesh_subnet = ipaddress.ip_network(mesh_document["mesh"]["subnet"])
    for index, peer_raw in enumerate(peers_raw):
        label = f"peers[{index}]"
        peer = _require_object(peer_raw, label)
        _require_exact_fields(peer, PEER_FIELDS, label)
        peer_id = _parse_node_id(peer["id"], f"{label}.id")
        if peer_id in peer_ids or peer_id == client["id"]:
            raise AccessBundleError("peer ids must be unique and distinct from client.id")
        peer_ids.add(peer_id)
        kind = _require_string(peer["kind"], f"{label}.kind")
        if kind not in PEER_KINDS:
            raise AccessBundleError("peer kind must be temporary-mesh or canonical-service")
        address = _parse_address(peer["address"], f"{label}.address")
        if address == client["address"] or address in peer_addresses:
            raise AccessBundleError("every bundle peer must have a distinct address")
        peer_addresses.add(address)
        public_key = _parse_public_key(peer["public_key"], f"{label}.public_key")
        if public_key == client["public_key"] or public_key in peer_keys:
            raise AccessBundleError("every bundle peer must have a distinct public key")
        peer_keys.add(public_key)
        endpoint = _parse_endpoint(peer["endpoint"], f"{label}.endpoint")
        normalized = {
            "id": peer_id,
            "kind": kind,
            "address": address,
            "public_key": public_key,
            "endpoint": endpoint,
        }
        if kind == "temporary-mesh":
            temporary_count += 1
            expected_endpoint = mesh_client["hub_transport"]["endpoint"]
            if normalized != {
                "id": mesh_hub["id"],
                "kind": "temporary-mesh",
                "address": mesh_hub["address"],
                "public_key": mesh_hub["public_key"],
                "endpoint": expected_endpoint,
            }:
                raise AccessBundleError(
                    "the temporary-mesh peer must exactly match the active mesh hub and client transport"
                )
        else:
            canonical_count += 1
            if ipaddress.ip_interface(address).ip in mesh_subnet:
                raise AccessBundleError(
                    "a canonical-service peer address must remain outside the temporary mesh subnet"
                )
        normalized_peers.append(normalized)
    if temporary_count != 1 or canonical_count < 1:
        raise AccessBundleError(
            "an active access bundle requires exactly one temporary-mesh peer and one or more canonical-service peers"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generation": generation,
        "expires_at": mesh_document["expires_at"],
        "client": client,
        "peers": sorted(normalized_peers, key=lambda item: item["id"]),
    }


def load_document(path: Path) -> dict[str, Any]:
    try:
        raw = MESH._load_json_document(path)
    except MESH.MeshError as error:
        raise AccessBundleError(str(error)) from error
    return raw


def initialize(path: Path) -> Path:
    payload = (json.dumps(inert_document(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        return MESH._write_owner_only_new(path, payload, require_owner_only_parent=False)
    except MESH.MeshError as error:
        raise AccessBundleError(str(error)) from error


def _render_profile(document: dict[str, Any], private_key: str) -> str:
    lines = [
        "# Render-only multi-service WireGuard access bundle.",
        "# Importing this replacement profile is a separate explicit action.",
        "# Exact /32 routes only: no peer transit, default route, or writer selection.",
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {document['client']['address']}",
    ]
    for peer in document["peers"]:
        lines.extend(
            [
                "",
                "[Peer]",
                f"# Peer = {peer['id']} ({peer['kind']})",
                f"PublicKey = {peer['public_key']}",
                f"AllowedIPs = {peer['address']}",
                f"Endpoint = {peer['endpoint']}",
                "PersistentKeepalive = 25",
            ]
        )
    return "\n".join(lines) + "\n"


def _render_manifest(document: dict[str, Any], config_name: str) -> str:
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generation": document["generation"],
        "expires_at": document["expires_at"],
        "client_id": document["client"]["id"],
        "client_address": document["client"]["address"],
        "config_file": config_name,
        "peer_ids": [peer["id"] for peer in document["peers"]],
        "peer_addresses": [peer["address"] for peer in document["peers"]],
        "activation_performed": False,
        "peer_transit_enabled": False,
        "default_route_enabled": False,
        "application_writer_selected": False,
        "private_key_in_manifest": False,
    }
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def render(
    *,
    document: dict[str, Any],
    mesh_document: dict[str, Any],
    private_key_path: Path,
    output_dir: Path,
) -> tuple[Path, Path]:
    document = validate_document(document, mesh_document=mesh_document)
    if document["generation"] == 0:
        raise AccessBundleError("generation 0 is inert and cannot be rendered")
    try:
        private_key = MESH._read_private_key(private_key_path)
        derived_public_key = MESH._run_wg("wg", "pubkey", private_key=private_key)
    except MESH.MeshError as error:
        raise AccessBundleError(str(error)) from error
    if derived_public_key != document["client"]["public_key"]:
        raise AccessBundleError("the private key does not match the configured client public key")
    try:
        output_absolute = MESH._ensure_private_directory(output_dir)
        config_path = output_absolute / f"{document['client']['id']}-access-bundle.conf"
        manifest_path = output_absolute / "manifest.json"
        MESH._assert_target_available(config_path)
        MESH._assert_target_available(manifest_path)
        config = _render_profile(document, private_key).encode("utf-8")
        manifest = _render_manifest(document, config_path.name).encode("utf-8")
        created_config: Path | None = None
        try:
            created_config = MESH._write_owner_only_new(config_path, config)
            created_manifest = MESH._write_owner_only_new(manifest_path, manifest)
        except Exception:
            if created_config is not None:
                with contextlib.suppress(OSError):
                    created_config.unlink()
            raise
    except MESH.MeshError as error:
        raise AccessBundleError(str(error)) from error
    return created_config, created_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render a static multi-service WireGuard access bundle without activation."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser(
        "init", help="write an inert local access-bundle declaration"
    )
    init_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    validate_parser = subparsers.add_parser(
        "validate", help="validate a local access-bundle declaration"
    )
    validate_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    validate_parser.add_argument("--mesh-config", type=Path, default=DEFAULT_MESH_CONFIG)
    render_parser = subparsers.add_parser("render", help="render one replacement client profile")
    render_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    render_parser.add_argument("--mesh-config", type=Path, default=DEFAULT_MESH_CONFIG)
    render_parser.add_argument("--private-key-file", type=Path, required=True)
    render_parser.add_argument("--output-dir", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            print(f"initialized inert access-bundle config: {initialize(args.config)}")
        else:
            document = load_document(args.config)
            try:
                mesh_document = MESH.load_document(args.mesh_config)
            except MESH.MeshError as error:
                raise AccessBundleError(str(error)) from error
            if args.command == "validate":
                state = validate_document(document, mesh_document=mesh_document)
                print(f"valid access bundle (generation {state['generation']})")
            else:
                state = validate_document(document, mesh_document=mesh_document)
                output_dir = args.output_dir or (
                    DEFAULT_OUTPUT_ROOT
                    / f"generation-{state['generation']}"
                    / state["client"]["id"]
                )
                config_path, manifest_path = render(
                    document=state,
                    mesh_document=mesh_document,
                    private_key_path=args.private_key_file,
                    output_dir=output_dir,
                )
                print(f"rendered owner-only access bundle: {config_path}")
                print(f"rendered key-free access manifest: {manifest_path}")
    except AccessBundleError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
