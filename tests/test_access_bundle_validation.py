"""WireGuard access bundle: validation, rendering and the command line.

The bundle becomes a client profile that carries a private key, so the tests pin what makes it
safe: only exact IPv4 /32 routes (never a default route or a transit subnet), the client must be
the leaf the active mesh already declares, the temporary peer must be the mesh hub, every peer is
distinct, the private key must match the declared public key and appears only in the owner-only
profile, and a failed write leaves no half-made bundle. ``wg`` is replaced; every file lives in a
private temporary directory.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import importlib.util
import json
import os
import stat
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bundle = _load("bundle_validation_under_test", REPO_ROOT / "scripts" / "render_wireguard_access_bundle.py")
Error = bundle.AccessBundleError

PRIVATE_B = base64.b64encode(bytes(range(1, 33))).decode("ascii")
PUBLIC_A = base64.b64encode(bytes([0x11]) * 32).decode("ascii")
PUBLIC_B = base64.b64encode(bytes([0x22]) * 32).decode("ascii")
PUBLIC_C = base64.b64encode(bytes([0x33]) * 32).decode("ascii")
PUBLIC_D = base64.b64encode(bytes([0x44]) * 32).decode("ascii")
EXPIRY = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")


def mesh_document():
    return {
        "schema_version": 2,
        "generation": 7,
        "mesh": {"name": "temporary-home", "subnet": "10.99.0.240/28", "listen_port": 51821,
                 "peer_transit": False},  # fmt: skip
        "failover_mode": "manual-static",
        "cutover_epoch": 3,
        "expires_at": EXPIRY,
        "egress": {"mode": "disabled", "gateway_node_id": None},
        "nodes": [
            {"id": "air", "role": "hub", "platform": "macos", "address": "10.99.0.254/32",
             "public_key": PUBLIC_A},  # fmt: skip
            {"id": "mini", "role": "leaf", "platform": "ios", "address": "10.99.0.241/32",
             "public_key": PUBLIC_B,
             "hub_transport": {"mode": "direct", "endpoint": "192.168.10.125:51821"}},  # fmt: skip
        ],
    }


def bundle_document():
    return {
        "schema_version": 1,
        "generation": 7,
        "expires_at": EXPIRY,
        "client": {"id": "mini", "address": "10.99.0.241/32", "public_key": PUBLIC_B},
        "peers": [
            {"id": "air", "kind": "temporary-mesh", "address": "10.99.0.254/32",
             "public_key": PUBLIC_A, "endpoint": "192.168.10.125:51821"},  # fmt: skip
            {"id": "fed", "kind": "canonical-service", "address": "10.99.0.1/32",
             "public_key": PUBLIC_C, "endpoint": "home.example.net:51820"},  # fmt: skip
        ],
    }


def validate(document=None, mesh=None):
    return bundle.validate_document(
        document if document is not None else bundle_document(),
        mesh_document=mesh if mesh is not None else mesh_document(),
    )


@pytest.fixture
def root(tmp_path):
    tmp_path.chmod(0o700)
    return tmp_path


# --- field parsers ------------------------------------------------------------------------


def test_documents_and_fields_must_have_exactly_the_expected_shape():
    with pytest.raises(Error, match="must be a JSON object"):
        bundle._require_object([], "thing")
    with pytest.raises(Error, match="missing field.*b"):
        bundle._require_exact_fields({"a": 1}, {"a", "b"}, "thing")
    with pytest.raises(Error, match="unsupported field.*c"):
        bundle._require_exact_fields({"a": 1, "c": 2}, {"a"}, "thing")
    bundle._require_exact_fields({"a": 1}, {"a"}, "thing")


@pytest.mark.parametrize("value", ["", "has space", "tab\there", 5, None, ["x"]])
def test_strings_must_be_non_empty_without_whitespace(value):
    with pytest.raises(Error, match="non-empty string without whitespace"):
        bundle._require_string(value, "field")


@pytest.mark.parametrize("value", ["10.0.0.5/32", "192.168.1.1/32"])
def test_canonical_ipv4_slash_32_addresses_are_accepted(value):
    assert bundle._parse_address(value, "a") == value


@pytest.mark.parametrize(
    "value",
    ["10.0.0.5", "10.0.0.5/24", "10.0.0.0/8", "fd00::1/128", "010.0.0.5/32", "not-an-ip/32", "10.0.0.5/32 "],
)
def test_only_exact_canonical_ipv4_slash_32_addresses_are_accepted(value):
    with pytest.raises(Error):
        bundle._parse_address(value, "a")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.168.10.125:51821", "192.168.10.125:51821"),
        ("[2001:db8::1]:51820", "[2001:db8::1]:51820"),
        ("[2001:0DB8:0:0:0:0:0:1]:51820", "[2001:db8::1]:51820"),
        ("home.example.net:51820", "home.example.net:51820"),
    ],
)
def test_endpoints_are_normalised(value, expected):
    assert bundle._parse_endpoint(value, "e") == expected


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("127.0.0.1:51820", "routable unicast"),
        ("0.0.0.0:51820", "routable unicast"),
        ("224.0.0.1:51820", "routable unicast"),
        ("169.254.1.1:51820", "routable unicast"),
        ("[::1]:51820", "routable unicast"),
        ("[fe80::1]:51820", "routable unicast"),
        ("[192.168.1.1]:51820", "must not put an IPv4 address inside brackets"),
        ("[example.net]:51820", "only an IPv6 literal inside brackets"),
    ],
)
def test_unsafe_or_malformed_endpoints_are_refused(value, message):
    with pytest.raises(Error, match=message):
        bundle._parse_endpoint(value, "e")


@pytest.mark.parametrize("value", ["", "host", "host:0", "host:99999", "host:abc", 5, None, "bad_name!:51820"])
def test_endpoints_without_a_valid_host_and_port_are_refused(value):
    with pytest.raises(Error):
        bundle._parse_endpoint(value, "e")


def test_public_keys_must_decode_to_thirty_two_bytes():
    assert bundle._parse_public_key(PUBLIC_A, "k") == PUBLIC_A
    for bad in ("short", "!" * 44, base64.b64encode(b"x" * 16).decode(), "", 5):
        with pytest.raises(Error):
            bundle._parse_public_key(bad, "k")


def test_node_ids_are_validated_by_the_mesh_rules():
    assert bundle._parse_node_id("mini", "id") == "mini"
    for bad in ("", "Has Space", "UPPER!", 5, None):
        with pytest.raises(Error):
            bundle._parse_node_id(bad, "id")


# --- the whole document -------------------------------------------------------------------


def test_the_inert_document_is_the_safe_default():
    assert bundle.inert_document() == {
        "schema_version": 1, "generation": 0, "expires_at": None, "client": {}, "peers": []
    }  # fmt: skip


def test_generation_zero_must_be_inert_and_validates_to_the_inert_document():
    inert = bundle.inert_document()
    assert validate(copy.deepcopy(inert)) == inert
    for change in (
        {"expires_at": EXPIRY},
        {"client": {"id": "x"}},
        {"peers": [{"id": "x"}]},
    ):
        with pytest.raises(Error, match="generation 0 must be inert"):
            validate({**copy.deepcopy(inert), **change})


@pytest.mark.parametrize("generation", [-1, 1.5, "7", True, None])
def test_the_generation_must_be_a_non_negative_integer(generation):
    document = bundle_document()
    document["generation"] = generation
    with pytest.raises(Error, match="generation must be an integer"):
        validate(document)


def test_unknown_schema_versions_and_extra_or_missing_fields_are_refused():
    document = bundle_document()
    document["schema_version"] = 2
    with pytest.raises(Error, match="schema_version must be 1"):
        validate(document)
    document = bundle_document()
    document["extra"] = 1
    with pytest.raises(Error, match="unsupported field"):
        validate(document)
    document = bundle_document()
    del document["peers"]
    with pytest.raises(Error, match="missing field"):
        validate(document)
    with pytest.raises(Error, match="must be a JSON object"):
        validate([])


def test_an_active_bundle_needs_an_active_mesh_with_the_same_generation_and_expiry():
    inert_mesh = {
        **mesh_document(),
        "generation": 0,
        "cutover_epoch": 0,
        "expires_at": None,
        "nodes": [],
    }
    with pytest.raises(Error, match="requires an active mesh declaration"):
        validate(mesh=inert_mesh)
    document = bundle_document()
    document["generation"] = 8
    with pytest.raises(Error, match="generation must equal the active mesh generation"):
        validate(document)
    document = bundle_document()
    document["expires_at"] = "2099-01-01T00:00:00Z"
    with pytest.raises(Error, match="expiry must equal"):
        validate(document)


def test_the_client_must_be_a_leaf_of_the_active_mesh_with_its_exact_identity():
    document = bundle_document()
    document["client"]["id"] = "ghost"
    with pytest.raises(Error, match="must identify a leaf"):
        validate(document)
    document = bundle_document()
    document["client"] = {"id": "air", "address": "10.99.0.254/32", "public_key": PUBLIC_A}
    document["peers"][0]["id"] = "mini"
    with pytest.raises(Error, match="must identify a leaf"):  # a hub is not a client
        validate(document)
    document = bundle_document()
    document["client"]["address"] = "10.99.0.242/32"
    with pytest.raises(Error, match="exactly match the active mesh leaf"):
        validate(document)
    document = bundle_document()
    document["client"]["public_key"] = PUBLIC_D
    with pytest.raises(Error, match="exactly match the active mesh leaf"):
        validate(document)
    document = bundle_document()
    del document["client"]["address"]
    with pytest.raises(Error, match="missing field"):
        validate(document)


@pytest.mark.parametrize("peers", [[], "nope", None])
def test_an_active_bundle_needs_at_least_two_peers(peers):
    document = bundle_document()
    document["peers"] = peers
    with pytest.raises(Error, match="at least two peers"):
        validate(document)
    document = bundle_document()
    document["peers"] = document["peers"][:1]
    with pytest.raises(Error, match="at least two peers"):
        validate(document)


def test_peer_ids_must_be_unique_and_not_the_client():
    document = bundle_document()
    document["peers"][1]["id"] = "air"
    with pytest.raises(Error, match="unique and distinct from client.id"):
        validate(document)
    document = bundle_document()
    document["peers"][1]["id"] = "mini"
    with pytest.raises(Error, match="unique and distinct from client.id"):
        validate(document)


def test_peer_kinds_are_limited():
    document = bundle_document()
    document["peers"][1]["kind"] = "relay"
    with pytest.raises(Error, match="temporary-mesh or canonical-service"):
        validate(document)


def test_every_peer_has_its_own_address_and_key_distinct_from_the_client():
    document = bundle_document()
    document["peers"][1]["address"] = "10.99.0.254/32"
    with pytest.raises(Error, match="distinct address"):
        validate(document)
    document = bundle_document()
    document["peers"][1]["address"] = "10.99.0.241/32"
    with pytest.raises(Error, match="distinct address"):
        validate(document)
    document = bundle_document()
    document["peers"][1]["public_key"] = PUBLIC_A
    with pytest.raises(Error, match="distinct public key"):
        validate(document)
    document = bundle_document()
    document["peers"][1]["public_key"] = PUBLIC_B
    with pytest.raises(Error, match="distinct public key"):
        validate(document)


def test_the_temporary_peer_must_be_exactly_the_mesh_hub_over_the_clients_transport():
    for field, value in (
        ("id", "fed2"),
        ("address", "10.99.0.253/32"),
        ("public_key", PUBLIC_D),
        ("endpoint", "192.168.10.126:51821"),
    ):
        document = bundle_document()
        document["peers"][0][field] = value
        with pytest.raises(Error):
            validate(document)


def test_exactly_one_temporary_peer_and_at_least_one_canonical_peer():
    document = bundle_document()
    document["peers"][1] = {"id": "air2", "kind": "temporary-mesh", "address": "10.99.0.254/32",
                            "public_key": PUBLIC_D, "endpoint": "192.168.10.125:51821"}  # fmt: skip
    with pytest.raises(Error):
        validate(document)
    document = bundle_document()
    document["peers"].append({"id": "fed2", "kind": "canonical-service", "address": "10.98.0.2/32",
                              "public_key": PUBLIC_D, "endpoint": "other.example.net:51820"})  # fmt: skip
    result = validate(document)
    assert [p["id"] for p in result["peers"]] == ["air", "fed", "fed2"]


def test_a_canonical_peer_may_not_sit_inside_the_temporary_mesh_subnet():
    document = bundle_document()
    document["peers"][1]["address"] = "10.99.0.250/32"
    with pytest.raises(Error, match="outside the temporary mesh subnet"):
        validate(document)


def test_a_valid_bundle_is_normalised_and_sorted_by_peer_id():
    document = bundle_document()
    document["peers"].reverse()
    result = validate(document)
    assert [p["id"] for p in result["peers"]] == ["air", "fed"]
    assert result["generation"] == 7 and result["expires_at"] == EXPIRY
    assert set(result) == {"schema_version", "generation", "expires_at", "client", "peers"}


# --- files --------------------------------------------------------------------------------


def test_initialising_writes_an_inert_owner_only_declaration_and_refuses_to_overwrite(root):
    path = root / "bundle.json"
    assert bundle.initialize(path) == path
    assert json.loads(path.read_text()) == bundle.inert_document()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(Error, match="refusing to overwrite"):
        bundle.initialize(path)


def test_loading_reports_unreadable_or_malformed_declarations_as_bundle_errors(root):
    with pytest.raises(Error):
        bundle.load_document(root / "missing.json")
    bad = root / "bad.json"
    bad.write_text("{not json")
    bad.chmod(0o600)
    with pytest.raises(Error):
        bundle.load_document(bad)
    good = root / "good.json"
    good.write_text(json.dumps(bundle_document()))
    good.chmod(0o600)
    assert bundle.load_document(good)["generation"] == 7


# --- rendering ----------------------------------------------------------------------------


def key_file(root, content=None, mode=0o600):
    path = root / "mini.key"
    path.write_text((content or PRIVATE_B) + "\n", encoding="ascii")
    path.chmod(mode)
    return path


def render(root, *, derived=PUBLIC_B, output=None, document=None):
    with mock.patch.object(bundle.MESH, "_run_wg", return_value=derived):
        return bundle.render(
            document=document if document is not None else bundle_document(),
            mesh_document=mesh_document(),
            private_key_path=key_file(root),
            output_dir=output or root / "out",
        )


def test_the_profile_has_exact_routes_the_private_key_and_nothing_wider(root):
    profile_path, manifest_path = render(root)
    profile = profile_path.read_text()
    assert profile_path.name == "mini-access-bundle.conf" and manifest_path.name == "manifest.json"
    assert f"PrivateKey = {PRIVATE_B}" in profile
    assert "Address = 10.99.0.241/32" in profile
    assert profile.count("[Peer]") == 2
    assert profile.count("PersistentKeepalive = 25") == 2
    assert "AllowedIPs = 10.99.0.254/32" in profile and "AllowedIPs = 10.99.0.1/32" in profile
    assert "Endpoint = 192.168.10.125:51821" in profile
    assert "Endpoint = home.example.net:51820" in profile
    for forbidden in ("0.0.0.0/0", "::/0", "10.99.0.240/28", "DNS =", "PostUp", "PreUp"):
        assert forbidden not in profile


def test_the_manifest_is_key_free_and_states_nothing_was_activated(root):
    _, manifest_path = render(root)
    text = manifest_path.read_text()
    manifest = json.loads(text)
    assert PRIVATE_B not in text and "PrivateKey" not in text
    assert manifest["private_key_in_manifest"] is False
    for flag in ("activation_performed", "peer_transit_enabled", "default_route_enabled",
                 "application_writer_selected"):  # fmt: skip
        assert manifest[flag] is False
    assert manifest["config_file"] == "mini-access-bundle.conf"
    assert manifest["peer_ids"] == ["air", "fed"]
    assert manifest["peer_addresses"] == ["10.99.0.254/32", "10.99.0.1/32"]
    assert manifest["client_id"] == "mini" and manifest["generation"] == 7


def test_the_bundle_directory_and_files_are_owner_only(root):
    profile_path, manifest_path = render(root)
    assert stat.S_IMODE(profile_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(profile_path.parent.stat().st_mode) & 0o077 == 0


def test_an_inert_document_cannot_be_rendered(root):
    with pytest.raises(Error, match="generation 0 is inert"):
        bundle.render(
            document=bundle.inert_document(),
            mesh_document=mesh_document(),
            private_key_path=key_file(root),
            output_dir=root / "out",
        )
    assert not (root / "out").exists()


def test_a_private_key_that_does_not_match_the_client_is_refused_and_writes_nothing(root):
    with pytest.raises(Error, match="does not match the configured client public key"):
        render(root, derived=PUBLIC_D)
    assert not list((root / "out").glob("*")) if (root / "out").exists() else True


def test_a_loose_or_missing_key_file_is_refused(root):
    loose = key_file(root, mode=0o644)
    with mock.patch.object(bundle.MESH, "_run_wg", return_value=PUBLIC_B), pytest.raises(Error):
        bundle.render(document=bundle_document(), mesh_document=mesh_document(),
                      private_key_path=loose, output_dir=root / "out")  # fmt: skip
    with pytest.raises(Error):
        bundle.render(document=bundle_document(), mesh_document=mesh_document(),
                      private_key_path=root / "absent.key", output_dir=root / "out2")  # fmt: skip


def test_a_wg_failure_is_reported_as_a_bundle_error(root):
    with mock.patch.object(bundle.MESH, "_run_wg", side_effect=bundle.MESH.MeshError("wg failed")):
        with pytest.raises(Error, match="wg failed"):
            bundle.render(document=bundle_document(), mesh_document=mesh_document(),
                          private_key_path=key_file(root), output_dir=root / "out")  # fmt: skip


def test_an_existing_target_is_never_overwritten(root):
    render(root)
    with pytest.raises(Error, match="refusing to overwrite"):
        render(root)


def test_a_failed_manifest_write_removes_the_profile_so_no_half_bundle_is_left(root):
    real = bundle.MESH._write_owner_only_new
    calls = []

    def flaky(path, payload, *args, **kwargs):
        calls.append(path.name)
        if path.name == "manifest.json":
            raise OSError("disk full")
        return real(path, payload, *args, **kwargs)

    with mock.patch.object(bundle.MESH, "_write_owner_only_new", flaky), pytest.raises(OSError):
        render(root)
    assert calls == ["mini-access-bundle.conf", "manifest.json"]
    assert list((root / "out").glob("*")) == []  # the private-key profile was removed


def test_a_mesh_error_while_writing_is_reported_as_a_bundle_error(root):
    with mock.patch.object(bundle.MESH, "_write_owner_only_new",
                           side_effect=bundle.MESH.MeshError("cannot write")):  # fmt: skip
        with pytest.raises(Error, match="cannot write"):
            render(root)


# --- the command line ---------------------------------------------------------------------


@pytest.fixture
def declared(root):
    bundle_path = root / "bundle.json"
    mesh_path = root / "mesh.json"
    for path, document in ((bundle_path, bundle_document()), (mesh_path, mesh_document())):
        path.write_text(json.dumps(document))
        path.chmod(0o600)
    return bundle_path, mesh_path


def test_init_writes_an_inert_declaration_and_says_where(root, capsys):
    path = root / "new.json"
    assert bundle.main(["init", "--config", str(path)]) == 0
    assert f"initialized inert access-bundle config: {path}" in capsys.readouterr().out
    assert json.loads(path.read_text())["generation"] == 0
    assert bundle.main(["init", "--config", str(path)]) == 1
    assert "error: " in capsys.readouterr().err


def test_validate_reports_the_generation(declared, capsys):
    bundle_path, mesh_path = declared
    assert bundle.main(["validate", "--config", str(bundle_path), "--mesh-config", str(mesh_path)]) == 0
    assert "valid access bundle (generation 7)" in capsys.readouterr().out


def test_validate_failures_are_one_line_errors_not_tracebacks(declared, root, capsys):
    bundle_path, mesh_path = declared
    broken = bundle_document()
    broken["client"]["id"] = "ghost"
    bundle_path.write_text(json.dumps(broken))
    assert bundle.main(["validate", "--config", str(bundle_path), "--mesh-config", str(mesh_path)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err
    assert bundle.main(["validate", "--config", str(bundle_path), "--mesh-config", str(root / "none.json")]) == 1
    assert "error: " in capsys.readouterr().err


def test_render_writes_to_the_requested_directory_and_never_prints_the_key(declared, root, capsys):
    bundle_path, mesh_path = declared
    out = root / "chosen"
    key = key_file(root)
    with mock.patch.object(bundle.MESH, "_run_wg", return_value=PUBLIC_B):
        code = bundle.main(["render", "--config", str(bundle_path), "--mesh-config", str(mesh_path),
                            "--private-key-file", str(key), "--output-dir", str(out)])  # fmt: skip
    captured = capsys.readouterr()
    assert code == 0
    assert f"rendered owner-only access bundle: {out / 'mini-access-bundle.conf'}" in captured.out
    assert f"rendered key-free access manifest: {out / 'manifest.json'}" in captured.out
    assert PRIVATE_B not in captured.out + captured.err


def test_render_defaults_to_a_per_generation_per_client_directory(declared, root, capsys, monkeypatch):
    bundle_path, mesh_path = declared
    monkeypatch.chdir(root)
    monkeypatch.setattr(bundle, "DEFAULT_OUTPUT_ROOT", Path("bundles"))
    key = key_file(root)
    with mock.patch.object(bundle.MESH, "_run_wg", return_value=PUBLIC_B):
        code = bundle.main(["render", "--config", str(bundle_path), "--mesh-config", str(mesh_path),
                            "--private-key-file", str(key)])  # fmt: skip
    assert code == 0
    assert (root / "bundles" / "generation-7" / "mini" / "mini-access-bundle.conf").is_file()


def test_render_with_a_mismatched_key_fails_cleanly(declared, root, capsys):
    bundle_path, mesh_path = declared
    key = key_file(root)
    with mock.patch.object(bundle.MESH, "_run_wg", return_value=PUBLIC_D):
        code = bundle.main(["render", "--config", str(bundle_path), "--mesh-config", str(mesh_path),
                            "--private-key-file", str(key), "--output-dir", str(root / "o")])  # fmt: skip
    assert code == 1
    assert "does not match the configured client public key" in capsys.readouterr().err


def test_a_subcommand_is_required():
    with pytest.raises(SystemExit):
        bundle.main([])


def test_the_mesh_validator_is_loaded_from_the_repository():
    assert bundle.MESH_RENDERER_PATH == REPO_ROOT / "scripts" / "render_wireguard_mesh.py"
    assert os.path.exists(bundle.MESH_RENDERER_PATH)


# --- remaining edges ----------------------------------------------------------------------


def test_an_ipv6_endpoint_must_be_bracketed():
    with pytest.raises(Error, match="put an IPv6 address inside brackets"):
        bundle._parse_endpoint("2001:db8::1:51820", "e")


def test_a_bundle_with_no_temporary_peer_is_refused():
    document = bundle_document()
    document["peers"] = [
        document["peers"][1],
        {"id": "fed2", "kind": "canonical-service", "address": "10.98.0.2/32",
         "public_key": PUBLIC_D, "endpoint": "other.example.net:51820"},  # fmt: skip
    ]
    with pytest.raises(Error, match="exactly one temporary-mesh peer and one or more canonical"):
        validate(document)


def test_a_bundle_with_only_the_temporary_peer_and_a_second_temporary_peer_is_refused():
    document = bundle_document()
    document["peers"][1] = {"id": "air2", "kind": "temporary-mesh", "address": "10.99.0.253/32",
                            "public_key": PUBLIC_D, "endpoint": "192.168.10.125:51821"}  # fmt: skip
    with pytest.raises(Error):
        validate(document)


def test_the_mesh_validator_failing_to_load_is_a_clean_bundle_error(tmp_path):
    with mock.patch.object(bundle, "MESH_RENDERER_PATH", tmp_path / "missing.py"):
        with pytest.raises(Error, match="could not load the WireGuard mesh validator"):
            bundle._load_mesh_renderer()
    with mock.patch.object(bundle.importlib.util, "spec_from_file_location", return_value=None):
        with pytest.raises(Error, match="could not load the WireGuard mesh validator"):
            bundle._load_mesh_renderer()


def test_running_the_script_directly_exits_through_main(tmp_path, monkeypatch):
    import runpy
    import sys

    target = tmp_path / "direct.json"
    monkeypatch.setattr(sys, "argv", ["prog", "init", "--config", str(target)])
    with pytest.raises(SystemExit) as info:
        runpy.run_path(str(REPO_ROOT / "scripts" / "render_wireguard_access_bundle.py"), run_name="__main__")
    assert info.value.code == 0
    assert json.loads(target.read_text())["generation"] == 0


@pytest.mark.parametrize("existing", ["manifest.json", "mini-access-bundle.conf"])
def test_an_existing_target_is_detected_before_any_private_key_file_is_written(root, existing):
    out = root / "out"
    out.mkdir(mode=0o700)
    (out / existing).write_text("already here")
    writes = []
    real = bundle.MESH._write_owner_only_new

    def spy(path, payload, *args, **kwargs):
        writes.append(path.name)
        return real(path, payload, *args, **kwargs)

    with mock.patch.object(bundle.MESH, "_write_owner_only_new", spy), pytest.raises(Error):
        render(root, output=out)
    assert writes == []  # nothing, not even a file that would be removed again afterwards
    assert (out / existing).read_text() == "already here"
