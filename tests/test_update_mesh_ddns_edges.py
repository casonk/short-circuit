"""The DNS updater: config rules, what it sends, and what it keeps secret.

This script holds a provider API token (or a token inside an update URL) and performs a real DNS
change from a cron-like context, so the tests pin: the config must be an owner-only regular file,
the detected address must be a public address of the right family, nothing is changed unless the
record differs (or --force), a dry run and a non-active host change nothing, credentials go only
in the headers they belong in, and no error message repeats a secret. Every network call, the
active-hub command and the clock are replaced; files live in a private temporary directory.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import stat
import subprocess
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "ddns_edges_under_test", REPO_ROOT / "scripts" / "update_mesh_ddns.py"
)
assert spec is not None and spec.loader is not None
ddns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ddns)
Error = ddns.DdnsError

CANARY = "canary-not-a-real-credential"


def cloudflare(**kw):
    config = {
        "fqdn": "mesh.example.com", "provider": "cloudflare", "record_type": "A", "ttl": 60,
        "ip_source": "https://ip.example.com", "api_token": CANARY, "zone_id": "zone1",
    }  # fmt: skip
    config.update(kw)
    return config


def generic(**kw):
    config = {
        "fqdn": "mesh.example.com", "provider": "generic-url", "record_type": "A", "ttl": 60,
        "ip_source": "https://ip.example.com",
        "url_template": f"https://dyn.example.com/update?token={CANARY}&ip={{ip}}",
    }  # fmt: skip
    config.update(kw)
    return config


class Http:
    """A scripted HTTP function recording every call."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        for (m, fragment), result in self.routes.items():
            if m == method and fragment in url:
                if isinstance(result, BaseException):
                    raise result
                return result
        raise AssertionError(f"unexpected call {method} {url}")


@pytest.fixture
def root(tmp_path):
    tmp_path.chmod(0o700)
    return tmp_path


def owner_only(root, name, content, mode=0o600):
    path = root / name
    path.write_bytes(content if isinstance(content, bytes) else content.encode())
    path.chmod(mode)
    return path


# --- config ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [("MESH.Example.COM", "mesh.example.com"), ("a.b", "a.b"), ("x-1.example.org", "x-1.example.org")],
)
def test_names_are_lowercased(value, expected):
    assert ddns._validate_fqdn(value) == expected


@pytest.mark.parametrize(
    "value",
    ["example", "example.com.", "bücher.example", "-a.example.com", "a-.example.com",
     "a..example.com", "under_score.example.com", "a" * 64 + ".com", ("a." * 130) + "com", "", None, 5],
)  # fmt: skip
def test_names_must_be_canonical_fully_qualified_dns_names(value):
    with pytest.raises(Error):
        ddns._validate_fqdn(value)


@pytest.mark.parametrize("url", ["http://x.example", "ftp://x", "x.example", "", None, 5])
def test_only_https_urls_are_accepted(url):
    with pytest.raises(Error):
        ddns._require_https_url(url, "u")


def test_valid_configs_are_normalised_and_unknown_or_missing_fields_refused():
    assert ddns.validate_config(cloudflare(fqdn="MESH.example.com"))["fqdn"] == "mesh.example.com"
    assert ddns.validate_config(cloudflare(record_id="rec1"))["record_id"] == "rec1"
    full = ddns.validate_config(
        generic(basic_auth_user="u", basic_auth_password="p", state_file="/tmp/s")
    )
    assert full["basic_auth_user"] == "u" and full["state_file"] == "/tmp/s"
    for config, message in (
        (cloudflare(extra=1), "unsupported field"),
        (generic(api_token="x"), "unsupported field"),
        ({k: v for k, v in cloudflare().items() if k != "zone_id"}, "missing field"),
        (cloudflare(provider="route53"), "provider must be"),
        ([], "must be a JSON object"),
    ):
        with pytest.raises(Error, match=message):
            ddns.validate_config(config)


@pytest.mark.parametrize("ttl", [29, 86401, True, "60", 60.5, None])
def test_ttl_must_be_an_integer_in_range(ttl):
    with pytest.raises(Error, match="ttl must be an integer"):
        ddns.validate_config(cloudflare(ttl=ttl))


@pytest.mark.parametrize("ttl", [30, 86400])
def test_ttl_bounds_are_inclusive(ttl):
    assert ddns.validate_config(cloudflare(ttl=ttl))["ttl"] == ttl


def test_record_type_and_url_rules():
    with pytest.raises(Error, match="record_type must be A or AAAA"):
        ddns.validate_config(cloudflare(record_type="CNAME"))
    assert ddns.validate_config(cloudflare(record_type="AAAA"))["record_type"] == "AAAA"
    with pytest.raises(Error, match="ip_source must be an https"):
        ddns.validate_config(cloudflare(ip_source="http://ip.example.com"))
    with pytest.raises(Error, match=r"\{ip\} placeholder"):
        ddns.validate_config(generic(url_template="https://dyn.example.com/update"))
    with pytest.raises(Error, match="url_template must be an https"):
        ddns.validate_config(generic(url_template="http://dyn.example.com/{ip}"))
    for field in ("basic_auth_user", "basic_auth_password", "state_file", "api_token"):
        config = generic(**{field: ""}) if field != "api_token" else cloudflare(api_token="")
        with pytest.raises(Error, match="non-empty string"):
            ddns.validate_config(config)


# --- the config file ----------------------------------------------------------------------


def test_the_config_must_exist_be_regular_owner_only_and_small(root):
    with pytest.raises(Error, match="does not exist"):
        ddns.load_config(root / "none.json")
    target = owner_only(root, "real.json", json.dumps(cloudflare()))
    link = root / "link.json"
    link.symlink_to(target)
    with pytest.raises(Error, match="not a symlink"):
        ddns.load_config(link)
    with pytest.raises(Error, match="regular file"):
        ddns.load_config(root)
    loose = owner_only(root, "loose.json", json.dumps(cloudflare()), mode=0o640)
    with pytest.raises(Error, match="group or other permissions"):
        ddns.load_config(loose)
    big = owner_only(root, "big.json", b" " * (ddns.MAX_CONFIG_BYTES + 1))
    with pytest.raises(Error, match="maximum allowed size"):
        ddns.load_config(big)
    with mock.patch.object(ddns.os, "geteuid", return_value=os.geteuid() + 1):
        with pytest.raises(Error, match="owned by the current user"):
            ddns.load_config(target)


def test_a_good_config_loads_and_a_bad_one_is_a_clean_error(root):
    good = owner_only(root, "good.json", json.dumps(cloudflare()))
    assert ddns.load_config(good)["zone_id"] == "zone1"
    for name, content in (("bin.json", b"\xff\xfe"), ("junk.json", b"{not json")):
        with pytest.raises(Error, match="valid UTF-8 JSON"):
            ddns.load_config(owner_only(root, name, content))


# --- HTTP ---------------------------------------------------------------------------------


class Response:
    def __init__(self, body):
        self.body = body

    def read(self, limit=None):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_the_default_http_sends_the_request_and_parses_json_text_or_nothing():
    seen = {}

    def fake(request, timeout):
        seen.update(method=request.get_method(), url=request.full_url, data=request.data,
                    headers=dict(request.header_items()), timeout=timeout)  # fmt: skip
        return Response(seen.setdefault("body", b'{"ok": true}'))

    with mock.patch.object(ddns.urllib.request, "urlopen", fake):
        assert ddns._default_http("PUT", "https://x.example/a", {"X-Test": "1"}, b"body") == {"ok": True}
        assert seen["method"] == "PUT" and seen["data"] == b"body" and seen["timeout"] == 15
        assert seen["headers"]["X-test"] == "1"
        seen["body"] = b""
        assert ddns._default_http("GET", "https://x.example/a", {}, None) is None
        seen["body"] = b"93.184.216.34\n"
        assert ddns._default_http("GET", "https://x.example/a", {}, None) == "93.184.216.34\n"
        seen["body"] = b"\xff\xfe"
        assert isinstance(ddns._default_http("GET", "https://x.example/a", {}, None), str)


def test_an_http_failure_never_repeats_the_secret_in_the_update_url():
    url = f"https://dyn.example.com:8443/update?token={CANARY}&ip=93.184.216.34"
    error = urllib.error.URLError("connection refused")
    with mock.patch.object(ddns.urllib.request, "urlopen", side_effect=error):
        with pytest.raises(Error) as info:
            ddns._default_http("GET", url, {}, None)
    message = str(info.value)
    assert CANARY not in message and "93.184.216.34" not in message
    assert "https://dyn.example.com:8443/update" in message
    assert "connection refused" in message and message.startswith("GET ")


def test_credentials_embedded_in_a_url_are_not_repeated_either():
    error = urllib.error.URLError("boom")
    with mock.patch.object(ddns.urllib.request, "urlopen", side_effect=error):
        with pytest.raises(Error) as info:
            ddns._default_http("GET", "https://user:hunter2@dyn.example.com/u#frag", {}, None)
    assert "hunter2" not in str(info.value) and "user" not in str(info.value).split("failed")[0]
    assert "dyn.example.com/u" in str(info.value)


# --- the address --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "record_type", "expected"),
    [("93.184.216.34", "A", "93.184.216.34"), (" 8.8.8.8 \n", "A", "8.8.8.8"),
     ("2001:4860:4860:0:0:0:0:8888", "AAAA", "2001:4860:4860::8888")],
)  # fmt: skip
def test_public_addresses_of_the_right_family_are_accepted_and_normalised(value, record_type, expected):
    assert ddns._validate_ip(value, record_type, "ip") == expected


@pytest.mark.parametrize(
    ("value", "record_type", "message"),
    [("not-an-ip", "A", "not a valid IP"), ("", "A", "not a valid IP"),
     ("2001:4860:4860::8888", "A", "does not match record_type A"),
     ("8.8.8.8", "AAAA", "does not match record_type AAAA"),
     ("10.0.0.5", "A", "global"), ("192.168.1.1", "A", "global"), ("127.0.0.1", "A", "global"),
     ("169.254.1.1", "A", "global"), ("100.64.0.1", "A", "global"), ("0.0.0.0", "A", "global"),
     ("fd00::1", "AAAA", "global"), ("2001:db8::1", "AAAA", "global")],
)  # fmt: skip
def test_private_special_and_wrong_family_addresses_are_refused(value, record_type, message):
    with pytest.raises(Error, match=message):
        ddns._validate_ip(value, record_type, "ip")


@pytest.mark.parametrize(
    "answer",
    ["93.184.216.34", "  93.184.216.34\n", '{"ip": "93.184.216.34"}', {"ip": "93.184.216.34"}],
)
def test_the_detected_address_may_be_bare_or_json(answer):
    http = Http({("GET", "ip.example.com"): answer})
    assert ddns.detect_public_ip(cloudflare(), http) == "93.184.216.34"
    assert http.calls[0][2] == {"Accept": "text/plain"}


def test_a_malformed_or_private_detection_answer_is_refused():
    for answer in ("{broken", '{"other": 1}', "10.0.0.1", "<html>blocked</html>"):
        with pytest.raises(Error):
            ddns.detect_public_ip(cloudflare(), Http({("GET", "ip.example.com"): answer}))


# --- Cloudflare ---------------------------------------------------------------------------


def test_the_record_is_found_by_type_and_name_when_no_id_is_configured():
    http = Http({("GET", "dns_records"): {"result": [{"id": "rec9", "content": "1.1.1.1"}, {"id": "rec8"}]}})
    assert ddns._cloudflare_current(cloudflare(), http) == ("rec9", "1.1.1.1")
    method, url, headers, body = http.calls[0]
    assert url == "https://api.cloudflare.com/client/v4/zones/zone1/dns_records?type=A&name=mesh.example.com"
    assert headers["Authorization"] == f"Bearer {CANARY}" and body is None


def test_a_configured_record_id_is_fetched_directly():
    http = Http({("GET", "/rec1"): {"result": {"content": "2.2.2.2"}}})
    assert ddns._cloudflare_current(cloudflare(record_id="rec1"), http) == ("rec1", "2.2.2.2")
    assert http.calls[0][1].endswith("/zones/zone1/dns_records/rec1")
    http = Http({("GET", "/rec1"): {}})
    assert ddns._cloudflare_current(cloudflare(record_id="rec1"), http) == ("rec1", None)


def test_no_matching_record_or_a_bad_response_is_an_error():
    with pytest.raises(Error, match="no matching DNS record"):
        ddns._cloudflare_current(cloudflare(), Http({("GET", "dns_records"): {"result": []}}))
    with pytest.raises(Error, match="no matching DNS record"):
        ddns._cloudflare_current(cloudflare(), Http({("GET", "dns_records"): {}}))
    with pytest.raises(Error, match="cloudflare response must be a JSON object"):
        ddns._cloudflare_current(cloudflare(), Http({("GET", "dns_records"): "oops"}))
    with pytest.raises(Error, match="must be a JSON object"):
        ddns._cloudflare_current(cloudflare(record_id="r"), Http({("GET", "/r"): None}))


def test_the_update_puts_an_unproxied_record_with_the_configured_ttl():
    http = Http({("PUT", "/rec1"): {"success": True}})
    ddns._cloudflare_update(cloudflare(ttl=120), "rec1", "93.184.216.34", http)
    method, url, headers, body = http.calls[0]
    assert url == "https://api.cloudflare.com/client/v4/zones/zone1/dns_records/rec1"
    assert headers["Authorization"] == f"Bearer {CANARY}"
    assert json.loads(body) == {"type": "A", "name": "mesh.example.com", "content": "93.184.216.34",
                                "ttl": 120, "proxied": False}  # fmt: skip


def test_a_rejected_update_is_an_error_without_the_token():
    for response in ({"success": False}, {}):
        with pytest.raises(Error, match="rejected the DNS update") as info:
            ddns._cloudflare_update(cloudflare(), "rec1", "1.2.3.4", Http({("PUT", "/rec1"): response}))
        assert CANARY not in str(info.value)
    with pytest.raises(Error, match="must be a JSON object"):
        ddns._cloudflare_update(cloudflare(), "rec1", "1.2.3.4", Http({("PUT", "/rec1"): None}))


# --- generic URL --------------------------------------------------------------------------


def test_the_last_published_address_is_read_from_an_owner_only_state_file(root):
    assert ddns._generic_state_ip(generic()) is None
    state = owner_only(root, "state", "93.184.216.34\n")
    assert ddns._generic_state_ip(generic(state_file=str(state))) == "93.184.216.34"
    assert ddns._generic_state_ip(generic(state_file=str(root / "none"))) is None
    assert ddns._generic_state_ip(generic(state_file=str(owner_only(root, "empty", "\n")))) is None
    loose = owner_only(root, "loose", "93.184.216.34\n", mode=0o644)
    assert ddns._generic_state_ip(generic(state_file=str(loose))) is None  # a loose file is not trusted


def test_the_generic_update_substitutes_the_address_and_records_it_owner_only(root):
    state = root / "state"
    http = Http({("GET", "dyn.example.com"): None})
    ddns._generic_update(generic(state_file=str(state)), "93.184.216.34", http)
    method, url, headers, body = http.calls[0]
    assert url == f"https://dyn.example.com/update?token={CANARY}&ip=93.184.216.34"
    assert "Authorization" not in headers and body is None
    assert state.read_text() == "93.184.216.34\n"
    assert stat.S_IMODE(state.stat().st_mode) == 0o600


def test_basic_auth_is_sent_only_in_the_header(root):
    http = Http({("GET", "dyn.example.com"): None})
    ddns._generic_update(generic(basic_auth_user="user", basic_auth_password="pw:with:colons"), "1.2.3.4", http)
    header = http.calls[0][2]["Authorization"]
    assert header == "Basic " + base64.b64encode(b"user:pw:with:colons").decode()
    assert "pw" not in http.calls[0][1]
    http = Http({("GET", "dyn.example.com"): None})
    ddns._generic_update(generic(basic_auth_user="user"), "1.2.3.4", http)
    assert base64.b64decode(http.calls[0][2]["Authorization"].split()[1]) == b"user:"


def test_without_a_state_file_nothing_is_written(root, monkeypatch):
    monkeypatch.chdir(root)
    ddns._generic_update(generic(), "1.2.3.4", Http({("GET", "dyn.example.com"): None}))
    assert list(root.iterdir()) == []


def test_an_existing_loose_state_file_is_tightened_when_rewritten(root):
    state = owner_only(root, "state", "old\n", mode=0o644)
    ddns._write_owner_only(state, b"new\n")
    assert state.read_text() == "new\n" and stat.S_IMODE(state.stat().st_mode) == 0o600


def test_a_symlinked_state_file_is_never_written_through(root):
    target = owner_only(root, "target", "keep\n")
    link = root / "state"
    link.symlink_to(target)
    with pytest.raises(OSError):
        ddns._write_owner_only(link, b"overwritten\n")
    assert target.read_text() == "keep\n"


# --- the active-hub fence ------------------------------------------------------------------


def test_the_active_check_runs_a_shell_command_and_only_exit_zero_means_active():
    assert ddns._run_active_check("exit 0") is True
    assert ddns._run_active_check("exit 1") is False
    assert ddns._run_active_check("exit 3") is False


def test_the_active_check_has_no_stdin_or_output_and_a_timeout():
    with mock.patch.object(ddns.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
        ddns._run_active_check("true")
    args, kwargs = run.call_args
    assert args[0] == ["/bin/sh", "-c", "true"]
    assert kwargs["stdin"] is subprocess.DEVNULL and kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL and kwargs["check"] is False
    assert kwargs["timeout"] == 15


@pytest.mark.parametrize("failure", [OSError("no sh"), subprocess.TimeoutExpired("sh", 15)])
def test_an_active_check_that_cannot_run_is_an_error_not_a_pass(failure):
    with mock.patch.object(ddns.subprocess, "run", side_effect=failure):
        with pytest.raises(Error, match="active-hub check could not run"):
            ddns._run_active_check("true")


# --- the whole update ---------------------------------------------------------------------


def cloudflare_http(current="93.184.216.1", detected="93.184.216.34"):
    return Http({
        ("GET", "ip.example.com"): detected,
        ("GET", "dns_records"): {"result": [{"id": "rec1", "content": current}]},
        ("PUT", "/rec1"): {"success": True},
    })  # fmt: skip


def test_a_changed_address_is_published():
    http = cloudflare_http()
    outcome = ddns.update(cloudflare(), http=http)
    assert outcome == {"action": "updated", "ip": "93.184.216.34", "from": "93.184.216.1", "fqdn": "mesh.example.com"}
    assert [c[0] for c in http.calls] == ["GET", "GET", "PUT"]


def test_an_unchanged_address_is_left_alone_unless_forced():
    http = cloudflare_http(current="93.184.216.34")
    assert ddns.update(cloudflare(), http=http)["action"] == "unchanged"
    assert "PUT" not in [c[0] for c in http.calls]
    http = cloudflare_http(current="93.184.216.34")
    assert ddns.update(cloudflare(), force=True, http=http)["action"] == "updated"
    assert "PUT" in [c[0] for c in http.calls]


def test_a_dry_run_reports_the_change_and_changes_nothing():
    http = cloudflare_http()
    outcome = ddns.update(cloudflare(), dry_run=True, http=http)
    assert outcome == {"action": "would-update", "ip": "93.184.216.34", "from": "93.184.216.1", "fqdn": "mesh.example.com"}
    assert "PUT" not in [c[0] for c in http.calls]
    unchanged = ddns.update(cloudflare(), dry_run=True, http=cloudflare_http(current="93.184.216.34"))
    assert unchanged["action"] == "unchanged"


def test_a_host_that_is_not_the_active_hub_does_nothing_at_all():
    http = cloudflare_http()
    outcome = ddns.update(cloudflare(), http=http, active_check_command="exit 1")
    assert outcome == {"action": "skipped", "reason": "not the active hub", "fqdn": "mesh.example.com"}
    assert http.calls == []  # not even the address lookup
    http = cloudflare_http()
    assert ddns.update(cloudflare(), http=http, active_check_command="exit 0")["action"] == "updated"


def test_the_generic_provider_compares_against_its_state_file(root):
    state = owner_only(root, "state", "93.184.216.34\n")
    http = Http({("GET", "ip.example.com"): "93.184.216.34"})
    assert ddns.update(generic(state_file=str(state)), http=http)["action"] == "unchanged"
    state.write_text("93.184.216.1\n")
    http = Http({("GET", "ip.example.com"): "93.184.216.34", ("GET", "dyn.example.com"): None})
    outcome = ddns.update(generic(state_file=str(state)), http=http)
    assert outcome["action"] == "updated" and outcome["from"] == "93.184.216.1"
    assert state.read_text() == "93.184.216.34\n"


def test_a_generic_dry_run_leaves_the_state_file_untouched(root):
    state = owner_only(root, "state", "93.184.216.1\n")
    http = Http({("GET", "ip.example.com"): "93.184.216.34"})
    assert ddns.update(generic(state_file=str(state)), dry_run=True, http=http)["action"] == "would-update"
    assert state.read_text() == "93.184.216.1\n"


def test_the_default_http_function_is_used_when_none_is_given():
    with mock.patch.object(ddns, "_default_http", return_value="93.184.216.34") as fake:
        with pytest.raises(Error):  # a cloudflare lookup then fails on the same fake
            ddns.update(cloudflare())
    assert fake.called


# --- the command line ---------------------------------------------------------------------


def test_main_prints_one_sorted_json_line_and_passes_the_flags_through(root, capsys):
    path = owner_only(root, "ddns.json", json.dumps(cloudflare()))
    with mock.patch.object(ddns, "update", return_value={"b": 1, "a": 2}) as fake:
        code = ddns.main(["--config", str(path), "--dry-run", "--force", "--check-active-command", "exit 0"])
    assert code == 0
    assert capsys.readouterr().out == '{"a": 2, "b": 1}\n'
    kwargs = fake.call_args.kwargs
    assert kwargs == {"dry_run": True, "force": True, "active_check_command": "exit 0"}


def test_main_reports_failures_on_stderr_without_a_traceback(root, capsys):
    assert ddns.main(["--config", str(root / "missing.json")]) == 1
    captured = capsys.readouterr()
    assert captured.err.startswith("error: ") and captured.out == "" and "Traceback" not in captured.err


def test_main_defaults(root):
    args = ddns.build_parser().parse_args([])
    assert args.config == ddns.DEFAULT_CONFIG
    assert args.dry_run is False and args.force is False and args.check_active_command is None


def test_the_redacted_url_keeps_only_scheme_host_port_and_path():
    redact = ddns._redacted_url
    assert redact("https://dyn.example.com/update?token=s&ip=1.2.3.4#f") == "https://dyn.example.com/update"
    assert redact("https://u:p@dyn.example.com:8443/a/b") == "https://dyn.example.com:8443/a/b"
    assert redact("https://dyn.example.com:notaport/x?token=s") == "https://dyn.example.com/x"
    assert redact("https://DYN.example.com") == "https://dyn.example.com"


def test_running_the_script_directly_exits_through_main(root, monkeypatch, capsys):
    import runpy
    import sys

    monkeypatch.setattr(sys, "argv", ["prog", "--config", str(root / "missing.json")])
    with pytest.raises(SystemExit) as info:
        runpy.run_path(str(REPO_ROOT / "scripts" / "update_mesh_ddns.py"), run_name="__main__")
    assert info.value.code == 1
    assert "error: " in capsys.readouterr().err


@pytest.mark.parametrize("mode", [0o604, 0o602, 0o640, 0o620, 0o660, 0o606])
def test_any_group_or_other_permission_makes_the_config_untrusted(root, mode):
    path = owner_only(root, "ddns.json", json.dumps(cloudflare()), mode=mode)
    with pytest.raises(Error, match="group or other permissions"):
        ddns.load_config(path)


def test_the_state_file_is_created_owner_only_from_the_start_not_fixed_afterwards(root):
    modes = []
    real = os.open

    def spy(path, flags, mode=0o777, **kwargs):
        modes.append(mode)
        return real(path, flags, mode, **kwargs)

    old = os.umask(0)
    try:
        with mock.patch.object(ddns.os, "open", spy):
            ddns._write_owner_only(root / "fresh-state", b"1.2.3.4\n")
    finally:
        os.umask(old)
    assert modes == [0o600]
    assert stat.S_IMODE((root / "fresh-state").stat().st_mode) == 0o600
