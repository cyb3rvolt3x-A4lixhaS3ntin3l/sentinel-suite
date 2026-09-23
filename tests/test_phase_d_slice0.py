"""Phase D0 — local UI shell (127.0.0.1:8888), bind gate + API smoke."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from gungnir.packs import list_pack_manifests, run_pack
from sentinel_cli.ui_server import (
    COACH_UI_BIND_NON_LOOPBACK,
    DEFAULT_UI_BIND,
    DEFAULT_UI_PORT,
    UIBindError,
    assert_ui_bind_allowed,
    doctor_status,
    is_loopback_bind,
    make_handler,
    packs_payload,
    programs_payload,
    resolve_ui_static_root,
)
from sentinel_core import ENGINE_ALLOWLIST, create_program, list_programs

PRIOR_PACKS = (
    "ato_oauth_oidc",
    "bola_idor_bfla",
    "business_logic",
    "race_toctou",
    "graphql",
    "xss_dom",
    "csrf_state",
    "open_redirect",
    "cache_host",
    "jwt_session",
    "http_desync",
    "ssrf_collaborator",
)


def _cli(*args: str, env: dict | None = None) -> subprocess.CompletedProcess[str]:
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run(
        [sys.executable, "-m", "sentinel_cli.cli", *args],
        capture_output=True,
        text=True,
        env=e,
    )


def test_engine_allowlist_still_empty_d0():
    assert ENGINE_ALLOWLIST == {}


def test_phase_c_twelve_packs_intact():
    ids = {m.id for m in list_pack_manifests()}
    assert set(PRIOR_PACKS) <= ids
    assert len(ids) == 12


def test_default_ui_bind_is_loopback():
    assert DEFAULT_UI_BIND == "127.0.0.1"
    assert DEFAULT_UI_PORT == 8888
    assert is_loopback_bind(DEFAULT_UI_BIND)
    assert assert_ui_bind_allowed(None, i_understand_lab=False) == "127.0.0.1"
    assert assert_ui_bind_allowed("127.0.0.1", i_understand_lab=False) == "127.0.0.1"
    assert assert_ui_bind_allowed("localhost", i_understand_lab=False) == "localhost"


def test_assert_ui_bind_refuses_wildcard_without_lab():
    with pytest.raises(UIBindError) as ei:
        assert_ui_bind_allowed("0.0.0.0", i_understand_lab=False)
    msg = str(ei.value)
    assert "0.0.0.0" in msg or "loopback" in msg.lower() or "non-loopback" in msg.lower()
    assert "lab" in msg.lower()


def test_assert_ui_bind_refuses_ipv6_wildcard_without_lab():
    with pytest.raises(UIBindError):
        assert_ui_bind_allowed("::", i_understand_lab=False)


def test_assert_ui_bind_wildcard_ok_with_lab_flag():
    assert assert_ui_bind_allowed("0.0.0.0", i_understand_lab=True) == "0.0.0.0"


def test_coach_message_mentions_default():
    assert "127.0.0.1" in COACH_UI_BIND_NON_LOOPBACK
    assert "8888" in COACH_UI_BIND_NON_LOOPBACK or "lab" in COACH_UI_BIND_NON_LOOPBACK.lower()


def test_ui_static_root_has_index():
    root = resolve_ui_static_root()
    assert (root / "index.html").is_file()
    assert (root / "app.js").is_file()


def test_doctor_status_structured():
    d = doctor_status()
    assert "ok" in d and "status" in d and "lines" in d
    assert d["status"] in ("PASS", "FAIL")
    assert any("SENTINEL_HOME" in line for line in d["lines"])


def test_list_programs_and_payloads(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    assert list_programs() == []
    create_program("d0demo")
    rows = list_programs()
    assert len(rows) == 1
    assert rows[0]["id"] == "d0demo"
    assert programs_payload()["count"] == 1
    packs = packs_payload()
    assert packs["count"] == 12


def test_cli_ui_help_and_alias():
    r = _cli("ui", "--help")
    assert r.returncode == 0
    assert "127.0.0.1" in r.stdout
    assert "8888" in r.stdout or "port" in r.stdout.lower()
    r2 = _cli("serve-ui", "--help")
    assert r2.returncode == 0


def test_cli_refuse_non_loopback_bind_without_lab():
    r = _cli("ui", "--bind", "0.0.0.0", "--port", "19999")
    assert r.returncode != 0
    err = (r.stderr + r.stdout).lower()
    assert "lab" in err or "loopback" in err or "0.0.0.0" in err


def _http_json(url: str, data: dict | None = None, method: str = "GET") -> tuple[int, dict]:
    body = None
    headers = {"Accept": "application/json"}
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = method if method != "GET" else "POST"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"raw": raw}
        return int(exc.code), payload


@pytest.fixture
def ui_server(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    create_program("uidemo")
    # D1 auth: lab skip so D0 pack-run smoke still mutates without password
    from sentinel_cli.ui_auth import clear_sessions, setup_auth

    clear_sessions()
    setup_auth(action="skip_lab")
    root = resolve_ui_static_root()
    handler = make_handler(root)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    # wait until accepting
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            code, _ = _http_json(f"http://127.0.0.1:{port}/api/health")
            if code == 200:
                break
        except Exception:  # noqa: BLE001
            time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def test_api_smoke_doctor_programs_packs(ui_server):
    base = ui_server
    code, health = _http_json(f"{base}/api/health")
    assert code == 200 and health.get("ok") is True
    assert health.get("default_bind") == "127.0.0.1"

    code, doctor = _http_json(f"{base}/api/doctor")
    assert code == 200
    assert "status" in doctor and "lines" in doctor

    code, programs = _http_json(f"{base}/api/programs")
    assert code == 200
    assert programs["count"] >= 1
    ids = {p["id"] for p in programs["programs"]}
    assert "uidemo" in ids

    code, packs = _http_json(f"{base}/api/packs")
    assert code == 200
    assert packs["count"] == 12

    code, findings = _http_json(f"{base}/api/programs/uidemo/findings?status=all")
    assert code == 200
    assert findings["program_id"] == "uidemo"
    assert "findings" in findings


def test_api_index_html(ui_server):
    req = urllib.request.Request(f"{ui_server}/", headers={"Accept": "text/html"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        html = resp.read().decode("utf-8")
    assert "Sentinel Suite" in html
    assert "Doctor" in html or "doctor" in html.lower()


def test_api_pack_run_requires_i_own_this(ui_server):
    code, data = _http_json(
        f"{ui_server}/api/pack/run",
        {
            "program_id": "uidemo",
            "pack_id": "open_redirect",
            "i_own_this": False,
        },
    )
    assert code == 400
    assert data.get("ok") is False
    assert "i_own_this" in (data.get("error") or "").lower() or "ownership" in (
        data.get("error") or ""
    ).lower()


def test_api_pack_run_with_i_own_this_fixture(ui_server, tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    # server fixture already set SENTINEL_HOME; ensure program exists there
    code, data = _http_json(
        f"{ui_server}/api/pack/run",
        {
            "program_id": "uidemo",
            "pack_id": "open_redirect",
            "i_own_this": True,
        },
    )
    assert code == 200, data
    assert data.get("ok") is True
    result = data.get("result") or {}
    # findings must not be auto-verified
    for f in result.get("findings") or []:
        ver = (f.get("verification") or f.get("verification_status") or "").lower()
        assert ver not in ("verified", "confirmed")


def test_bind_gate_enforced_before_listen():
    """serve_ui must not open a non-loopback socket without lab flag."""
    from sentinel_cli.ui_server import serve_ui

    with pytest.raises(UIBindError):
        serve_ui(bind="0.0.0.0", port=19998, i_understand_lab=False)
