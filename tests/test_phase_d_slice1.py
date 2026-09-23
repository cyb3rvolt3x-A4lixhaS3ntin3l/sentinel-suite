"""Phase D1 — Hunt/Scope/Reports polish, bcrypt gate, scope dry-run, confirm UX APIs."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from gungnir.packs import list_pack_manifests, run_pack
from sentinel_cli.ui_auth import (
    MODE_PASSWORD,
    MODE_SKIP_LAB,
    auth_status,
    clear_sessions,
    setup_auth,
)
from sentinel_cli.ui_server import (
    DEFAULT_UI_BIND,
    make_handler,
    resolve_ui_static_root,
    scope_brief_import_action,
    scope_write_action,
)
from sentinel_core import ENGINE_ALLOWLIST, create_program


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


def _http_json(
    url: str,
    data: dict | None = None,
    method: str = "GET",
    headers: dict | None = None,
) -> tuple[int, dict]:
    body = None
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
        method = method if method != "GET" else "POST"
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = {"raw": raw}
            return resp.status, payload
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"raw": raw}
        return int(exc.code), payload


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    clear_sessions()
    create_program("d1demo")
    return tmp_path


@pytest.fixture
def ui_server_raw(home):
    """UI server without auth configured (need_first_run)."""
    root = resolve_ui_static_root()
    handler = make_handler(root)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
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


@pytest.fixture
def ui_server_skip(home):
    setup_auth(action="skip_lab")
    root = resolve_ui_static_root()
    handler = make_handler(root)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
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


def test_engine_allowlist_still_empty_d1():
    assert ENGINE_ALLOWLIST == {}


def test_twelve_packs_intact_d1():
    ids = {m.id for m in list_pack_manifests()}
    assert set(PRIOR_PACKS) <= ids
    assert len(ids) == 12


def test_default_bind_unchanged():
    assert DEFAULT_UI_BIND == "127.0.0.1"


def test_auth_status_need_first_run(home):
    st = auth_status()
    assert st["need_first_run"] is True
    assert st["configured"] is False


def test_auth_skip_lab(home):
    r = setup_auth(action="skip_lab")
    assert r["mode"] == MODE_SKIP_LAB
    st = auth_status()
    assert st["mode"] == MODE_SKIP_LAB
    assert st["mutating_requires_auth"] is False
    assert (home / "ui_auth.json").is_file()


def test_auth_set_password_and_login(home):
    setup_auth(action="set_password", password="lab-pass-99")
    st = auth_status()
    assert st["mode"] == MODE_PASSWORD
    assert st["mutating_requires_auth"] is True
    from sentinel_cli.ui_auth import UIAuthError, login

    tok = login("lab-pass-99")
    assert tok.get("token")
    with pytest.raises(UIAuthError):
        login("wrong-password")


def test_api_mutating_blocked_until_first_run(ui_server_raw):
    base = ui_server_raw
    code, data = _http_json(
        f"{base}/api/pack/run",
        {"program_id": "d1demo", "pack_id": "open_redirect", "i_own_this": True},
    )
    assert code == 401
    assert data.get("code") == "need_first_run"

    code, data = _http_json(
        f"{base}/api/auth/setup",
        {"action": "skip_lab"},
    )
    assert code == 200
    assert data.get("mode") == MODE_SKIP_LAB

    code, data = _http_json(
        f"{base}/api/pack/run",
        {"program_id": "d1demo", "pack_id": "open_redirect", "i_own_this": True},
    )
    assert code == 200, data
    assert data.get("ok") is True


def test_api_password_gate_on_confirm_and_scope(ui_server_raw, home):
    base = ui_server_raw
    code, setup = _http_json(
        f"{base}/api/auth/setup",
        {"action": "set_password", "password": "correct-horse"},
    )
    assert code == 200
    assert setup.get("mode") == MODE_PASSWORD

    # mutating without token
    code, data = _http_json(
        f"{base}/api/programs/d1demo/scope",
        {"text": "example.com\n", "dry_run": True},
        method="PUT",
    )
    assert code == 401
    assert data.get("code") == "auth_required"

    code, login = _http_json(
        f"{base}/api/auth/login",
        {"password": "correct-horse"},
    )
    assert code == 200
    token = login["token"]
    hdrs = {"Authorization": f"Bearer {token}"}

    code, data = _http_json(
        f"{base}/api/programs/d1demo/scope",
        {"text": "example.com\n!oos.example.com\n", "dry_run": True},
        method="PUT",
        headers=hdrs,
    )
    assert code == 200, data
    result = data["result"]
    assert result["dry_run"] is True
    assert result["allow_count"] == 1
    assert result["deny_count"] == 1
    assert result["written"] is False


def test_scope_write_and_dry_run_helpers(home):
    dry = scope_write_action(
        "d1demo",
        {"text": "a.example.com\nb.example.com\n!x.example.com\n", "dry_run": True},
    )
    assert dry["dry_run"] is True
    assert dry["allow_count"] == 2
    assert dry["deny_count"] == 1
    assert dry["written"] is False
    # file unchanged aside from create_program stub
    text = (home / "programs" / "d1demo" / "scope.txt").read_text(encoding="utf-8")
    assert "a.example.com" not in text

    written = scope_write_action(
        "d1demo",
        {"text": "a.example.com\n", "dry_run": False},
    )
    assert written["written"] is True
    assert "a.example.com" in (
        home / "programs" / "d1demo" / "scope.txt"
    ).read_text(encoding="utf-8")


def test_scope_brief_dry_run(home):
    brief = "# In Scope\n- *.example.com\n\n# Out of Scope\n- oos.example.com\n"
    summary = scope_brief_import_action(
        "d1demo",
        {"brief": brief, "platform": "h1", "dry_run": True},
    )
    assert summary["dry_run"] is True
    assert summary["written"] is False
    assert summary["allow_count"] >= 1


def test_api_scope_get_hardkill_report(ui_server_skip, home):
    base = ui_server_skip
    # write scope
    code, data = _http_json(
        f"{base}/api/programs/d1demo/scope",
        {"text": "in.example.com\n!out.example.com\n", "dry_run": False},
        method="PUT",
    )
    assert code == 200 and data["result"]["written"] is True

    code, scope = _http_json(f"{base}/api/programs/d1demo/scope")
    assert code == 200
    assert scope["allow_count"] == 1
    assert scope["hard_kill"] is True

    code, hk = _http_json(
        f"{base}/api/programs/d1demo/scope/hard-kill",
        {"target": "out.example.com"},
    )
    assert code == 200
    assert hk["result"]["hard_kill"] is True
    assert hk["result"]["allowed"] is False

    code, hk2 = _http_json(
        f"{base}/api/programs/d1demo/scope/hard-kill",
        {"target": "in.example.com"},
    )
    assert code == 200
    assert hk2["result"]["allowed"] is True

    code, report = _http_json(
        f"{base}/api/programs/d1demo/report?all_packs=1"
    )
    assert code == 200
    assert "markdown" in report
    assert report["program_id"] == "d1demo"


def test_api_confirm_finding_human_gate(ui_server_skip, home):
    base = ui_server_skip
    # emit a finding via pack (fixtures)
    result = run_pack("open_redirect", "d1demo", i_own_this=True)
    events = result.get("events") or []
    if not events:
        pytest.skip("open_redirect emitted no findings in this environment")
    fid = events[0]["id"]

    # missing note refused
    code, data = _http_json(
        f"{base}/api/confirm-finding",
        {
            "program_id": "d1demo",
            "finding_id": fid,
            "status": "confirmed",
            "note": "",
        },
    )
    assert code == 400

    code, data = _http_json(
        f"{base}/api/confirm-finding",
        {
            "program_id": "d1demo",
            "finding_id": fid,
            "status": "confirmed",
            "note": "reproduced in lab browser",
        },
    )
    assert code == 200, data
    assert data["result"]["verification"] == "confirmed"
    assert data["result"]["verified"] is True

    # list findings
    code, findings = _http_json(
        f"{base}/api/programs/d1demo/findings?status=confirmed"
    )
    assert code == 200
    ids = {f["id"] for f in findings["findings"]}
    assert fid in ids


def test_api_pack_run_log_lines_and_async_stop(ui_server_skip):
    base = ui_server_skip
    code, data = _http_json(
        f"{base}/api/pack/run",
        {
            "program_id": "d1demo",
            "pack_id": "open_redirect",
            "i_own_this": True,
        },
    )
    assert code == 200, data
    result = data["result"]
    assert "log_lines" in result
    assert any("pack" in (L.get("msg") or "").lower() for L in result["log_lines"])
    for f in result.get("events") or []:
        ver = (f.get("verification") or "").lower()
        assert ver not in ("verified", "confirmed")

    code, job = _http_json(
        f"{base}/api/pack/run",
        {
            "program_id": "d1demo",
            "pack_id": "open_redirect",
            "i_own_this": True,
            "async": True,
        },
    )
    assert code == 200, job
    run_id = job["run_id"]
    # poll until done
    deadline = time.time() + 15
    final = None
    while time.time() < deadline:
        code, final = _http_json(f"{base}/api/pack/run/{run_id}")
        assert code == 200
        if final["status"] in ("done", "error", "stopped"):
            break
        time.sleep(0.1)
    assert final is not None
    assert final["status"] in ("done", "error", "stopped")
    assert isinstance(final.get("log_lines"), list)

    code, stop = _http_json(f"{base}/api/pack/stop", {"run_id": run_id})
    assert code == 200
    assert "ok" in stop


def test_spa_mentions_d1_screens():
    root = resolve_ui_static_root()
    html = (root / "index.html").read_text(encoding="utf-8")
    # D2 supersedes banner text; D1 screens must remain.
    assert "Phase D1" in html or "Phase D2" in html or "Phase D3" in html
    assert "view-scope" in html
    assert "view-reports" in html
    assert "confirm-form" in html
    assert "run-stop" in html
