"""Phase D3 — Coach hints + Settings read / auth clear."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer

import pytest

from gungnir.packs import list_pack_manifests
from sentinel_cli.ui_auth import (
    auth_file_path,
    auth_status,
    clear_sessions,
    login,
    setup_auth,
)
from sentinel_cli.ui_coach import (
    MAP_BUDGET_HOURS,
    coach_payload,
    collect_program_stats,
    generate_coach_hints,
)
from sentinel_cli.ui_server import (
    DEFAULT_UI_BIND,
    make_handler,
    resolve_ui_static_root,
    settings_payload,
)
from sentinel_core import ENGINE_ALLOWLIST, create_program, open_graph, program_dir
from shadowseye.bridge import emit_dns_name_event, emit_domain_event, emit_url_event
from shadowseye.watch import save_snapshot, snapshot_from_inventory

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
    create_program("d3demo")
    return tmp_path


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


def _seed_api_auth_urls(program_id: str = "d3demo") -> None:
    g = open_graph(program_id)
    emit_domain_event(g, program_id=program_id, domain="example.com")
    emit_dns_name_event(g, program_id=program_id, name="api.example.com")
    emit_url_event(
        g,
        program_id=program_id,
        url="https://api.example.com/api/v1/users/123",
        status=200,
        title="users",
    )
    emit_url_event(
        g,
        program_id=program_id,
        url="https://api.example.com/api/v1/orders",
        status=200,
        title="orders",
    )
    emit_url_event(
        g,
        program_id=program_id,
        url="https://example.com/login",
        status=200,
        title="Login",
    )
    emit_url_event(
        g,
        program_id=program_id,
        url="https://example.com/oauth/authorize?client_id=x&redirect_uri=https://x",
        status=200,
        title="OAuth",
    )


def test_engine_allowlist_still_empty_d3():
    assert ENGINE_ALLOWLIST == {}


def test_twelve_packs_intact_d3():
    ids = {m.id for m in list_pack_manifests()}
    assert set(PRIOR_PACKS) <= ids
    assert len(ids) == 12


def test_default_bind_unchanged_d3():
    assert DEFAULT_UI_BIND == "127.0.0.1"


def test_coach_hints_stage_and_bola_rule(home):
    _seed_api_auth_urls()
    stats = collect_program_stats("d3demo")
    assert stats["interesting_api"] >= 2
    assert stats["auth_surface"] >= 2
    assert stats["findings_total"] == 0

    hints = generate_coach_hints("d3demo", stats=stats)
    kinds = {h["kind"] for h in hints}
    ids = {h["id"] for h in hints}
    assert "stage_checklist" in kinds
    assert "fp_school" in kinds
    assert "report_school" in kinds
    assert "rule-bola-over-xss" in ids

    bola = next(h for h in hints if h["id"] == "rule-bola-over-xss")
    body_l = bola["body"].lower()
    assert "bola" in body_l
    assert "not a claim" in body_l or "methodology" in body_l
    # Must not invent that BOLA exists
    assert "you have bola" not in body_l
    assert bola["evidence_counts"]["bola_idor_bfla_findings"] == 0

    payload = coach_payload("d3demo")
    assert payload["llm"] is False
    assert payload["count"] == len(payload["hints"])
    assert "never invents" in (payload.get("disclaimer") or "").lower()


def test_coach_time_budget_when_eye_old(home):
    _seed_api_auth_urls()
    root = program_dir("d3demo")
    snap = snapshot_from_inventory(
        {
            "domains": ["example.com"],
            "dns_names": ["api.example.com"],
            "ports": [],
            "http": ["https://api.example.com/api/v1/users"],
            "tech": [],
        }
    )
    snap["ts"] = (
        datetime.now(timezone.utc) - timedelta(hours=MAP_BUDGET_HOURS + 1)
    ).isoformat()
    save_snapshot(root, snap)

    stats = collect_program_stats("d3demo")
    assert stats["eye_last_run_age_hours"] is not None
    assert stats["eye_last_run_age_hours"] >= MAP_BUDGET_HOURS

    hints = generate_coach_hints("d3demo", stats=stats)
    tb = [h for h in hints if h["kind"] == "time_budget"]
    assert tb, "expected time_budget hint when Eye snapshot is old and map-heavy"
    assert "time-budget" in tb[0]["id"]


def test_coach_never_claims_absent_vuln(home):
    """Empty graph → checklist/FP/report only; no fabricated pack vuln claims."""
    hints = generate_coach_hints("d3demo")
    blob = " ".join(h["body"].lower() for h in hints)
    assert "vulnerability exists" not in blob
    assert "cvss" not in blob or "never invent cvss" in blob or "do not assign cvss" in blob
    for h in hints:
        assert "id" in h and "kind" in h and "title" in h and "body" in h


def test_settings_payload_read(home):
    setup_auth(action="skip_lab")
    out = settings_payload()
    assert out["SENTINEL_HOME"] == str(home)
    assert out["bind"]["host"] == "127.0.0.1"
    assert out["bind"]["port"] == 8888
    assert out["engines"]["allowlist"] == {}
    assert out["theme"]["stub"] is True
    assert out["rates_present"] is False
    assert out["rates"] is None
    assert out["phase"] in ("D3", "D4", "E0", "E1", "E2")
    assert out["auth"]["mode"] == "skip_lab"


def test_settings_rates_when_present(home):
    rates_path = home / "rates.json"
    rates_path.write_text(
        json.dumps({"default_rps": 5, "burst": 10}), encoding="utf-8"
    )
    out = settings_payload()
    assert out["rates_present"] is True
    assert out["rates"]["default_rps"] == 5


def test_auth_clear_password_mode(home):
    setup_auth(action="set_password", password="testpass1")
    assert auth_file_path().is_file()
    tok = login("testpass1")["token"]

    root = resolve_ui_static_root()
    handler = make_handler(root)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                code, _ = _http_json(f"{base}/api/health")
                if code == 200:
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.05)

        # RO settings open
        code, settings = _http_json(f"{base}/api/settings")
        assert code == 200
        assert settings["auth"]["mode"] == "password"

        # clear without auth → 401
        code, blocked = _http_json(
            f"{base}/api/auth/clear",
            {"confirm": True},
            method="POST",
        )
        assert code == 401
        assert blocked.get("code") == "auth_required"

        # clear with session
        code, cleared = _http_json(
            f"{base}/api/auth/clear",
            {"confirm": True},
            method="POST",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert code == 200, cleared
        assert cleared["ok"] is True
        assert cleared["cleared"] is True
        assert not auth_file_path().is_file()
        st = auth_status()
        assert st["need_first_run"] is True
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_api_coach_and_settings_routes(ui_server_skip):
    base = ui_server_skip
    _seed_api_auth_urls()

    code, health = _http_json(f"{base}/api/health")
    assert code == 200
    assert health["phase"] in ("D3", "D4", "E0", "E1", "E2")

    code, coach = _http_json(f"{base}/api/programs/d3demo/coach")
    assert code == 200, coach
    assert coach["llm"] is False
    assert coach["count"] >= 3
    assert any(h["kind"] == "stage_checklist" for h in coach["hints"])
    assert any(h["id"] == "rule-bola-over-xss" for h in coach["hints"])

    code, settings = _http_json(f"{base}/api/settings")
    assert code == 200
    assert settings["engines"]["allowlist"] == {}
    assert settings["bind"]["display"].startswith("127.0.0.1:")

    # clear under skip_lab (open mutating)
    code, cleared = _http_json(
        f"{base}/api/auth/clear",
        {"confirm": True},
        method="POST",
    )
    assert code == 200, cleared
    assert cleared["ok"] is True


def test_coach_settings_ro_without_auth(home):
    root = resolve_ui_static_root()
    handler = make_handler(root)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                code, _ = _http_json(f"{base}/api/health")
                if code == 200:
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.05)
        code, coach = _http_json(f"{base}/api/programs/d3demo/coach")
        assert code == 200
        code, settings = _http_json(f"{base}/api/settings")
        assert code == 200
        assert settings["phase"] in ("D3", "D4", "E0", "E1", "E2")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_spa_mentions_d3_screens():
    root = resolve_ui_static_root()
    html = (root / "index.html").read_text(encoding="utf-8")
    assert "Phase D3" in html or "Phase D4" in html or "E2 labs" in html
    assert "view-coach" in html
    assert "view-settings" in html
    assert 'data-view="coach"' in html
    assert 'data-view="settings"' in html
    # D2 screens remain
    assert "view-assets" in html
    assert "view-changes" in html
    assert "view-modules" in html
    js = (root / "app.js").read_text(encoding="utf-8")
    assert "loadCoach" in js
    assert "loadSettings" in js
    assert "sentinel_ui_theme" in js
