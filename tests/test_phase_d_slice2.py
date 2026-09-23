"""Phase D2 — Assets / Changes / Modules API + SPA smoke."""

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
from sentinel_cli.ui_auth import clear_sessions, setup_auth
from sentinel_cli.ui_server import (
    DEFAULT_UI_BIND,
    assets_payload,
    changes_payload,
    make_handler,
    modules_payload,
    resolve_ui_static_root,
)
from sentinel_core import ENGINE_ALLOWLIST, create_program, open_graph, program_dir
from shadowseye.bridge import (
    emit_dns_name_event,
    emit_domain_event,
    emit_ip_event,
    emit_open_port_event,
    emit_url_event,
)
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
    create_program("d2demo")
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


def _seed_graph(program_id: str = "d2demo") -> None:
    g = open_graph(program_id)
    emit_domain_event(g, program_id=program_id, domain="example.com")
    emit_dns_name_event(g, program_id=program_id, name="admin.example.com")
    emit_dns_name_event(g, program_id=program_id, name="www.example.com")
    emit_ip_event(g, program_id=program_id, ip="1.2.3.4", host="admin.example.com")
    emit_open_port_event(
        g, program_id=program_id, host="admin.example.com", port=443, service="https"
    )
    emit_url_event(
        g,
        program_id=program_id,
        url="https://admin.example.com/login",
        status=200,
        title="Admin",
    )


def test_engine_allowlist_still_empty_d2():
    assert ENGINE_ALLOWLIST == {}


def test_twelve_packs_intact_d2():
    ids = {m.id for m in list_pack_manifests()}
    assert set(PRIOR_PACKS) <= ids
    assert len(ids) == 12


def test_default_bind_unchanged_d2():
    assert DEFAULT_UI_BIND == "127.0.0.1"


def test_assets_payload_empty_graph(home):
    out = assets_payload("d2demo")
    assert out["empty"] is True
    assert out["count"] == 0
    assert out["assets"] == []
    msg = (out.get("message") or "").lower()
    assert "fabricat" in msg or "never" in msg
    assert "eye" in msg or "inventory" in msg or "graph" in msg


def test_assets_payload_sorted_and_filter(home):
    _seed_graph()
    out = assets_payload("d2demo")
    assert out["empty"] is False
    assert out["count"] == 6
    assert out["counts"]["dns"] == 2
    assert out["assets"][0]["name"] == "admin.example.com"
    assert out["assets"][0]["score"] >= out["assets"][-1]["score"]

    filt = assets_payload("d2demo", kind="dns", q="admin")
    assert filt["count"] == 1
    assert filt["assets"][0]["name"] == "admin.example.com"

    ports = assets_payload("d2demo", kind="port")
    assert ports["count"] == 1
    assert ports["assets"][0]["port"] == 443


def test_changes_payload_missing_store(home):
    out = changes_payload("d2demo", window="24h")
    assert out["empty"] is True
    assert out["deltas"] == []
    msg = (out.get("message") or "").lower()
    assert "watch" in msg or "runs" in msg


def test_changes_payload_windowed_ranked(home):
    root = program_dir("d2demo")
    old = snapshot_from_inventory(
        {
            "domains": ["example.com"],
            "dns_names": ["www.example.com"],
            "ports": [],
            "http": [],
            "tech": [],
        }
    )
    old["ts"] = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
    save_snapshot(root, old)

    new = snapshot_from_inventory(
        {
            "domains": ["example.com"],
            "dns_names": ["www.example.com", "admin.example.com"],
            "ports": [{"host": "admin.example.com", "port": 443}],
            "http": ["https://admin.example.com/"],
            "tech": ["nginx"],
        }
    )
    new["ts"] = datetime.now(timezone.utc).isoformat()
    save_snapshot(root, new)

    out = changes_payload("d2demo", window="24h")
    assert out["empty"] is False
    assert out["count"] >= 1
    assert out["baseline_ts"]
    assert out["current_ts"]
    assert out["deltas"][0]["score"] >= out["deltas"][-1]["score"]
    names = {d["name"] for d in out["deltas"]}
    assert "admin.example.com" in names

    latest = changes_payload("d2demo", window="latest")
    assert latest["empty"] is False
    assert latest["count"] >= 1

    week = changes_payload("d2demo", window="7d")
    assert week["empty"] is True
    assert "7d" in (week.get("message") or "")


def test_modules_payload_readonly_twelve():
    out = modules_payload()
    assert out["count"] == 12
    assert out["installable"] is False
    ids = {m["id"] for m in out["modules"]}
    assert set(PRIOR_PACKS) <= ids
    for m in out["modules"]:
        assert m["installable"] is False
        assert m["type"] == "hunt_pack"
        assert m["status"] == "bundled"


def test_api_assets_changes_modules_routes(ui_server_skip):
    base = ui_server_skip
    _seed_graph()

    code, health = _http_json(f"{base}/api/health")
    assert code == 200
    assert health["phase"] in ("D2", "D3", "D4", "E0", "E1", "E2", "E3")

    code, assets = _http_json(f"{base}/api/programs/d2demo/assets")
    assert code == 200, assets
    assert assets["count"] == 6
    assert assets["assets"][0]["score"] >= assets["assets"][-1]["score"]

    code, filt = _http_json(f"{base}/api/programs/d2demo/assets?kind=url")
    assert code == 200
    assert filt["count"] == 1

    code, bad = _http_json(f"{base}/api/programs/d2demo/assets?kind=nope")
    assert code == 400

    code, ch = _http_json(f"{base}/api/programs/d2demo/changes?window=24h")
    assert code == 200
    assert ch["empty"] is True

    root = program_dir("d2demo")
    old = snapshot_from_inventory(
        {
            "domains": ["example.com"],
            "dns_names": ["www.example.com"],
            "ports": [],
            "http": [],
            "tech": [],
        }
    )
    old["ts"] = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
    save_snapshot(root, old)
    new = snapshot_from_inventory(
        {
            "domains": ["example.com"],
            "dns_names": ["www.example.com", "staging.example.com"],
            "ports": [],
            "http": [],
            "tech": [],
        }
    )
    new["ts"] = datetime.now(timezone.utc).isoformat()
    save_snapshot(root, new)

    code, ch2 = _http_json(f"{base}/api/programs/d2demo/changes?window=latest")
    assert code == 200, ch2
    assert ch2["empty"] is False
    assert any("staging" in d["name"] for d in ch2["deltas"])

    code, mods = _http_json(f"{base}/api/modules")
    assert code == 200
    assert mods["count"] == 12
    assert mods["installable"] is False


def test_assets_changes_modules_ro_without_auth(home):
    """RO catalog/list OK without password when need_first_run."""
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
        code, mods = _http_json(f"{base}/api/modules")
        assert code == 200
        assert mods["count"] == 12
        code, assets = _http_json(f"{base}/api/programs/d2demo/assets")
        assert code == 200
        code, ch = _http_json(f"{base}/api/programs/d2demo/changes")
        assert code == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_spa_mentions_d2_screens():
    root = resolve_ui_static_root()
    html = (root / "index.html").read_text(encoding="utf-8")
    assert "Phase D2" in html or "Phase D3" in html or "Phase D4" in html or "E2 labs" in html
    assert "view-assets" in html
    assert "view-changes" in html
    assert "view-modules" in html
    assert 'data-view="assets"' in html
    js = (root / "app.js").read_text(encoding="utf-8")
    assert "loadAssets" in js
    assert "loadChanges" in js
    assert "loadModules" in js
