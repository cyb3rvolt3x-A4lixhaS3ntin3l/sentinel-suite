"""Phase D4 — OSINT/Surface/Auth lab/Workbench RO APIs + Tauri dry-run."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from gungnir.packs import list_pack_manifests
from gungnir.packs.roles import role_session_path
from sentinel_cli.ui_auth import clear_sessions, login, setup_auth
from sentinel_cli.ui_d4 import (
    auth_lab_payload,
    osint_graph_payload,
    surface_payload,
    tauri_status_payload,
    workbench_export,
    workbench_send,
)
from sentinel_cli.ui_server import (
    DEFAULT_UI_BIND,
    make_handler,
    resolve_ui_static_root,
)
from sentinel_core import (
    ENGINE_ALLOWLIST,
    Event,
    create_program,
    open_graph,
    program_dir,
)
from shadowseye.bridge import (
    emit_dns_name_event,
    emit_domain_event,
    emit_identity_event,
    emit_url_event,
)

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

REPO = Path(__file__).resolve().parents[1]


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
    create_program("d4demo")
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


def _seed_osint_surface(program_id: str = "d4demo") -> None:
    g = open_graph(program_id)
    emit_identity_event(
        g, program_id=program_id, kind="org", value="Acme Corp", confidence=0.4
    )
    emit_domain_event(g, program_id=program_id, domain="example.com")
    emit_dns_name_event(g, program_id=program_id, name="api.example.com")
    emit_url_event(
        g,
        program_id=program_id,
        url="https://api.example.com/api/v1/users/{id}",
        status=200,
        title="users",
    )
    emit_url_event(
        g,
        program_id=program_id,
        url="https://api.example.com/openapi.json",
        status=200,
        title="OpenAPI",
    )
    emit_url_event(
        g,
        program_id=program_id,
        url="https://example.com/static/app.js",
        status=200,
        title="bundle",
    )
    # CERT + PERSON typed events (may not be emitted by Eye yet — still schema-valid)
    g.insert(
        Event(
            type="CERT",
            source_module="test",
            program_id=program_id,
            payload={"cn": "example.com", "fingerprint": "ab" * 16},
            confidence=0.5,
        )
    )
    g.insert(
        Event(
            type="PERSON",
            source_module="test",
            program_id=program_id,
            payload={"name": "Ada Example", "email": "ada@example.com"},
            confidence=0.3,
        )
    )
    g.insert(
        Event(
            type="EMAIL",
            source_module="test",
            program_id=program_id,
            payload={"email": "ada@example.com", "value": "ada@example.com"},
            confidence=0.3,
        )
    )
    g.close()


def test_engine_allowlist_still_empty_d4():
    assert ENGINE_ALLOWLIST == {}


def test_twelve_packs_intact_d4():
    ids = {m.id for m in list_pack_manifests()}
    assert set(PRIOR_PACKS) <= ids
    assert len(ids) == 12


def test_default_bind_unchanged_d4():
    assert DEFAULT_UI_BIND == "127.0.0.1"


def test_osint_graph_empty_honest(home):
    out = osint_graph_payload("d4demo")
    assert out["empty"] is True
    assert out["nodes"] == []
    assert "never fabricates" in (out.get("message") or "").lower() or "no osint" in (
        out.get("message") or ""
    ).lower()


def test_osint_graph_filterable(home):
    _seed_osint_surface()
    out = osint_graph_payload("d4demo")
    assert out["empty"] is False
    assert out["counts"]["domain"] >= 1
    assert out["counts"]["cert"] >= 1
    assert out["counts"]["person"] >= 1
    assert out["counts"]["org"] >= 1
    assert len(out["layout"]) == len(out["nodes"])

    only_cert = osint_graph_payload("d4demo", kinds="cert")
    assert only_cert["counts"]["cert"] >= 1
    assert only_cert["counts"]["domain"] == 0

    q = osint_graph_payload("d4demo", q="acme")
    assert q["counts"]["org"] >= 1


def test_surface_catalog_from_urls(home):
    _seed_osint_surface()
    out = surface_payload("d4demo")
    assert out["empty"] is False
    assert out["counts"]["endpoint"] >= 1
    assert out["counts"]["openapi"] >= 1
    assert out["counts"]["js"] >= 1
    assert out["counts"]["param"] >= 1  # {id} path param and/or query

    js_only = surface_payload("d4demo", kind="js")
    assert all(i["kind"] == "js" for i in js_only["items"])
    assert js_only["count"] >= 1


def test_surface_empty_honest(home):
    out = surface_payload("d4demo")
    assert out["empty"] is True
    assert out["items"] == []


def test_auth_lab_empty_and_vault(home):
    empty = auth_lab_payload("d4demo")
    assert empty["empty"] is True
    assert empty["roles"]["a"]["exists"] is False

    path = role_session_path("d4demo", "a")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cookies": {"session": "secret-session-value"},
                "headers": {"X-Role": "a"},
                "bearer": "tok_abcdef123456",
            }
        ),
        encoding="utf-8",
    )
    lab = auth_lab_payload("d4demo")
    assert lab["empty"] is False
    assert lab["roles"]["a"]["usable"] is True
    assert "session" in lab["roles"]["a"]["cookie_keys"]
    stub = lab["roles"]["a"]["replay_stub"]
    assert stub["live"] is False
    assert "Authorization" in stub["headers_redacted"] or "authorization" in {
        k.lower() for k in stub["headers_redacted"]
    }
    # Must not leak full bearer in redacted display
    assert "tok_abcdef123456" not in json.dumps(stub["headers_redacted"])


def test_workbench_export_formats(home):
    out = workbench_export(
        {
            "method": "POST",
            "url": "https://api.example.com/v1/x",
            "headers": {"Content-Type": "application/json"},
            "body": {"a": 1},
            "format": "all",
        }
    )
    assert out["live"] is False
    assert "curl -i -X POST" in out["curl"]
    assert "burpVersion" in out["burp_xml"]
    assert out["caido_json"]["request"]["url"] == "https://api.example.com/v1/x"


def test_workbench_send_requires_ownership(home):
    with pytest.raises(ValueError, match="i_own_this"):
        workbench_send(
            {
                "program_id": "d4demo",
                "url": "https://example.com/",
                "method": "GET",
                "i_own_this": False,
            }
        )


def test_workbench_send_requires_scope(home):
    # create_program may leave empty scope.txt (no allow lines) → hard-kill / missing
    root = program_dir("d4demo")
    scope_path = root / "scope.txt"
    if scope_path.is_file() and not scope_path.read_text(encoding="utf-8").strip():
        # empty allow list → scope denied on any host
        with pytest.raises(ValueError, match="scope"):
            workbench_send(
                {
                    "program_id": "d4demo",
                    "url": "https://example.com/",
                    "method": "GET",
                    "i_own_this": True,
                }
            )
    else:
        if scope_path.is_file():
            scope_path.unlink()
        with pytest.raises(ValueError, match="scope"):
            workbench_send(
                {
                    "program_id": "d4demo",
                    "url": "https://example.com/",
                    "method": "GET",
                    "i_own_this": True,
                }
            )


def test_workbench_send_scope_hard_kill(home):
    root = program_dir("d4demo")
    (root / "scope.txt").write_text("in-scope.example\n", encoding="utf-8")
    with pytest.raises(ValueError, match="scope denied"):
        workbench_send(
            {
                "program_id": "d4demo",
                "url": "https://evil.example/",
                "method": "GET",
                "i_own_this": True,
            }
        )


def test_tauri_dry_run_script():
    script = REPO / "scripts" / "tauri_dry_run.py"
    assert script.is_file()
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads(proc.stdout)
    assert report["ok"] is True
    assert report["electron"] is False
    assert report["dev_url"] == "http://127.0.0.1:8888"
    assert report["scaffold"]["tauri_conf"] is True


def test_tauri_status_payload():
    out = tauri_status_payload()
    assert out["phase"] == "D4"
    assert out["electron"] is False
    assert out["browser_first"] is True
    assert out["tauri_scaffold"]["tauri_conf"] is True


def test_api_d4_routes(ui_server_skip):
    base = ui_server_skip
    _seed_osint_surface()

    code, health = _http_json(f"{base}/api/health")
    assert code == 200
    assert health["phase"] == "D4"

    code, og = _http_json(f"{base}/api/programs/d4demo/osint-graph")
    assert code == 200, og
    assert og["counts"]["domain"] >= 1

    code, surf = _http_json(f"{base}/api/programs/d4demo/surface?kind=openapi")
    assert code == 200, surf
    assert surf["count"] >= 1

    code, lab = _http_json(f"{base}/api/programs/d4demo/auth-lab")
    assert code == 200
    assert lab["empty"] is True

    code, exported = _http_json(
        f"{base}/api/workbench/export",
        {"url": "https://example.com/", "method": "GET", "format": "curl"},
    )
    assert code == 200
    assert exported["live"] is False
    assert "curl" in exported

    code, tauri = _http_json(f"{base}/api/tauri/status")
    assert code == 200
    assert tauri["electron"] is False

    # Live send without ownership → 400
    code, blocked = _http_json(
        f"{base}/api/workbench/send",
        {
            "program_id": "d4demo",
            "url": "https://example.com/",
            "method": "GET",
            "i_own_this": False,
        },
    )
    assert code == 400
    assert "i_own_this" in (blocked.get("error") or "").lower()


def test_workbench_send_gated_when_password(home):
    setup_auth(action="set_password", password="testpass1")
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

        # RO export open
        code, _ = _http_json(
            f"{base}/api/workbench/export",
            {"url": "https://example.com/", "format": "curl"},
        )
        assert code == 200

        # send without session → 401
        code, blocked = _http_json(
            f"{base}/api/workbench/send",
            {
                "program_id": "d4demo",
                "url": "https://example.com/",
                "i_own_this": True,
            },
        )
        assert code == 401
        assert blocked.get("code") == "auth_required"

        tok = login("testpass1")["token"]
        # with session but no scope → 400
        code, noscope = _http_json(
            f"{base}/api/workbench/send",
            {
                "program_id": "d4demo",
                "url": "https://example.com/",
                "i_own_this": True,
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert code == 400
        assert "scope" in (noscope.get("error") or "").lower()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_spa_mentions_d4_screens():
    root = resolve_ui_static_root()
    html = (root / "index.html").read_text(encoding="utf-8")
    assert "Phase D4" in html
    for view in ("osint", "surface", "authlab", "workbench"):
        assert f'id="view-{view}"' in html
        assert f'data-view="{view}"' in html
    assert "cmd-palette" in html
    # D3 screens remain
    assert "view-coach" in html
    assert "view-settings" in html
    js = (root / "app.js").read_text(encoding="utf-8")
    assert "loadOsint" in js
    assert "loadSurface" in js
    assert "loadAuthLab" in js
    assert "loadWorkbench" in js
    assert "Ctrl+K" in js or "ctrlKey" in js

    # No Electron in tauri main
    main = (REPO / "src-tauri" / "src" / "main.rs").read_text(encoding="utf-8")
    assert "tauri::Builder" in main
    conf = json.loads((REPO / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
    assert conf["build"]["devUrl"] == "http://127.0.0.1:8888"

    # Packaging CI not pushed
    workflows = REPO / ".github" / "workflows"
    if workflows.is_dir():
        assert not list(workflows.glob("*.yml")) and not list(workflows.glob("*.yaml"))
    assert (REPO / "docs" / "ci-pending" / "tauri.yml").is_file()


def test_no_new_workflows_pushed():
    workflows = REPO / ".github" / "workflows"
    if workflows.is_dir():
        assert list(workflows.iterdir()) == [] or (
            not any(workflows.glob("*.yml")) and not any(workflows.glob("*.yaml"))
        )
