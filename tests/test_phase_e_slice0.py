"""Phase E0 — Open Lab scaffold + Juice Shop curriculum + hints after attempt."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from gungnir.packs import list_pack_manifests
from sentinel_cli.ui_auth import clear_sessions, setup_auth
from sentinel_cli.ui_coach import coach_payload
from sentinel_cli.ui_labs import (
    JUICE_SHOP_DEFAULT_BASE,
    get_lab_def,
    hints_for_objective,
    lab_catalog,
    lab_status_payload,
    labs_payload,
    load_lab_binding,
    mark_objective_complete,
    open_lab,
    record_attempt,
)
from sentinel_cli.ui_server import (
    DEFAULT_UI_BIND,
    make_handler,
    resolve_ui_static_root,
)
from sentinel_core import ENGINE_ALLOWLIST, create_program, open_graph, program_dir

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
    return tmp_path


@pytest.fixture
def ui_server_skip(home):
    setup_auth(action="skip_lab")
    root = resolve_ui_static_root()
    handler = make_handler(root)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_allowlist_still_empty_and_twelve_packs():
    assert ENGINE_ALLOWLIST == {}
    ids = {m.id for m in list_pack_manifests()}
    for p in PRIOR_PACKS:
        assert p in ids
    assert len(ids) == 12


def test_lab_catalog_juice_shop():
    labs = lab_catalog()
    ids = {L["lab_id"] for L in labs}
    assert "juice-shop" in ids
    lab = next(L for L in labs if L["lab_id"] == "juice-shop")
    assert lab["default_base_url"] == JUICE_SHOP_DEFAULT_BASE
    assert "127.0.0.1" in lab["default_hosts"]
    objs = lab["objectives"]
    assert len(objs) >= 5
    assert all("hints" in o and len(o["hints"]) >= 1 for o in objs)
    assert "docker" in lab["start_docs"].lower()
    payload = labs_payload()
    assert payload["count"] >= 1
    assert "juice-shop" in {L["lab_id"] for L in payload["labs"]}
    assert payload["phase"] in ("E0", "E1", "E2")


def test_open_lab_writes_binding_scope_no_findings(home):
    status = open_lab("juice-shop", program_id="lab-js")
    assert status["program_id"] == "lab-js"
    assert status["lab_id"] == "juice-shop"
    assert status["invent_findings"] is False
    assert status["auto_verified"] is False
    root = program_dir("lab-js")
    assert (root / "lab.json").is_file()
    assert (root / "lab_progress.json").is_file()
    assert (root / "LAB_START.md").is_file()
    scope = (root / "scope.txt").read_text(encoding="utf-8")
    assert "127.0.0.1" in scope
    assert "localhost" in scope
    binding = load_lab_binding("lab-js")
    assert binding is not None
    assert binding["lab_id"] == "juice-shop"
    # Never invent FINDING events on open
    with open_graph("lab-js") as g:
        findings = list(g.list_by_type("FINDING"))
    assert findings == []
    assert status["counts"]["attempted"] == 0
    assert status["counts"]["hints_unlocked"] == 0


def test_hints_locked_until_attempt(home):
    open_lab("juice-shop", program_id="lab-js")
    oid = "js-admin-section"
    locked = hints_for_objective("lab-js", oid)
    assert locked["unlocked"] is False
    assert locked["hints"] == []
    assert locked["hint_count"] >= 1
    assert "attempt" in (locked["locked_message"] or "").lower()

    record_attempt("lab-js", oid, note="tried /#/administration")
    unlocked = hints_for_objective("lab-js", oid)
    assert unlocked["unlocked"] is True
    assert len(unlocked["hints"]) == unlocked["hint_count"]
    assert unlocked["hints"][0]["body"]

    status = lab_status_payload("lab-js")
    row = next(o for o in status["objectives"] if o["id"] == oid)
    assert row["attempted"] is True
    assert row["hints_unlocked"] is True
    assert row["hints_preview"]


def test_human_complete_never_auto(home):
    open_lab("juice-shop")
    pid = "lab-juice-shop"
    mark_objective_complete(pid, "js-score-board", note="found score board")
    status = lab_status_payload(pid)
    row = next(o for o in status["objectives"] if o["id"] == "js-score-board")
    assert row["completed"] is True
    assert row["complete_meta"]["auto"] is False
    with open_graph(pid) as g:
        assert list(g.list_by_type("FINDING")) == []


def test_coach_hooks_when_lab_bound(home):
    open_lab("juice-shop", program_id="lab-coach")
    payload = coach_payload("lab-coach")
    assert payload["llm"] is False
    assert payload["lab_bound"] is True
    kinds = {h["kind"] for h in payload["hints"]}
    assert "lab_stage" in kinds
    assert "lab_hint_gate" in kinds
    # still has baseline coach kinds
    assert "stage_checklist" in kinds or "fp_school" in kinds
    bodies = " ".join(h["body"] for h in payload["hints"])
    assert "invent" in bodies.lower() or "never invents" in payload["disclaimer"].lower()


def test_coach_without_lab_no_lab_kinds(home):
    create_program("plain")
    payload = coach_payload("plain")
    assert payload.get("lab_bound") is False
    assert not any(
        str(h.get("kind", "")).startswith("lab_") for h in payload["hints"]
    )


def test_unknown_lab_and_objective(home):
    with pytest.raises(FileNotFoundError):
        get_lab_def("not-a-lab")
    open_lab("juice-shop", program_id="lab-js")
    with pytest.raises(FileNotFoundError):
        record_attempt("lab-js", "nope-objective")


def test_api_labs_open_attempt_hints_coach(ui_server_skip):
    base = ui_server_skip
    code, labs = _http_json(f"{base}/api/labs")
    assert code == 200
    assert labs["count"] >= 1
    assert "juice-shop" in {L["lab_id"] for L in labs["labs"]}

    code, opened = _http_json(
        f"{base}/api/labs/open",
        {"lab_id": "juice-shop", "program_id": "e0api"},
    )
    assert code == 200, opened
    result = opened["result"]
    assert result["program_id"] == "e0api"
    assert result["counts"]["hints_unlocked"] == 0

    oid = "js-dom-xss-search"
    code, locked = _http_json(
        f"{base}/api/programs/e0api/lab/hints/{oid}"
    )
    assert code == 200
    assert locked["unlocked"] is False
    assert locked["hints"] == []

    code, att = _http_json(
        f"{base}/api/programs/e0api/lab/attempt",
        {"objective_id": oid, "note": "probed search"},
    )
    assert code == 200, att
    assert att["result"]["counts"]["hints_unlocked"] >= 1

    code, unlocked = _http_json(
        f"{base}/api/programs/e0api/lab/hints/{oid}"
    )
    assert code == 200
    assert unlocked["unlocked"] is True
    assert len(unlocked["hints"]) >= 1

    code, coach = _http_json(f"{base}/api/programs/e0api/coach")
    assert code == 200
    assert coach["lab_bound"] is True
    assert any(h["kind"] == "lab_stage" for h in coach["hints"])

    code, health = _http_json(f"{base}/api/health")
    assert code == 200
    assert health["phase"] in ("E0", "E1", "E2")
    assert health["default_bind"] == DEFAULT_UI_BIND


def test_spa_has_labs_tab():
    root = resolve_ui_static_root()
    html = (root / "index.html").read_text(encoding="utf-8")
    js = (root / "app.js").read_text(encoding="utf-8")
    assert 'data-view="labs"' in html
    assert 'id="view-labs"' in html
    assert "Open Lab" in html
    assert "loadLabs" in js
    assert "/api/labs/open" in js
    assert "lab_bound" in js


def test_docs_pointers_exist():
    repo = Path(__file__).resolve().parents[1]
    assert (repo / "docs" / "PHASE_E_PLAN.md").is_file()
    assert (repo / "docs" / "PHASE_E_SLICE0.md").is_file()
    plan = (repo / "docs" / "PHASE_E_PLAN.md").read_text(encoding="utf-8")
    assert "SENTINEL_SUITE_PHASE_E_PLAN.md" in plan
