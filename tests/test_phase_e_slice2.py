"""Phase E2 — crAPI + auth-session labs, progress schema, shared UX polish."""

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
    PROGRESS_SCHEMA_VERSION,
    generate_lab_coach_hints,
    get_lab_def,
    hints_for_objective,
    lab_catalog,
    lab_status_payload,
    labs_payload,
    load_progress,
    mark_objective_complete,
    migrate_progress,
    open_lab,
    record_attempt,
    save_progress,
)
from sentinel_cli.ui_server import (
    DEFAULT_UI_BIND,
    make_handler,
    resolve_ui_static_root,
)
from sentinel_core import ENGINE_ALLOWLIST, open_graph, program_dir

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

EXPECTED_LABS = ("juice-shop", "crapi", "auth-session")


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


def test_lab_catalog_has_three_labs():
    labs = lab_catalog()
    ids = [L["lab_id"] for L in labs]
    assert len(labs) >= 3
    for expected in EXPECTED_LABS:
        assert expected in ids
    payload = labs_payload()
    assert payload["count"] >= 3
    assert payload["phase"] == "E2"
    assert payload["progress_schema_version"] == PROGRESS_SCHEMA_VERSION
    for L in payload["labs"]:
        assert L.get("start_docs")
        assert L.get("default_base_url", "").startswith("http://127.0.0.1")


def test_crapi_lab_open_and_hints(home):
    status = open_lab("crapi", program_id="lab-crapi")
    assert status["lab_id"] == "crapi"
    assert status["invent_findings"] is False
    assert status["auto_verified"] is False
    assert status["progress_schema_version"] == PROGRESS_SCHEMA_VERSION
    assert status["phase"] == "E2"
    root = program_dir("lab-crapi")
    assert (root / "lab.json").is_file()
    assert (root / "lab_progress.json").is_file()
    assert (root / "LAB_START.md").is_file()
    assert "8888" in (root / "LAB_START.md").read_text(encoding="utf-8")
    progress = load_progress("lab-crapi")
    assert progress["schema_version"] == PROGRESS_SCHEMA_VERSION
    assert progress["lab_id"] == "crapi"

    oid = "crapi-bola-vehicle"
    locked = hints_for_objective("lab-crapi", oid)
    assert locked["unlocked"] is False
    assert locked["hints"] == []
    record_attempt("lab-crapi", oid, note="tried vehicle id as role B")
    unlocked = hints_for_objective("lab-crapi", oid)
    assert unlocked["unlocked"] is True
    assert len(unlocked["hints"]) >= 1

    with open_graph("lab-crapi") as g:
        assert list(g.list_by_type("FINDING")) == []


def test_auth_session_lab_open_roles_dir(home):
    status = open_lab("auth-session", program_id="lab-auth-session")
    assert status["lab_id"] == "auth-session"
    root = program_dir("lab-auth-session")
    assert (root / "roles").is_dir()
    assert (root / "roles" / "README.md").is_file()
    assert (root / "LAB_START.md").is_file()
    objs = {o["id"] for o in status["objectives"]}
    assert "as-role-fixtures" in objs
    assert "as-role-a-vs-b" in objs
    record_attempt("lab-auth-session", "as-role-fixtures", note="wrote a.json")
    mark_objective_complete("lab-auth-session", "as-role-fixtures", note="fixtures placed")
    st = lab_status_payload("lab-auth-session")
    row = next(o for o in st["objectives"] if o["id"] == "as-role-fixtures")
    assert row["completed"] is True
    assert row["complete_meta"]["auto"] is False


def test_progress_schema_migrate_legacy(home):
    open_lab("juice-shop", program_id="lab-migrate")
    path = program_dir("lab-migrate") / "lab_progress.json"
    # Simulate E0/E1 file without schema_version
    legacy = {
        "attempts": {
            "js-admin-section": {
                "objective_id": "js-admin-section",
                "attempted_at": "2026-01-01T00:00:00+00:00",
                "count": 2,
                "note": "old",
                "hints_unlocked": True,
            }
        },
        "completed": {},
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    loaded = load_progress("lab-migrate")
    assert loaded["schema_version"] == PROGRESS_SCHEMA_VERSION
    assert "js-admin-section" in loaded["attempts"]
    assert loaded["attempts"]["js-admin-section"]["count"] == 2
    assert loaded["lab_id"] == "juice-shop"
    # On-disk should be upgraded
    disk = json.loads(path.read_text(encoding="utf-8"))
    assert disk["schema_version"] == PROGRESS_SCHEMA_VERSION
    # migrate_progress itself is idempotent
    again = migrate_progress(disk, lab_id="juice-shop", program_id="lab-migrate")
    assert again["schema_version"] == PROGRESS_SCHEMA_VERSION
    assert again["attempts"]["js-admin-section"]["count"] == 2


def test_coach_kinds_work_for_crapi_and_auth(home):
    open_lab("crapi", program_id="e2coach-crapi")
    record_attempt("e2coach-crapi", "crapi-jwt-identity", note="token")
    payload = coach_payload("e2coach-crapi")
    assert payload["lab_bound"] is True
    assert payload["llm"] is False
    assert payload["phase"] == "E2"
    kinds = {h["kind"] for h in payload["hints"]}
    assert "lab_stage" in kinds
    assert "lab_fp_school" in kinds
    assert "lab_stage" in (payload.get("lab_kinds") or [])

    open_lab("auth-session", program_id="e2coach-auth")
    record_attempt("e2coach-auth", "as-anon-vs-role", note="anon vs a")
    hints = generate_lab_coach_hints("e2coach-auth")
    assert any(h["kind"] == "lab_stage" for h in hints)
    assert any(h["kind"] == "lab_fp_school" for h in hints)
    # never auto-complete
    prog = load_progress("e2coach-auth")
    assert not (prog.get("completed") or {})


def test_shared_attempt_ux_all_labs(home):
    for lab_id, pid, oid in (
        ("juice-shop", "e2ux-js", "js-score-board"),
        ("crapi", "e2ux-crapi", "crapi-recon-api"),
        ("auth-session", "e2ux-auth", "as-session-cookie"),
    ):
        open_lab(lab_id, program_id=pid)
        status = record_attempt(pid, oid, note=f"try {lab_id}")
        assert status["counts"]["hints_unlocked"] >= 1
        h = hints_for_objective(pid, oid)
        assert h["unlocked"] is True
        assert h["lab_id"] == lab_id
        how = status["how_to_open"]
        assert lab_id in how["cli"]
        assert lab_id in how["ui"]


def test_api_multi_lab_and_health(ui_server_skip):
    base = ui_server_skip
    code, labs = _http_json(f"{base}/api/labs")
    assert code == 200
    assert labs["count"] >= 3
    assert labs["phase"] == "E2"
    ids = {L["lab_id"] for L in labs["labs"]}
    assert ids >= set(EXPECTED_LABS)

    code, opened = _http_json(
        f"{base}/api/labs/open",
        {"lab_id": "crapi", "program_id": "e2api-crapi"},
    )
    assert code == 200, opened
    result = opened["result"]
    assert result["lab_id"] == "crapi"
    assert result["progress_schema_version"] == PROGRESS_SCHEMA_VERSION

    oid = "crapi-graphql"
    code, att = _http_json(
        f"{base}/api/programs/e2api-crapi/lab/attempt",
        {"objective_id": oid, "note": "enum"},
    )
    assert code == 200, att
    code, unlocked = _http_json(
        f"{base}/api/programs/e2api-crapi/lab/hints/{oid}"
    )
    assert code == 200
    assert unlocked["unlocked"] is True

    code, opened2 = _http_json(
        f"{base}/api/labs/open",
        {"lab_id": "auth-session", "program_id": "e2api-auth"},
    )
    assert code == 200, opened2
    code, coach = _http_json(f"{base}/api/programs/e2api-auth/coach")
    assert code == 200
    assert coach["lab_bound"] is True
    assert coach["phase"] == "E2"

    code, health = _http_json(f"{base}/api/health")
    assert code == 200
    assert health["phase"] == "E2"
    assert health["default_bind"] == DEFAULT_UI_BIND


def test_spa_multi_lab_ux():
    root = resolve_ui_static_root()
    html = (root / "index.html").read_text(encoding="utf-8")
    js = (root / "app.js").read_text(encoding="utf-8")
    css = (root / "style.css").read_text(encoding="utf-8")
    assert "crAPI" in html or "crapi" in html
    assert "auth-session" in html
    assert 'id="labs-objective-select"' in html
    assert "labs-obj-actions" in js
    assert "labs-obj-attempt" in js
    assert "fillLabObjectiveSelect" in js
    assert "showCatalogStartDocs" in js
    assert "progress_schema_version" in js
    assert "labs-obj-actions" in css


def test_docs_e2_pointers_exist():
    repo = Path(__file__).resolve().parents[1]
    assert (repo / "docs" / "PHASE_E_SLICE2.md").is_file()
    plan = (repo / "docs" / "PHASE_E_PLAN.md").read_text(encoding="utf-8")
    assert "PHASE_E_SLICE2" in plan or "E2" in plan
    assert (repo / "docs" / "PHASE_E_SLICE2.md").read_text(encoding="utf-8")


def test_unknown_new_lab_rejected(home):
    with pytest.raises(FileNotFoundError):
        get_lab_def("not-real-lab")
    open_lab("crapi", program_id="e2bad")
    with pytest.raises(FileNotFoundError):
        record_attempt("e2bad", "nope-obj")


def test_save_load_roundtrip_schema(home):
    open_lab("juice-shop", program_id="e2rt")
    record_attempt("e2rt", "js-jwt-auth", note="one")
    record_attempt("e2rt", "js-jwt-auth", note="two")
    prog = load_progress("e2rt")
    assert prog["schema_version"] == PROGRESS_SCHEMA_VERSION
    assert prog["attempts"]["js-jwt-auth"]["count"] == 2
    notes = prog["attempts"]["js-jwt-auth"].get("notes") or []
    assert len(notes) == 2
    save_progress("e2rt", prog)
    again = load_progress("e2rt")
    assert again["attempts"]["js-jwt-auth"]["count"] == 2
