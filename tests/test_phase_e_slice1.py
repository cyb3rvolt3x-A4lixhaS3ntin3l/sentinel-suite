"""Phase E1 — Coach lab-aware deepen (lab_stage / lab_fp_school / lab_time_budget)."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from gungnir.packs import list_pack_manifests
from sentinel_cli.ui_auth import clear_sessions, setup_auth
from sentinel_cli.ui_coach import coach_payload
from sentinel_cli.ui_labs import (
    LAB_TIME_BUDGET_ATTEMPT_TOTAL,
    LAB_TIME_BUDGET_HOURS,
    generate_lab_coach_hints,
    get_lab_def,
    load_progress,
    mark_objective_complete,
    open_lab,
    record_attempt,
    save_progress,
)
from sentinel_cli.ui_server import (
    DEFAULT_UI_BIND,
    make_handler,
    resolve_ui_static_root,
)
from sentinel_core import ENGINE_ALLOWLIST, create_program, program_dir

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


def test_lab_stage_map_attempt_hint_complete(home):
    open_lab("juice-shop", program_id="e1stage")
    hints = generate_lab_coach_hints("e1stage")
    stage = next(h for h in hints if h["kind"] == "lab_stage")
    assert stage["lab_stage"] == "map"
    assert (stage.get("evidence_counts") or {}).get("lab_stage") == "map"

    record_attempt("e1stage", "js-admin-section", note="try1")
    hints = generate_lab_coach_hints("e1stage")
    stage = next(h for h in hints if h["kind"] == "lab_stage")
    assert stage["lab_stage"] == "attempt"

    lab = get_lab_def("juice-shop")
    for obj in lab["objectives"]:
        record_attempt("e1stage", obj["id"], note="cover")
    hints = generate_lab_coach_hints("e1stage")
    stage = next(h for h in hints if h["kind"] == "lab_stage")
    assert stage["lab_stage"] == "hint"

    mark_objective_complete("e1stage", "js-score-board", note="done")
    hints = generate_lab_coach_hints("e1stage")
    stage = next(h for h in hints if h["kind"] == "lab_stage")
    assert stage["lab_stage"] == "complete"


def test_lab_fp_school_when_attempted_incomplete(home):
    open_lab("juice-shop", program_id="e1fp")
    kinds0 = {h["kind"] for h in generate_lab_coach_hints("e1fp")}
    assert "lab_fp_school" not in kinds0

    record_attempt("e1fp", "js-dom-xss-search", note="reflected")
    hints = generate_lab_coach_hints("e1fp")
    assert "lab_fp_school" in {h["kind"] for h in hints}
    fp = next(h for h in hints if h["kind"] == "lab_fp_school")
    body = fp["body"].lower()
    assert "xss" in body or "reflection" in body or "sink" in body
    assert "invent" in body or "never" in body
    samples = (fp.get("evidence_counts") or {}).get("sample_ids") or []
    assert "js-dom-xss-search" in samples


def test_lab_time_budget_many_attempts(home):
    open_lab("juice-shop", program_id="e1tb")
    record_attempt("e1tb", "js-admin-section", note="grind")
    prog = load_progress("e1tb")
    prog["attempts"]["js-admin-section"]["count"] = LAB_TIME_BUDGET_ATTEMPT_TOTAL
    save_progress("e1tb", prog)
    hints = generate_lab_coach_hints("e1tb")
    assert "lab_time_budget" in {h["kind"] for h in hints}
    tb = next(h for h in hints if h["kind"] == "lab_time_budget")
    assert (tb.get("evidence_counts") or {}).get("attempt_total") >= LAB_TIME_BUDGET_ATTEMPT_TOTAL
    assert "auto" in tb["body"].lower() or "never" in tb["body"].lower()


def test_lab_time_budget_long_open(home):
    open_lab("juice-shop", program_id="e1age")
    root = program_dir("e1age")
    binding_path = root / "lab.json"
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    old = (
        datetime.now(timezone.utc) - timedelta(hours=float(LAB_TIME_BUDGET_HOURS) + 1)
    ).isoformat()
    binding["opened_at"] = old
    binding_path.write_text(
        json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    record_attempt("e1age", "js-open-redirect", note="old try")
    hints = generate_lab_coach_hints("e1age")
    assert any(h["kind"] == "lab_time_budget" for h in hints)


def test_coach_payload_lab_kinds_and_progress(home):
    open_lab("juice-shop", program_id="e1coach")
    record_attempt("e1coach", "js-jwt-auth", note="token")
    payload = coach_payload("e1coach")
    assert payload["llm"] is False
    assert payload["lab_bound"] is True
    assert payload.get("phase") in ("E1", "E2")
    assert "lab_stage" in (payload.get("lab_kinds") or [])
    assert "lab_fp_school" in (payload.get("lab_kinds") or [])
    assert (payload.get("lab_progress") or {}).get("lab_id") == "juice-shop"
    assert payload["lab_progress"].get("lab_stage") in (
        "map",
        "attempt",
        "hint",
        "complete",
    )
    kinds = {h["kind"] for h in payload["hints"]}
    assert "lab_stage" in kinds
    assert "lab_fp_school" in kinds
    assert "stage_checklist" in kinds or "fp_school" in kinds


def test_coach_plain_program_no_lab_kinds(home):
    create_program("plain-e1")
    payload = coach_payload("plain-e1")
    assert payload.get("lab_bound") is False
    assert not (payload.get("lab_kinds") or [])
    assert not any(str(h.get("kind", "")).startswith("lab_") for h in payload["hints"])


def test_never_auto_complete_from_coach(home):
    open_lab("juice-shop", program_id="e1noauto")
    record_attempt("e1noauto", "js-score-board")
    generate_lab_coach_hints("e1noauto")
    coach_payload("e1noauto")
    prog = load_progress("e1noauto")
    assert not (prog.get("completed") or {})


def test_api_coach_lab_kinds_and_health(ui_server_skip):
    base = ui_server_skip
    code, opened = _http_json(
        f"{base}/api/labs/open",
        {"lab_id": "juice-shop", "program_id": "e1api"},
    )
    assert code == 200, opened
    _http_json(
        f"{base}/api/programs/e1api/lab/attempt",
        {"objective_id": "js-admin-section", "note": "api try"},
    )
    code, coach = _http_json(f"{base}/api/programs/e1api/coach")
    assert code == 200, coach
    assert coach["lab_bound"] is True
    assert coach["llm"] is False
    kinds = {h["kind"] for h in coach["hints"]}
    assert "lab_stage" in kinds
    assert "lab_fp_school" in kinds
    assert "lab_stage" in (coach.get("lab_kinds") or [])

    code, health = _http_json(f"{base}/api/health")
    assert code == 200
    assert health["phase"] in ("E1", "E2")
    assert health["default_bind"] == DEFAULT_UI_BIND


def test_spa_lab_coach_section():
    root = resolve_ui_static_root()
    html = (root / "index.html").read_text(encoding="utf-8")
    js = (root / "app.js").read_text(encoding="utf-8")
    css = (root / "style.css").read_text(encoding="utf-8")
    assert 'id="coach-lab-section"' in html
    assert "Lab Coach" in html
    assert "lab_stage" in html or "lab_fp_school" in html
    assert "renderCoachCard" in js
    assert "coach-lab-hints" in js
    assert "lab_kinds" in js
    assert "coach-lab-section" in css
    assert "lab-kind" in css


def test_docs_e1_pointers_exist():
    repo = Path(__file__).resolve().parents[1]
    assert (repo / "docs" / "PHASE_E_SLICE1.md").is_file()
    plan = (repo / "docs" / "PHASE_E_PLAN.md").read_text(encoding="utf-8")
    assert "PHASE_E_SLICE1" in plan
    assert "E1" in plan
