"""Phase E3 — Lab 1 tutorial checklist → confirm-finding → report.md exit."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from gungnir.packs import confirm_finding, list_pack_manifests, run_pack
from sentinel_cli.ui_auth import clear_sessions, setup_auth
from sentinel_cli.ui_labs import (
    PROGRESS_SCHEMA_VERSION,
    TUTORIAL_STEPS,
    export_lab_report,
    get_lab_def,
    lab_catalog,
    lab_status_payload,
    labs_payload,
    load_progress,
    mark_objective_complete,
    open_lab,
    record_attempt,
    render_lab_report_markdown,
    tutorial_checklist,
)
from sentinel_cli.ui_server import make_handler, resolve_ui_static_root
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


def _emit_and_confirm(program_id: str, *, note: str = "reproduced on juice-shop lab") -> str:
    """Emit needs_human FINDING via open_redirect fixtures (127.0.0.1), then human confirm."""
    scope = str(program_dir(program_id) / "scope.txt")
    result = run_pack(
        "open_redirect",
        program_id,
        scope_path=scope,
        i_own_this=True,
        fixtures={},
    )
    assert result["findings_emitted"] >= 1
    fid = result["events"][0]["id"]
    assert result["events"][0]["verification"] in {"needs_human", "unverified"}
    out = confirm_finding(
        program_id,
        fid,
        status="confirmed",
        note=note,
        who="hunter-e3",
    )
    assert out["verification"] == "confirmed"
    return fid


def test_allowlist_still_empty_and_twelve_packs():
    assert ENGINE_ALLOWLIST == {}
    ids = {m.id for m in list_pack_manifests()}
    for p in PRIOR_PACKS:
        assert p in ids
    assert len(ids) == 12


def test_tutorial_steps_defined():
    ids = [s["id"] for s in TUTORIAL_STEPS]
    assert ids == [
        "open_lab",
        "attempt",
        "hints",
        "complete",
        "confirm_finding",
        "export_report",
    ]


def test_lab1_tutorial_e2e_to_report(home):
    """Lab 1 juice-shop: open → attempt → hints → complete → confirm → report.md."""
    status = open_lab("juice-shop", program_id="lab-juice-shop")
    assert status["lab_id"] == "juice-shop"
    assert status["invent_findings"] is False
    assert status["phase"] == "E3"

    tutorial = tutorial_checklist("lab-juice-shop")
    assert tutorial["lab1_exit"] is True
    assert tutorial["complete"] is False
    assert tutorial["steps"][0]["done"] is True  # open_lab
    assert tutorial["next_step"]["id"] == "attempt"

    oid = "js-admin-section"
    # pick a real objective from catalog
    lab = get_lab_def("juice-shop")
    oid = str(lab["objectives"][0]["id"])

    record_attempt("lab-juice-shop", oid, note="tried from suite story")
    tutorial = tutorial_checklist("lab-juice-shop")
    assert tutorial["steps"][1]["done"] is True  # attempt
    assert tutorial["steps"][2]["done"] is True  # hints unlocked with attempt

    mark_objective_complete("lab-juice-shop", oid, note="human complete")
    tutorial = tutorial_checklist("lab-juice-shop")
    assert tutorial["steps"][3]["done"] is True  # complete
    assert tutorial["steps"][4]["done"] is False  # confirm not yet

    fid = _emit_and_confirm("lab-juice-shop")
    tutorial = tutorial_checklist("lab-juice-shop")
    assert fid in tutorial["confirmed_finding_ids"]
    assert tutorial["steps"][4]["done"] is True
    assert tutorial["steps"][5]["done"] is False

    out_path = home / "report.md"
    result = export_lab_report(
        "lab-juice-shop", output=out_path, confirmed_only=True
    )
    assert result["ok"] is True
    assert result["tutorial_complete"] is True
    assert result["invent_findings"] is False
    assert result["auto_verified"] is False
    assert Path(result["output"]).is_file()
    md = out_path.read_text(encoding="utf-8")
    assert "Lab exit report" in md
    assert "Curriculum progress (not findings)" in md
    assert "Hunter tutorial checklist" in md
    assert "not** auto-emitted FINDING" in md or "not** auto-emitted" in md or "not auto-emitted" in md.lower() or "not** auto-emitted FINDING events" in md or "auto-emitted FINDING" in md
    assert "Verification: confirmed" in md or "confirmed" in md

    tutorial = tutorial_checklist("lab-juice-shop")
    assert tutorial["complete"] is True
    assert all(s["done"] for s in tutorial["steps"])

    progress = load_progress("lab-juice-shop")
    assert progress["schema_version"] == PROGRESS_SCHEMA_VERSION
    assert len(progress.get("report_exports") or []) >= 1

    # status payload includes tutorial
    st = lab_status_payload("lab-juice-shop")
    assert st["tutorial"]["complete"] is True
    assert st["how_to_exit"]["cli"]


def test_lab_report_does_not_invent_findings(home):
    open_lab("juice-shop", program_id="lab-js-empty")
    record_attempt("lab-js-empty", get_lab_def("juice-shop")["objectives"][0]["id"])
    md = render_lab_report_markdown("lab-js-empty", confirmed_only=True)
    assert "No confirmed FINDING" in md
    assert "Curriculum progress (not findings)" in md
    # Must not claim a vuln from curriculum titles alone
    assert "invent_findings: `False`" in md


def test_cli_lab_tutorial_and_report(home):
    open_lab("juice-shop", program_id="lab-cli-e3")
    oid = str(get_lab_def("juice-shop")["objectives"][0]["id"])
    record_attempt("lab-cli-e3", oid, note="cli attempt")
    mark_objective_complete("lab-cli-e3", oid, note="cli complete")
    _emit_and_confirm("lab-cli-e3", note="cli confirm note")

    proc = subprocess.run(
        [sys.executable, "-m", "sentinel_cli.cli", "lab", "tutorial", "lab-cli-e3"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["steps"][4]["done"] is True
    assert payload["complete"] is False  # export not yet

    out = home / "cli-report.md"
    proc2 = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "lab",
            "report",
            "lab-cli-e3",
            "-o",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc2.returncode == 0, proc2.stderr
    meta = json.loads(proc2.stdout)
    assert meta["tutorial_complete"] is True
    assert out.is_file()
    assert "Lab exit report" in out.read_text(encoding="utf-8")


def test_api_tutorial_and_report(ui_server_skip):
    base = ui_server_skip
    code, opened = _http_json(
        base + "/api/labs/open",
        {"lab_id": "juice-shop", "program_id": "lab-api-e3"},
    )
    assert code == 200
    pid = opened["result"]["program_id"]
    oid = str(get_lab_def("juice-shop")["objectives"][0]["id"])

    code, _ = _http_json(
        base + f"/api/programs/{pid}/lab/attempt",
        {"objective_id": oid, "note": "api attempt"},
    )
    assert code == 200
    code, _ = _http_json(
        base + f"/api/programs/{pid}/lab/attempt",
        {"objective_id": oid, "note": "api complete", "complete": True},
    )
    assert code == 200

    _emit_and_confirm(pid, note="api confirm")

    code, tutorial = _http_json(base + f"/api/programs/{pid}/lab/tutorial")
    assert code == 200
    assert tutorial["steps"][4]["done"] is True
    assert tutorial["phase"] == "E3"

    code, preview = _http_json(base + f"/api/programs/{pid}/lab/report")
    assert code == 200
    assert preview.get("preview") is True
    assert "Lab exit report" in (preview.get("markdown") or "")

    code, exported = _http_json(
        base + f"/api/programs/{pid}/lab/report",
        {},
        method="POST",
    )
    assert code == 200
    result = exported["result"]
    assert result["tutorial_complete"] is True
    assert Path(result["output"]).is_file()

    code, tutorial2 = _http_json(base + f"/api/programs/{pid}/lab/tutorial")
    assert code == 200
    assert tutorial2["complete"] is True


def test_labs_payload_phase_e3():
    payload = labs_payload()
    assert payload["phase"] == "E3"
    assert payload["count"] >= 3
    ids = [L["lab_id"] for L in lab_catalog()]
    assert "juice-shop" in ids


def test_ui_static_has_tutorial_card():
    root = resolve_ui_static_root()
    html = (root / "index.html").read_text(encoding="utf-8")
    js = (root / "app.js").read_text(encoding="utf-8")
    assert "labs-tutorial-checklist" in html
    assert "labs-export-report" in html
    assert "renderLabTutorial" in js
    assert "lab/report" in js


def test_docs_and_plan_mark_e_complete():
    repo = Path(__file__).resolve().parents[1]
    assert (repo / "docs" / "PHASE_E_SLICE3.md").is_file()
    assert (repo / "docs" / "PHASE_E_PLAN.md").is_file()
    plan = (repo / "docs" / "PHASE_E_PLAN.md").read_text(encoding="utf-8")
    assert "E3" in plan
    assert "complete" in plan.lower()
    deliverable = Path("/workspace/deliverables/SENTINEL_SUITE_PHASE_E3_SLICE.md")
    assert deliverable.is_file()
