"""Phase C slice7 — xss_dom sink-proof pack v0 (fixture-driven)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import PackRunError, discover_packs, list_pack_manifests, run_pack
from gungnir.packs.report import export_report
from gungnir.packs.xss_dom.caps import (
    COACH_CAPS,
    DEFAULT_REQUESTS,
    HARD_MAX_REQUESTS,
    RequestBudget,
    XssDomCapExceededError,
    resolve_caps,
)
from gungnir.packs.xss_dom.checks import COACH_XSS, DEFAULT_MARKER, run_checks
from sentinel_core import ENGINE_ALLOWLIST, create_program, open_graph, program_dir


def _write_role(program_id: str, role: str = "a", **extra) -> Path:
    root = program_dir(program_id)
    roles = root / "roles"
    roles.mkdir(parents=True, exist_ok=True)
    path = roles / f"{role}.json"
    body = {"cookies": {"session": f"lab-{role}"}, "headers": {}, "bearer": None}
    body.update(extra)
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _write_scope(program_id: str, allow: list[str]) -> Path:
    root = program_dir(program_id)
    p = root / "scope.txt"
    p.write_text("\n".join(allow) + "\n", encoding="utf-8")
    return p


def test_engine_allowlist_still_empty_slice7():
    assert ENGINE_ALLOWLIST == {}


def test_pack_listed_needs_roles_0():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "xss_dom" in manifests
    m = manifests["xss_dom"]
    assert m.needs_roles == 0
    assert m.pack_class == "xss_dom"
    assert m.version == "0"
    # prior packs intact
    for pid in (
        "ato_oauth_oidc",
        "bola_idor_bfla",
        "business_logic",
        "race_toctou",
        "graphql",
    ):
        assert pid in manifests


def test_discover_six_packs():
    packs = discover_packs()
    assert set(packs) >= {
        "xss_dom",
        "graphql",
        "ato_oauth_oidc",
        "bola_idor_bfla",
        "business_logic",
        "race_toctou",
    }
    assert callable(packs["xss_dom"]["run"])


def test_resolve_caps_defaults_under_maxima():
    caps = resolve_caps()
    assert caps.max_requests <= HARD_MAX_REQUESTS
    assert caps.max_requests == DEFAULT_REQUESTS


def test_resolve_caps_over_limit_hard_fails():
    with pytest.raises(XssDomCapExceededError) as ei:
        resolve_caps(max_requests=HARD_MAX_REQUESTS + 1)
    assert "hard" in str(ei.value).lower() or "cap" in str(ei.value).lower()


def test_request_budget_refuses_past_max():
    b = RequestBudget(max_requests=2)
    assert b.try_acquire()
    assert b.try_acquire()
    assert not b.try_acquire()
    assert b.used == 2
    assert b.rejected >= 1


def test_default_source_sink_fixtures_emit_needs_human():
    r = run_checks({"i_own_this": True, "fixtures": {}})
    assert r["candidates"]
    assert any(c["check"] == "xss_dom_source_sink_marker" for c in r["candidates"])
    for c in r["candidates"]:
        assert c["verification"] in {"needs_human", "unverified"}
        assert c.get("auto_verified") is False
        assert "checklist" in c
        assert set(c["checklist"]) >= {
            "in_scope",
            "reproducible",
            "impact",
            "evidence_attached",
        }
        stub = c["evidence_stub"]
        assert stub["response"].get("marker_in_sink") is True
        assert stub["response"].get("alert_only") is not True
        assert DEFAULT_MARKER in (stub["response"].get("sink_snippet") or "") or stub[
            "request"
        ].get("marker") == DEFAULT_MARKER


def test_alert_only_fixture_rejected():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "source_sink": [
                    {
                        "name": "alert-spam",
                        "url": "http://127.0.0.1/x",
                        "source": {"kind": "location.hash"},
                        "sink": {"snippet": f"alert('{DEFAULT_MARKER}')"},
                        "marker": DEFAULT_MARKER,
                    }
                ]
            },
        }
    )
    assert not any(c["check"] == "xss_dom_source_sink_marker" for c in r["candidates"])
    blob = " ".join(r["notes"]).lower()
    assert "alert" in blob


def test_marker_in_innerhtml_sink_proved():
    marker = "canaryXSS99"
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "source_sink": [
                    {
                        "url": f"http://127.0.0.1/app#{marker}",
                        "source": {"kind": "location.hash", "value": f"#{marker}"},
                        "sink": {
                            "kind": "innerHTML",
                            "snippet": f"el.innerHTML = location.hash; // {marker}",
                        },
                        "marker": marker,
                        "expect": {"marker_in_sink": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "xss_dom_source_sink_marker"]
    assert hits
    assert hits[0]["verification"] == "needs_human"
    assert hits[0]["evidence_stub"]["response"]["marker_in_sink"] is True
    assert marker in hits[0]["evidence_stub"]["response"]["sink_snippet"]


def test_reflected_stub_with_sink_proof():
    marker = "reflMark1"
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "reflected": [
                    {
                        "url": f"http://127.0.0.1/search?q={marker}",
                        "param": "q",
                        "marker": marker,
                        "response": {"status": 200, "body": f"<b>{marker}</b>"},
                        "sink": {
                            "kind": "innerHTML",
                            "snippet": f"out.innerHTML = q; // {marker}",
                        },
                        "expect": {"reflected": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "xss_dom_reflected_stub"]
    assert hits
    assert hits[0]["verification"] == "needs_human"
    assert hits[0]["evidence_stub"]["response"]["marker_in_sink"] is True


def test_reflected_stub_body_only_unverified():
    marker = "reflBodyOnly"
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "reflected": [
                    {
                        "url": f"http://127.0.0.1/search?q={marker}",
                        "marker": marker,
                        "response": {"status": 200, "body": f"Hello {marker}"},
                        "expect": {"reflected": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "xss_dom_reflected_stub"]
    assert hits
    assert hits[0]["verification"] == "unverified"


def test_stored_stub_with_sink_proof():
    marker = "storeMark1"
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "stored": [
                    {
                        "write_url": "http://127.0.0.1/comments",
                        "url": "http://127.0.0.1/comments/1",
                        "marker": marker,
                        "write_response": {"status": 201},
                        "read_response": {
                            "status": 200,
                            "body": f"<p>{marker}</p>",
                        },
                        "sink": {
                            "kind": "innerHTML",
                            "snippet": f"div.innerHTML = comment; // {marker}",
                        },
                        "expect": {"stored": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "xss_dom_stored_stub"]
    assert hits
    assert hits[0]["verification"] == "needs_human"


def test_postmessage_hints_only():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "postmessage": [
                    {
                        "url": "http://127.0.0.1/widget",
                        "origin_check": False,
                    }
                ]
            },
        }
    )
    assert r["hints"]
    assert all(h.get("verification") == "needs_human" for h in r["hints"])


def test_checks_over_limit_raises_pack_run_error():
    with pytest.raises(PackRunError) as ei:
        run_checks({"i_own_this": True, "max_requests": HARD_MAX_REQUESTS + 5})
    assert ei.value.exit_code != 0


def test_live_mock_respects_hard_caps():
    calls: list[dict] = []

    def opener(payload):
        calls.append(payload)
        return {"status": 200, "body": "<html></html>"}

    r = run_checks(
        {
            "i_own_this": True,
            "opener": opener,
            "max_requests": 3,
            "fixtures": {
                "live_mock": {
                    "calls": [
                        {"url": "http://127.0.0.1/a"},
                        {"url": "http://127.0.0.1/b"},
                        {"url": "http://127.0.0.1/c"},
                        {"url": "http://127.0.0.1/d"},
                        {"url": "http://127.0.0.1/e"},
                    ]
                }
            },
        }
    )
    assert r["caps"]["max_requests"] == 3
    assert r["caps"].get("requests_used", 0) <= 3
    assert len(calls) <= 3
    assert r.get("fixtures_only") is False


def test_run_pack_emits_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("xss-lab")
    result = run_pack("xss_dom", "xss-lab", i_own_this=True)
    assert result["pack_id"] == "xss_dom"
    assert result["findings_emitted"] >= 1
    for e in result["events"]:
        assert e["verification"] in {"needs_human", "unverified"}
    with open_graph("xss-lab") as g:
        for ev in g.list_by_type("FINDING"):
            payload = ev.payload or {}
            if payload.get("pack_id") == "xss_dom":
                assert payload.get("verification") in {"needs_human", "unverified"}
                assert payload.get("verified") is False


def test_oos_host_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("xss-oos")
    scope = _write_scope("xss-oos", ["lab.example"])
    result = run_pack(
        "xss_dom",
        "xss-oos",
        scope_path=scope,
        fixtures={
            "source_sink": [
                {
                    "url": "https://evil.example/app#x",
                    "source": {"kind": "location.hash"},
                    "sink": {
                        "kind": "innerHTML",
                        "snippet": "el.innerHTML = location.hash; // ssntnlXSS7m4rk",
                    },
                    "marker": "ssntnlXSS7m4rk",
                    "expect": {"marker_in_sink": True},
                }
            ]
        },
    )
    assert result["findings_emitted"] == 0


def test_prior_packs_intact(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("xss-legacy")
    scope = _write_scope("xss-legacy", ["lab.example"])
    _write_role("xss-legacy", "a")
    _write_role("xss-legacy", "b")

    ato = run_pack(
        "ato_oauth_oidc",
        "xss-legacy",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    assert ato["pack_id"] == "ato_oauth_oidc"

    bola = run_pack(
        "bola_idor_bfla",
        "xss-legacy",
        scope_path=scope,
        fixtures={
            "horizontal_idor": [
                {
                    "url": "https://lab.example/api/objects/obj-b",
                    "role_a_on_b": {"status": 200, "body": '{"owner":"b"}'},
                    "role_b_on_b": {"status": 200, "body": '{"owner":"b"}'},
                    "expect": {"idor": True},
                }
            ]
        },
    )
    assert bola["pack_id"] == "bola_idor_bfla"
    assert bola["findings_emitted"] >= 1

    bl = run_pack(
        "business_logic",
        "xss-legacy",
        scope_path=scope,
        fixtures={
            "flows": [
                {
                    "name": "cart-checkout",
                    "url": "https://lab.example/cart",
                    "steps": [
                        {"name": "cart", "url": "https://lab.example/cart"},
                        {"name": "checkout", "url": "https://lab.example/checkout"},
                    ],
                }
            ]
        },
    )
    assert bl["pack_id"] == "business_logic"
    assert bl["findings_emitted"] >= 1

    race = run_pack(
        "race_toctou",
        "xss-legacy",
        i_own_this=True,
        i_understand_lab=True,
        max_workers=2,
        max_requests=6,
        max_duration=2.0,
    )
    assert race["pack_id"] == "race_toctou"
    assert race["findings_emitted"] >= 1

    gq = run_pack("graphql", "xss-legacy", i_own_this=True)
    assert gq["pack_id"] == "graphql"
    assert gq["findings_emitted"] >= 1


def test_cli_pack_list_includes_xss_dom(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(os.environ)
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    proc = subprocess.run(
        [sys.executable, "-m", "sentinel_cli.cli", "hunt", "pack", "list"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    ids = {p["id"] for p in data["packs"]}
    assert "xss_dom" in ids
    assert "graphql" in ids
    assert "race_toctou" in ids
    assert "business_logic" in ids
    assert "bola_idor_bfla" in ids
    assert "ato_oauth_oidc" in ids


def test_cli_happy_lab_run_and_report(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-xss")
    env = dict(os.environ)
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "pack",
            "run",
            "xss_dom",
            "--program",
            "cli-xss",
            "--i-own-this",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["pack_id"] == "xss_dom"
    assert data["findings_emitted"] >= 1
    for e in data["events"]:
        assert e["verification"] in {"needs_human", "unverified"}

    out = tmp_path / "xss-report.md"
    rep = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "report",
            "cli-xss",
            "--pack",
            "xss_dom",
            "-o",
            str(out),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert rep.returncode == 0, rep.stdout + rep.stderr
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "xss" in text.lower()


def test_export_report_pack_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("xss-rep")
    run_pack("xss_dom", "xss-rep", i_own_this=True)
    result = export_report("xss-rep", pack_id="xss_dom")
    assert result["pack_id"] == "xss_dom"
    assert result["findings"] >= 1


def test_coach_constants():
    assert "sink" in COACH_XSS.lower() or "marker" in COACH_XSS.lower()
    assert "alert" in COACH_XSS.lower()
    assert "cap" in COACH_CAPS.lower() or "request" in COACH_CAPS.lower()
