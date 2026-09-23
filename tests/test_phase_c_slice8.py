"""Phase C slice8 — csrf_state pack v0 (fixture-driven)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import PackRunError, discover_packs, list_pack_manifests, run_pack
from gungnir.packs.report import export_report
from gungnir.packs.csrf_state.caps import (
    COACH_CAPS,
    DEFAULT_REQUESTS,
    HARD_MAX_REQUESTS,
    RequestBudget,
    CsrfStateCapExceededError,
    resolve_caps,
)
from gungnir.packs.csrf_state.checks import COACH_CSRF, run_checks
from gungnir.packs.csrf_state.hints import hints_for_pattern, PATTERN_KINDS
from gungnir.packs.race_toctou.caps import (
    HARD_MAX_REQUESTS as RACE_HARD_MAX_REQUESTS,
    HARD_MAX_WORKERS as RACE_HARD_MAX_WORKERS,
    HARD_MAX_DURATION_S as RACE_HARD_MAX_DURATION_S,
)
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


def test_engine_allowlist_still_empty_slice8():
    assert ENGINE_ALLOWLIST == {}


def test_race_toctou_hard_caps_untouched():
    assert RACE_HARD_MAX_WORKERS == 4
    assert RACE_HARD_MAX_REQUESTS == 20
    assert RACE_HARD_MAX_DURATION_S == 5.0


def test_pack_listed_needs_roles_0():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "csrf_state" in manifests
    m = manifests["csrf_state"]
    assert m.needs_roles == 0
    assert m.pack_class == "csrf_state"
    assert m.version == "0"
    for pid in (
        "ato_oauth_oidc",
        "bola_idor_bfla",
        "business_logic",
        "race_toctou",
        "graphql",
        "xss_dom",
    ):
        assert pid in manifests


def test_discover_seven_packs():
    packs = discover_packs()
    assert set(packs) >= {
        "csrf_state",
        "xss_dom",
        "graphql",
        "ato_oauth_oidc",
        "bola_idor_bfla",
        "business_logic",
        "race_toctou",
    }
    assert callable(packs["csrf_state"]["run"])


def test_resolve_caps_defaults_under_maxima():
    caps = resolve_caps()
    assert caps.max_requests <= HARD_MAX_REQUESTS
    assert caps.max_requests == DEFAULT_REQUESTS


def test_resolve_caps_over_limit_hard_fails():
    with pytest.raises(CsrfStateCapExceededError) as ei:
        resolve_caps(max_requests=HARD_MAX_REQUESTS + 1)
    assert "hard" in str(ei.value).lower() or "cap" in str(ei.value).lower()


def test_request_budget_refuses_past_max():
    b = RequestBudget(max_requests=2)
    assert b.try_acquire()
    assert b.try_acquire()
    assert not b.try_acquire()
    assert b.used == 2
    assert b.rejected >= 1


def test_default_fixtures_emit_needs_human():
    r = run_checks({"i_own_this": True, "fixtures": {}})
    assert r["candidates"]
    checks = {c["check"] for c in r["candidates"]}
    assert "csrf_state_missing_token" in checks
    assert "csrf_state_unbound_token" in checks
    assert "csrf_state_samesite_none_without_secure" in checks
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
        assert "evidence_signal" in stub["response"] or stub["response"].get("observed")
    assert r["hints"]
    assert any(h.get("pattern_kind") == "synchronizer_token" for h in r["hints"])
    assert any(h.get("pattern_kind") == "double_submit_cookie" for h in r["hints"])


def test_missing_csrf_requires_explicit_signal_no_spray():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "state_changing": [
                    {
                        "name": "blind-post-no-flag",
                        "url": "http://127.0.0.1/do",
                        "method": "POST",
                        "body": {"x": 1},
                        # no missing_csrf / has_csrf_token=False — must skip
                    }
                ]
            },
        }
    )
    assert not any(c["check"] == "csrf_state_missing_token" for c in r["candidates"])
    blob = " ".join(r["notes"]).lower()
    assert "spray" in blob or "explicit" in blob or "skipped" in blob


def test_missing_csrf_with_explicit_signal():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "state_changing": [
                    {
                        "name": "email-change",
                        "url": "http://127.0.0.1/account/email",
                        "method": "POST",
                        "body": {"email": "a@b.c"},
                        "csrf_present": False,
                        "expect": {"missing_csrf": True},
                    },
                    {
                        "name": "has-token",
                        "url": "http://127.0.0.1/account/email",
                        "method": "POST",
                        "body": {"email": "a@b.c", "csrf_token": "abc"},
                        "expect": {"missing_csrf": False},
                    },
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "csrf_state_missing_token"]
    assert len(hits) == 1
    assert hits[0]["verification"] == "needs_human"
    assert "missing" in hits[0]["evidence_stub"]["response"]["evidence_signal"].lower()


def test_unbound_token_fixture():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "unbound_token": [
                    {
                        "url": "http://127.0.0.1/xfer",
                        "method": "POST",
                        "token": "STATIC_DEMO",
                        "session_bound": False,
                        "reusable": True,
                        "unbound_marker": "STATIC_DEMO",
                        "expect": {"unbound": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "csrf_state_unbound_token"]
    assert len(hits) == 1
    assert hits[0]["verification"] == "needs_human"
    assert "STATIC_DEMO" in hits[0]["evidence_stub"]["response"]["evidence_signal"]


def test_samesite_none_without_secure():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "cookie_flags": [
                    {
                        "url": "http://127.0.0.1/",
                        "set_cookie": "sid=1; Path=/; SameSite=None",
                        "expect": {"samesite_none_without_secure": True},
                    },
                    {
                        "url": "http://127.0.0.1/",
                        "set_cookie": "sid=1; Path=/; SameSite=None; Secure",
                    },
                ]
            },
        }
    )
    hits = [
        c
        for c in r["candidates"]
        if c["check"] == "csrf_state_samesite_none_without_secure"
    ]
    assert len(hits) == 1
    assert "SameSite=None" in hits[0]["evidence_stub"]["response"]["set_cookie"]
    assert hits[0]["evidence_stub"]["response"]["observed"]["secure"] is False


def test_pattern_coach_hints_only():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "csrf_patterns": [
                    {
                        "pattern": "double_submit_cookie",
                        "url": "http://127.0.0.1/",
                        "cookie_name": "csrf",
                        "form_field": "csrf",
                    }
                ]
            },
        }
    )
    assert r["hints"]
    assert all(h.get("kind") == "coach_hints" for h in r["hints"])
    assert all(
        "not auto-confirmed" in (h.get("note") or "").lower()
        or "coach" in (h.get("note") or "").lower()
        for h in r["hints"]
    )
    # pattern fixtures alone should not invent missing-token findings
    assert not any(c["check"] == "csrf_state_missing_token" for c in r["candidates"])


def test_hints_for_known_patterns():
    for kind in PATTERN_KINDS:
        qs = hints_for_pattern(kind)
        assert qs
        assert isinstance(qs[0], str)


def test_live_mock_respects_hard_cap():
    calls: list = []

    def opener(payload):
        calls.append(payload)
        return {"status": 200, "body": "ok"}

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


def test_cap_over_limit_via_run_checks_raises():
    with pytest.raises(PackRunError) as ei:
        run_checks({"i_own_this": True, "max_requests": HARD_MAX_REQUESTS + 5})
    assert ei.value.exit_code == 2


def test_run_pack_emits_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("csrf-lab")
    result = run_pack("csrf_state", "csrf-lab", i_own_this=True)
    assert result["pack_id"] == "csrf_state"
    assert result["findings_emitted"] >= 1
    for e in result["events"]:
        assert e["verification"] in {"needs_human", "unverified"}
    with open_graph("csrf-lab") as g:
        for ev in g.list_by_type("FINDING"):
            payload = ev.payload or {}
            if payload.get("pack_id") == "csrf_state":
                assert payload.get("verification") in {"needs_human", "unverified"}
                assert payload.get("verified") is False


def test_oos_host_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("csrf-oos")
    scope = _write_scope("csrf-oos", ["lab.example"])
    result = run_pack(
        "csrf_state",
        "csrf-oos",
        scope_path=scope,
        fixtures={
            "state_changing": [
                {
                    "url": "https://evil.example/account",
                    "method": "POST",
                    "body": {"x": 1},
                    "csrf_present": False,
                    "expect": {"missing_csrf": True},
                }
            ],
            "unbound_token": [],
            "cookie_flags": [],
        },
    )
    assert result["findings_emitted"] == 0


def test_prior_packs_intact(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("csrf-legacy")
    scope = _write_scope("csrf-legacy", ["lab.example"])
    _write_role("csrf-legacy", "a")
    _write_role("csrf-legacy", "b")

    ato = run_pack(
        "ato_oauth_oidc",
        "csrf-legacy",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    assert ato["pack_id"] == "ato_oauth_oidc"

    bola = run_pack(
        "bola_idor_bfla",
        "csrf-legacy",
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
        "csrf-legacy",
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
        "csrf-legacy",
        i_own_this=True,
        i_understand_lab=True,
        max_workers=2,
        max_requests=6,
        max_duration=2.0,
    )
    assert race["pack_id"] == "race_toctou"
    assert race["findings_emitted"] >= 1
    assert race["caps"]["hard_max_workers"] == 4
    assert race["caps"]["hard_max_requests"] == 20

    gq = run_pack("graphql", "csrf-legacy", i_own_this=True)
    assert gq["pack_id"] == "graphql"
    assert gq["findings_emitted"] >= 1

    xss = run_pack("xss_dom", "csrf-legacy", i_own_this=True)
    assert xss["pack_id"] == "xss_dom"
    assert xss["findings_emitted"] >= 1


def test_cli_pack_list_includes_csrf_state(tmp_path, monkeypatch):
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
    assert "csrf_state" in ids
    assert "xss_dom" in ids
    assert "graphql" in ids
    assert "race_toctou" in ids
    assert "business_logic" in ids
    assert "bola_idor_bfla" in ids
    assert "ato_oauth_oidc" in ids


def test_cli_happy_lab_run_and_report(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-csrf")
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
            "csrf_state",
            "--program",
            "cli-csrf",
            "--i-own-this",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["pack_id"] == "csrf_state"
    assert data["findings_emitted"] >= 1
    for e in data["events"]:
        assert e["verification"] in {"needs_human", "unverified"}

    out = tmp_path / "csrf-report.md"
    rep = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "report",
            "cli-csrf",
            "--pack",
            "csrf_state",
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
    assert "csrf" in text.lower()


def test_export_report_pack_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("csrf-rep")
    run_pack("csrf_state", "csrf-rep", i_own_this=True)
    result = export_report("csrf-rep", pack_id="csrf_state")
    assert result["pack_id"] == "csrf_state"
    assert result["findings"] >= 1


def test_coach_constants():
    assert "csrf" in COACH_CSRF.lower() or "token" in COACH_CSRF.lower()
    assert "fixture" in COACH_CSRF.lower() or "spray" in COACH_CSRF.lower()
    assert "cap" in COACH_CAPS.lower() or "request" in COACH_CAPS.lower()
