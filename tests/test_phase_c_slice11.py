"""Phase C slice11 — jwt_session pack v0 (fixture-driven)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import PackRunError, discover_packs, list_pack_manifests, run_pack
from gungnir.packs.report import export_report
from gungnir.packs.jwt_session.caps import (
    COACH_CAPS,
    DEFAULT_REQUESTS,
    HARD_MAX_REQUESTS,
    RequestBudget,
    JwtSessionCapExceededError,
    resolve_caps,
)
from gungnir.packs.jwt_session.checks import (
    CANNOT_LIVE_IDP_EXFIL,
    COACH_JWT_SESSION,
    _decode_jwt_fixture,
    run_checks,
)
from gungnir.packs.jwt_session.hints import hints_for_pattern, PATTERN_KINDS
from gungnir.packs.race_toctou.caps import (
    HARD_MAX_REQUESTS as RACE_HARD_MAX_REQUESTS,
    HARD_MAX_WORKERS as RACE_HARD_MAX_WORKERS,
    HARD_MAX_DURATION_S as RACE_HARD_MAX_DURATION_S,
)
from sentinel_core import ENGINE_ALLOWLIST, create_program, open_graph, program_dir

# Lab fixture tokens (unsigned / demo sigs — analysis only).
LAB_ALG_NONE = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJzdWIiOiJsYWItdXNlciIsImlhdCI6MX0."
)
LAB_NO_EXP = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJsYWItdXNlciIsImlhdCI6MX0."
    "lab-sig"
)
LAB_KID = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uL2tleXMvaG1hYy5wZW0ifQ."
    "eyJzdWIiOiJsYWItdXNlciIsImV4cCI6OTk5OTk5OTk5OX0."
    "lab-sig"
)
LAB_WEAK = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJsYWItdXNlciIsImV4cCI6OTk5OTk5OTk5OX0."
    "lab-sig"
)


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


def test_engine_allowlist_still_empty_slice11():
    assert ENGINE_ALLOWLIST == {}


def test_race_toctou_hard_caps_untouched():
    assert RACE_HARD_MAX_WORKERS == 4
    assert RACE_HARD_MAX_REQUESTS == 20
    assert RACE_HARD_MAX_DURATION_S == 5.0


def test_pack_listed_needs_roles_0():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "jwt_session" in manifests
    m = manifests["jwt_session"]
    assert m.needs_roles == 0
    assert m.pack_class == "jwt_session"
    assert m.version == "0"
    for pid in (
        "ato_oauth_oidc",
        "bola_idor_bfla",
        "business_logic",
        "race_toctou",
        "graphql",
        "xss_dom",
        "csrf_state",
        "open_redirect",
        "cache_host",
    ):
        assert pid in manifests


def test_discover_ten_packs():
    packs = discover_packs()
    assert set(packs) >= {
        "jwt_session",
        "cache_host",
        "open_redirect",
        "csrf_state",
        "xss_dom",
        "graphql",
        "ato_oauth_oidc",
        "bola_idor_bfla",
        "business_logic",
        "race_toctou",
    }
    assert callable(packs["jwt_session"]["run"])


def test_resolve_caps_defaults_under_maxima():
    caps = resolve_caps()
    assert caps.max_requests <= HARD_MAX_REQUESTS
    assert caps.max_requests == DEFAULT_REQUESTS


def test_resolve_caps_over_limit_hard_fails():
    with pytest.raises(JwtSessionCapExceededError) as ei:
        resolve_caps(max_requests=HARD_MAX_REQUESTS + 1)
    assert "hard" in str(ei.value).lower() or "cap" in str(ei.value).lower()


def test_request_budget_refuses_past_max():
    b = RequestBudget(max_requests=2)
    assert b.try_acquire()
    assert b.try_acquire()
    assert not b.try_acquire()
    assert b.used == 2
    assert b.rejected >= 1


def test_decode_jwt_fixture_alg_none():
    d = _decode_jwt_fixture(LAB_ALG_NONE)
    assert d is not None
    assert d["alg"].lower() == "none"
    assert d["has_exp"] is False


def test_default_fixtures_emit_needs_human():
    r = run_checks({"i_own_this": True, "fixtures": {}})
    assert r["candidates"]
    checks = {c["check"] for c in r["candidates"]}
    assert "jwt_session_fixation" in checks
    assert "jwt_session_alg_none" in checks
    assert "jwt_session_missing_exp" in checks
    assert "jwt_session_kid_confusion" in checks
    assert "jwt_session_weak_alg" in checks
    assert "jwt_session_token_query" in checks
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
    assert any(h.get("pattern_kind") == "session_fixation" for h in r["hints"])
    assert any(h.get("pattern_kind") == "jwt_alg_none" for h in r["hints"])
    blob = " ".join(r["notes"]).lower()
    assert "idp" in blob or "exfil" in blob or "token" in blob
    assert r.get("cannot")
    assert any(
        "idp" in str(x).lower() or "exfil" in str(x).lower() for x in r["cannot"]
    )


def test_fixation_without_same_cookie_rejected():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "session_fixation": [
                    {
                        "name": "rotated-ok",
                        "url": "http://127.0.0.1/login",
                        "pre_login": {"cookies": {"session": "PRE-A"}},
                        "post_login": {"cookies": {"session": "POST-B"}},
                    }
                ]
            },
        }
    )
    assert not any(c["check"] == "jwt_session_fixation" for c in r["candidates"])
    blob = " ".join(r["notes"]).lower()
    assert "skipped" in blob or "cookie" in blob


def test_fixation_with_same_cookie_evidence():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "session_fixation": [
                    {
                        "name": "not-rotated",
                        "url": "http://127.0.0.1/login",
                        "pre_login": {"cookies": {"session": "SAME-SID"}},
                        "post_login": {"cookies": {"session": "SAME-SID"}},
                        "expect": {"fixation": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "jwt_session_fixation"]
    assert len(hits) == 1
    assert hits[0]["verification"] == "needs_human"
    sig = hits[0]["evidence_stub"]["response"]["evidence_signal"]
    assert "SAME-SID" in sig
    assert "pre" in sig.lower() or "post" in sig.lower() or "not rotated" in sig.lower()


def test_jwt_alg_none_fixture():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "jwt": [
                    {
                        "name": "alg-none",
                        "url": "http://127.0.0.1/api/me",
                        "token": LAB_ALG_NONE,
                        "expect": {"alg_none": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "jwt_session_alg_none"]
    assert len(hits) == 1
    assert hits[0]["verification"] == "needs_human"
    sig = hits[0]["evidence_stub"]["response"]["evidence_signal"]
    assert "none" in sig.lower()


def test_jwt_missing_exp_fixture():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "jwt": [
                    {
                        "url": "http://127.0.0.1/api/me",
                        "token": LAB_NO_EXP,
                        "expect": {"missing_exp": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "jwt_session_missing_exp"]
    assert len(hits) == 1
    assert hits[0]["evidence_stub"]["response"]["observed"]["has_exp"] is False


def test_jwt_kid_confusion_fixture():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "jwt": [
                    {
                        "url": "http://127.0.0.1/api/me",
                        "token": LAB_KID,
                        "expect": {"kid_confusion": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "jwt_session_kid_confusion"]
    assert len(hits) == 1
    sig = hits[0]["evidence_stub"]["response"]["evidence_signal"]
    assert "kid" in sig.lower()


def test_jwt_weak_alg_fixture():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "jwt": [
                    {
                        "url": "http://127.0.0.1/api/me",
                        "token": LAB_WEAK,
                        "expected_alg": "RS256",
                        "expect": {"weak_alg": True, "expected_alg": "RS256"},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "jwt_session_weak_alg"]
    assert len(hits) == 1
    assert hits[0]["verification"] == "needs_human"


def test_jwt_without_token_rejected():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "jwt": [
                    {
                        "url": "http://127.0.0.1/api/me",
                        # no token — must skip
                    }
                ]
            },
        }
    )
    assert not any(
        c["check"].startswith("jwt_session_") and c["check"] != "jwt_session_fixation"
        for c in r["candidates"]
        if c["check"] != "jwt_session_token_query"
    )
    # specifically no jwt_* from empty token rows
    assert not any(
        c["check"]
        in {
            "jwt_session_alg_none",
            "jwt_session_weak_alg",
            "jwt_session_missing_exp",
            "jwt_session_kid_confusion",
        }
        for c in r["candidates"]
    )
    blob = " ".join(r["notes"]).lower()
    assert "token" in blob or "skipped" in blob


def test_token_query_leak_fixture():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "token_query": [
                    {
                        "url": (
                            "http://127.0.0.1/callback?access_token="
                            + LAB_NO_EXP
                            + "&token_type=bearer"
                        ),
                        "expect": {"token_in_query": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "jwt_session_token_query"]
    assert len(hits) == 1
    assert hits[0]["verification"] == "needs_human"
    sig = hits[0]["evidence_stub"]["response"]["evidence_signal"]
    assert "query" in sig.lower()


def test_token_query_without_token_rejected():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "token_query": [
                    {
                        "url": "http://127.0.0.1/callback?code=abc",
                    }
                ]
            },
        }
    )
    assert not any(c["check"] == "jwt_session_token_query" for c in r["candidates"])


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
    create_program("jwt-lab")
    result = run_pack("jwt_session", "jwt-lab", i_own_this=True)
    assert result["pack_id"] == "jwt_session"
    assert result["findings_emitted"] >= 1
    for e in result["events"]:
        assert e["verification"] in {"needs_human", "unverified"}
    with open_graph("jwt-lab") as g:
        for ev in g.list_by_type("FINDING"):
            payload = ev.payload or {}
            if payload.get("pack_id") == "jwt_session":
                assert payload.get("verification") in {"needs_human", "unverified"}
                assert payload.get("verified") is False


def test_oos_host_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("jwt-oos")
    scope = _write_scope("jwt-oos", ["lab.example"])
    result = run_pack(
        "jwt_session",
        "jwt-oos",
        scope_path=scope,
        fixtures={
            "session_fixation": [
                {
                    "url": "https://evil.example/login",
                    "pre_login": {"cookies": {"session": "X"}},
                    "post_login": {"cookies": {"session": "X"}},
                    "expect": {"fixation": True},
                }
            ],
            "jwt": [],
            "token_query": [],
        },
    )
    assert result["findings_emitted"] == 0


def test_prior_packs_intact(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("jwt-legacy")
    scope = _write_scope("jwt-legacy", ["lab.example"])
    _write_role("jwt-legacy", "a")
    _write_role("jwt-legacy", "b")

    ato = run_pack(
        "ato_oauth_oidc",
        "jwt-legacy",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    assert ato["pack_id"] == "ato_oauth_oidc"

    bola = run_pack(
        "bola_idor_bfla",
        "jwt-legacy",
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
        "jwt-legacy",
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
        "jwt-legacy",
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

    gq = run_pack("graphql", "jwt-legacy", i_own_this=True)
    assert gq["pack_id"] == "graphql"
    assert gq["findings_emitted"] >= 1

    xss = run_pack("xss_dom", "jwt-legacy", i_own_this=True)
    assert xss["pack_id"] == "xss_dom"
    assert xss["findings_emitted"] >= 1

    csrf = run_pack("csrf_state", "jwt-legacy", i_own_this=True)
    assert csrf["pack_id"] == "csrf_state"
    assert csrf["findings_emitted"] >= 1

    ored = run_pack("open_redirect", "jwt-legacy", i_own_this=True)
    assert ored["pack_id"] == "open_redirect"
    assert ored["findings_emitted"] >= 1

    ch = run_pack("cache_host", "jwt-legacy", i_own_this=True)
    assert ch["pack_id"] == "cache_host"
    assert ch["findings_emitted"] >= 1


def test_cli_pack_list_includes_jwt_session(tmp_path, monkeypatch):
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
    assert "jwt_session" in ids
    assert "cache_host" in ids
    assert "open_redirect" in ids
    assert "csrf_state" in ids
    assert "xss_dom" in ids
    assert "graphql" in ids
    assert "race_toctou" in ids
    assert "business_logic" in ids
    assert "bola_idor_bfla" in ids
    assert "ato_oauth_oidc" in ids


def test_cli_happy_lab_run_and_report(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-jwt")
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
            "jwt_session",
            "--program",
            "cli-jwt",
            "--i-own-this",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["pack_id"] == "jwt_session"
    assert data["findings_emitted"] >= 1
    for e in data["events"]:
        assert e["verification"] in {"needs_human", "unverified"}

    out = tmp_path / "jwt-report.md"
    rep = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "report",
            "cli-jwt",
            "--pack",
            "jwt_session",
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
    assert "jwt" in text.lower() or "session" in text.lower() or "fixation" in text.lower()


def test_export_report_pack_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("jwt-rep")
    run_pack("jwt_session", "jwt-rep", i_own_this=True)
    result = export_report("jwt-rep", pack_id="jwt_session")
    assert result["pack_id"] == "jwt_session"
    assert result["findings"] >= 1


def test_coach_constants_and_cannot():
    assert "jwt" in COACH_JWT_SESSION.lower() or "session" in COACH_JWT_SESSION.lower()
    assert "idp" in CANNOT_LIVE_IDP_EXFIL.lower()
    assert "exfil" in CANNOT_LIVE_IDP_EXFIL.lower()
    assert "cap" in COACH_CAPS.lower() or "request" in COACH_CAPS.lower()


def test_no_auto_verified_ever():
    r = run_checks({"i_own_this": True, "fixtures": {}})
    assert all(c.get("auto_verified") is False for c in r["candidates"])
    assert all(c["verification"] != "VERIFIED" for c in r["candidates"])
    assert all(c["verification"] != "verified" for c in r["candidates"])
