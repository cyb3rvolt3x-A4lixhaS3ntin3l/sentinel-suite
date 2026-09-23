"""Phase C slice10 — cache_host pack v0 (fixture-driven)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import PackRunError, discover_packs, list_pack_manifests, run_pack
from gungnir.packs.report import export_report
from gungnir.packs.cache_host.caps import (
    COACH_CAPS,
    DEFAULT_REQUESTS,
    HARD_MAX_REQUESTS,
    RequestBudget,
    CacheHostCapExceededError,
    resolve_caps,
)
from gungnir.packs.cache_host.checks import (
    CANNOT_PRODUCTION_CDN,
    COACH_CACHE_HOST,
    run_checks,
)
from gungnir.packs.cache_host.hints import hints_for_pattern, PATTERN_KINDS
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


def test_engine_allowlist_still_empty_slice10():
    assert ENGINE_ALLOWLIST == {}


def test_race_toctou_hard_caps_untouched():
    assert RACE_HARD_MAX_WORKERS == 4
    assert RACE_HARD_MAX_REQUESTS == 20
    assert RACE_HARD_MAX_DURATION_S == 5.0


def test_pack_listed_needs_roles_0():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "cache_host" in manifests
    m = manifests["cache_host"]
    assert m.needs_roles == 0
    assert m.pack_class == "cache_host"
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
    ):
        assert pid in manifests


def test_discover_nine_packs():
    packs = discover_packs()
    assert set(packs) >= {
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
    assert callable(packs["cache_host"]["run"])


def test_resolve_caps_defaults_under_maxima():
    caps = resolve_caps()
    assert caps.max_requests <= HARD_MAX_REQUESTS
    assert caps.max_requests == DEFAULT_REQUESTS


def test_resolve_caps_over_limit_hard_fails():
    with pytest.raises(CacheHostCapExceededError) as ei:
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
    assert "cache_host_host_reflect" in checks or "cache_host_xfh_reflect" in checks
    assert "cache_host_xfs_reflect" in checks
    assert "cache_host_key_mismatch" in checks
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
    assert any(h.get("pattern_kind") == "cache_control_weakness" for h in r["hints"])
    assert any(h.get("pattern_kind") == "vary_weakness" for h in r["hints"])
    blob = " ".join(r["notes"]).lower()
    assert "cdn" in blob or "poison" in blob
    assert r.get("cannot")
    assert any("cdn" in str(x).lower() for x in r["cannot"])


def test_bare_host_header_without_evidence_rejected():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "host_reflect": [
                    {
                        "name": "bare-host-no-reflection",
                        "url": "http://127.0.0.1/app",
                        "request_headers": {"Host": "evil.example"},
                        # no body/header reflection — must skip
                    }
                ]
            },
        }
    )
    assert not any(
        c["check"] in {"cache_host_host_reflect", "cache_host_xfh_reflect"}
        for c in r["candidates"]
    )
    blob = " ".join(r["notes"]).lower()
    assert "evidence" in blob or "skipped" in blob


def test_host_reflect_with_body_evidence():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "host_reflect": [
                    {
                        "name": "host-in-canonical",
                        "url": "http://127.0.0.1/app",
                        "request_headers": {"Host": "evil.example"},
                        "response": {
                            "status": 200,
                            "headers": {"Cache-Control": "public, max-age=3600"},
                            "body": '<link rel="canonical" href="https://evil.example/app"/>',
                        },
                        "expect": {"host_reflects": True, "cacheable": True},
                    },
                    {
                        "name": "host-no-land",
                        "url": "http://127.0.0.1/safe",
                        "request_headers": {"Host": "evil.example"},
                        "response": {
                            "status": 200,
                            "headers": {"Cache-Control": "public, max-age=60"},
                            "body": "<html>ok</html>",
                        },
                    },
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "cache_host_host_reflect"]
    assert len(hits) == 1
    assert hits[0]["verification"] == "needs_human"
    sig = hits[0]["evidence_stub"]["response"]["evidence_signal"]
    assert "evil.example" in sig
    assert "header_in" in sig or "diff" in sig.lower()


def test_xfh_reflect_fixture():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "host_reflect": [
                    {
                        "url": "http://127.0.0.1/page",
                        "request_headers": {
                            "Host": "127.0.0.1",
                            "X-Forwarded-Host": "attacker.example",
                        },
                        "response": {
                            "status": 200,
                            "headers": {
                                "Cache-Control": "public, max-age=600",
                                "Location": "https://attacker.example/page",
                            },
                            "body": "ok",
                        },
                        "expect": {"xfh_reflects": True, "cacheable": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "cache_host_xfh_reflect"]
    assert len(hits) == 1
    assert hits[0]["verification"] == "needs_human"
    assert "attacker.example" in hits[0]["evidence_stub"]["response"]["evidence_signal"]


def test_scheme_reflect_fixture():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "scheme_reflect": [
                    {
                        "url": "http://127.0.0.1/login",
                        "request_headers": {
                            "Host": "127.0.0.1",
                            "X-Forwarded-Scheme": "http",
                        },
                        "response": {
                            "status": 200,
                            "headers": {"Cache-Control": "public, max-age=120"},
                            "body": '<a href="http://127.0.0.1/login">continue</a>',
                        },
                        "expect": {"scheme_reflects": True, "cacheable": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "cache_host_xfs_reflect"]
    assert len(hits) == 1
    assert hits[0]["verification"] == "needs_human"
    sig = hits[0]["evidence_stub"]["response"]["evidence_signal"]
    assert "http" in sig.lower() or "scheme" in sig.lower() or "header_in" in sig


def test_key_mismatch_fixture():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "path_confusion": [
                    {
                        "url": "http://127.0.0.1/static",
                        "path_a": "/static/../admin",
                        "path_b": "/admin",
                        "cache_key_a": "GET|/static/../admin|host=127.0.0.1",
                        "cache_key_b": "GET|/admin|host=127.0.0.1",
                        "body_a": "cached-static-poison",
                        "body_b": "real-admin",
                        "expect": {"key_mismatch": True, "path_confusion": True},
                    }
                ]
            },
        }
    )
    hits = [c for c in r["candidates"] if c["check"] == "cache_host_key_mismatch"]
    assert len(hits) == 1
    assert hits[0]["verification"] == "needs_human"
    sig = hits[0]["evidence_stub"]["response"]["evidence_signal"]
    assert "cache_key_a" in sig and "cache_key_b" in sig


def test_key_mismatch_without_keys_rejected():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "path_confusion": [
                    {
                        "url": "http://127.0.0.1/static",
                        "path_a": "/static/../admin",
                        "path_b": "/admin",
                        # no keys — must skip
                    }
                ]
            },
        }
    )
    assert not any(c["check"] == "cache_host_key_mismatch" for c in r["candidates"])
    blob = " ".join(r["notes"]).lower()
    assert "key" in blob or "skipped" in blob


def test_cache_vary_coach_hints_only():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "cache_control_vary": [
                    {
                        "pattern": "cache_control",
                        "cache_control": "public, max-age=86400",
                        "note": "Long max-age on sensitive page?",
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
    # Coach-only fixtures should not invent host_reflect findings
    assert not any(c["check"] == "cache_host_host_reflect" for c in r["candidates"])


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
    create_program("ch-lab")
    result = run_pack("cache_host", "ch-lab", i_own_this=True)
    assert result["pack_id"] == "cache_host"
    assert result["findings_emitted"] >= 1
    for e in result["events"]:
        assert e["verification"] in {"needs_human", "unverified"}
    with open_graph("ch-lab") as g:
        for ev in g.list_by_type("FINDING"):
            payload = ev.payload or {}
            if payload.get("pack_id") == "cache_host":
                assert payload.get("verification") in {"needs_human", "unverified"}
                assert payload.get("verified") is False


def test_oos_host_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ch-oos")
    scope = _write_scope("ch-oos", ["lab.example"])
    result = run_pack(
        "cache_host",
        "ch-oos",
        scope_path=scope,
        fixtures={
            "host_reflect": [
                {
                    "url": "https://evil.example/app",
                    "request_headers": {"Host": "attacker.example"},
                    "response": {
                        "status": 200,
                        "headers": {"Cache-Control": "public, max-age=60"},
                        "body": "https://attacker.example/app",
                    },
                    "expect": {"host_reflects": True, "cacheable": True},
                }
            ],
            "scheme_reflect": [],
            "path_confusion": [],
        },
    )
    assert result["findings_emitted"] == 0


def test_prior_packs_intact(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ch-legacy")
    scope = _write_scope("ch-legacy", ["lab.example"])
    _write_role("ch-legacy", "a")
    _write_role("ch-legacy", "b")

    ato = run_pack(
        "ato_oauth_oidc",
        "ch-legacy",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    assert ato["pack_id"] == "ato_oauth_oidc"

    bola = run_pack(
        "bola_idor_bfla",
        "ch-legacy",
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
        "ch-legacy",
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
        "ch-legacy",
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

    gq = run_pack("graphql", "ch-legacy", i_own_this=True)
    assert gq["pack_id"] == "graphql"
    assert gq["findings_emitted"] >= 1

    xss = run_pack("xss_dom", "ch-legacy", i_own_this=True)
    assert xss["pack_id"] == "xss_dom"
    assert xss["findings_emitted"] >= 1

    csrf = run_pack("csrf_state", "ch-legacy", i_own_this=True)
    assert csrf["pack_id"] == "csrf_state"
    assert csrf["findings_emitted"] >= 1

    ored = run_pack("open_redirect", "ch-legacy", i_own_this=True)
    assert ored["pack_id"] == "open_redirect"
    assert ored["findings_emitted"] >= 1


def test_cli_pack_list_includes_cache_host(tmp_path, monkeypatch):
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
    create_program("cli-ch")
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
            "cache_host",
            "--program",
            "cli-ch",
            "--i-own-this",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["pack_id"] == "cache_host"
    assert data["findings_emitted"] >= 1
    for e in data["events"]:
        assert e["verification"] in {"needs_human", "unverified"}

    out = tmp_path / "ch-report.md"
    rep = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "report",
            "cli-ch",
            "--pack",
            "cache_host",
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
    assert "cache" in text.lower() or "host" in text.lower()


def test_export_report_pack_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ch-rep")
    run_pack("cache_host", "ch-rep", i_own_this=True)
    result = export_report("ch-rep", pack_id="cache_host")
    assert result["pack_id"] == "cache_host"
    assert result["findings"] >= 1


def test_coach_constants_and_cannot():
    assert "cache" in COACH_CACHE_HOST.lower() or "host" in COACH_CACHE_HOST.lower()
    assert "cdn" in CANNOT_PRODUCTION_CDN.lower()
    assert "poison" in CANNOT_PRODUCTION_CDN.lower()
    assert "cap" in COACH_CAPS.lower() or "request" in COACH_CAPS.lower()
