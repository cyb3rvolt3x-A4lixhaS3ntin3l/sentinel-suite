"""Phase C slice12 — http_desync pack v0 (fixture differentials + lab dual-flag)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import PackRunError, discover_packs, list_pack_manifests, run_pack
from gungnir.packs.report import export_report
from gungnir.packs.http_desync.caps import (
    COACH_LAB_FIRST,
    COACH_NON_FIXTURE_LAB,
    COACH_OPEN_INTERNET,
    DEFAULT_REQUESTS,
    HARD_MAX_REQUESTS,
    CapExceededError,
    RequestBudget,
    assert_lab_dual_flag,
    assert_target_allowed,
    resolve_caps,
)
from gungnir.packs.http_desync.checks import (
    CANNOT_PROD_SMUGGLING,
    COACH_DESYNC,
    run_checks,
)
from gungnir.packs.http_desync.fixture_mock import (
    analyze_fixture_scenario,
    default_lab_scenarios,
)
from gungnir.packs.http_desync.hints import hints_for_pattern, PATTERN_KINDS
from gungnir.packs.race_toctou.caps import (
    HARD_MAX_DURATION_S as RACE_HARD_MAX_DURATION_S,
    HARD_MAX_REQUESTS as RACE_HARD_MAX_REQUESTS,
    HARD_MAX_WORKERS as RACE_HARD_MAX_WORKERS,
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


def test_engine_allowlist_still_empty_slice12():
    assert ENGINE_ALLOWLIST == {}


def test_race_toctou_hard_caps_untouched():
    assert RACE_HARD_MAX_WORKERS == 4
    assert RACE_HARD_MAX_REQUESTS == 20
    assert RACE_HARD_MAX_DURATION_S == 5.0


def test_pack_listed_needs_roles_0():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "http_desync" in manifests
    m = manifests["http_desync"]
    assert m.needs_roles == 0
    assert m.pack_class == "http_desync"
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
        "jwt_session",
    ):
        assert pid in manifests


def test_discover_eleven_packs():
    packs = discover_packs()
    assert set(packs) >= {
        "http_desync",
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
    assert callable(packs["http_desync"]["run"])


def test_resolve_caps_defaults_under_maxima():
    caps = resolve_caps()
    assert caps.max_requests <= HARD_MAX_REQUESTS
    assert caps.max_requests == DEFAULT_REQUESTS


def test_resolve_caps_over_limit_hard_fails():
    with pytest.raises(CapExceededError) as ei:
        resolve_caps(max_requests=HARD_MAX_REQUESTS + 1)
    msg = str(ei.value).lower()
    assert "hard" in msg or "cap" in msg
    assert "lab/staging" in str(ei.value) or "written auth" in str(ei.value)


def test_resolve_caps_lab_flag_does_not_raise_ceiling():
    with pytest.raises(CapExceededError):
        resolve_caps(max_requests=99, i_understand_lab=True)


def test_request_budget_refuses_past_max():
    b = RequestBudget(max_requests=2)
    assert b.try_acquire()
    assert b.try_acquire()
    assert not b.try_acquire()
    assert b.used == 2
    assert b.rejected >= 1


def test_assert_open_internet_triple_gate():
    with pytest.raises(CapExceededError) as ei:
        assert_target_allowed(
            "https://cdn.example/",
            scope_present=True,
            i_own_this=True,
            i_understand_lab=False,
            fixtures_only=False,
        )
    assert "lab/staging" in str(ei.value) or "open-internet" in str(ei.value).lower()
    assert_target_allowed(
        "https://cdn.example/",
        scope_present=True,
        i_own_this=True,
        i_understand_lab=True,
        fixtures_only=False,
    )


def test_assert_non_fixture_requires_dual_flag():
    with pytest.raises(CapExceededError) as ei:
        assert_lab_dual_flag(
            i_own_this=True,
            i_understand_lab=False,
            fixtures_only=False,
        )
    assert "i-understand-lab" in str(ei.value) or "lab/staging" in str(ei.value)
    with pytest.raises(CapExceededError):
        assert_lab_dual_flag(
            i_own_this=False,
            i_understand_lab=True,
            fixtures_only=False,
        )
    assert_lab_dual_flag(
        i_own_this=True,
        i_understand_lab=True,
        fixtures_only=False,
    )
    assert_lab_dual_flag(
        i_own_this=False,
        i_understand_lab=False,
        fixtures_only=True,
    )


def test_assert_fixtures_only_skips_host_gate():
    assert_target_allowed(
        "https://anywhere.example/",
        scope_present=False,
        i_own_this=False,
        i_understand_lab=False,
        fixtures_only=True,
    )


def test_lab_local_beyond_fixture_needs_dual_flag():
    with pytest.raises(CapExceededError):
        assert_target_allowed(
            "http://127.0.0.1/lab/desync",
            scope_present=False,
            i_own_this=True,
            i_understand_lab=False,
            fixtures_only=False,
        )
    assert_target_allowed(
        "http://127.0.0.1/lab/desync",
        scope_present=False,
        i_own_this=True,
        i_understand_lab=True,
        fixtures_only=False,
    )


def test_fixture_analyzer_detects_differential():
    caps = resolve_caps()
    obs = analyze_fixture_scenario(default_lab_scenarios()[0], caps)
    assert obs["candidate_signal"] is True
    assert obs["diff"]["has_differential"] is True
    assert obs["kind"] == "cl_te"


def test_default_fixtures_emit_needs_human_without_lab_flag():
    """Pure fixture path must work in CI without --i-understand-lab."""
    r = run_checks({"i_own_this": True, "fixtures": {}})
    assert r["fixtures_only"] is True
    assert r["candidates"]
    checks = {c["check"] for c in r["candidates"]}
    assert "http_desync_cl_te" in checks
    assert "http_desync_te_cl" in checks
    assert "http_desync_header_smuggle" in checks
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
        assert stub["response"].get("evidence_signal") == "differential_responses"
        hints = c.get("coach_hints") or []
        assert any("lab/staging" in h for h in hints)
    assert r["hints"]
    assert any(h.get("pattern_kind") == "cl_te" for h in r["hints"])
    assert r.get("cannot")
    assert any("cdn" in str(x).lower() or "waf" in str(x).lower() for x in r["cannot"])
    blob = " ".join(r["notes"]).lower()
    assert "lab/staging" in blob or "written auth" in blob


def test_no_differential_no_candidate():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "desync_scenarios": [
                    {
                        "name": "same-both",
                        "kind": "cl_te",
                        "url": "http://127.0.0.1/lab",
                        "interpretation_a": {"status": 200, "body": "ok", "marker": "A"},
                        "interpretation_b": {"status": 200, "body": "ok", "marker": "A"},
                    }
                ]
            },
        }
    )
    assert r["candidates"] == []


def test_checks_over_limit_raises_pack_run_error():
    with pytest.raises(PackRunError) as ei:
        run_checks({"i_own_this": True, "max_requests": 99})
    assert ei.value.exit_code != 0


def test_fail_closed_open_internet_without_lab_flag(tmp_path, monkeypatch):
    """open-internet / non-lab without lab flag → fails closed."""
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("desync-inet")
    scope = _write_scope("desync-inet", ["app.example"])
    with pytest.raises(PackRunError) as ei:
        run_pack(
            "http_desync",
            "desync-inet",
            scope_path=scope,
            i_own_this=True,
            i_understand_lab=False,
            urls=["https://app.example/"],
        )
    msg = str(ei.value).lower()
    assert (
        "open-internet" in msg
        or "i-understand-lab" in msg
        or "lab/staging" in msg
        or "written auth" in msg
    )


def test_fail_closed_lab_local_live_without_lab_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("desync-local")
    with pytest.raises(PackRunError) as ei:
        run_pack(
            "http_desync",
            "desync-local",
            i_own_this=True,
            i_understand_lab=False,
            urls=["http://127.0.0.1/lab/desync"],
        )
    assert "i-understand-lab" in str(ei.value) or "lab/staging" in str(ei.value)


def test_fail_closed_live_mock_without_lab_flag():
    with pytest.raises(PackRunError) as ei:
        run_checks(
            {
                "i_own_this": True,
                "i_understand_lab": False,
                "fixtures": {"live_mock": {"calls": [{"url": "http://127.0.0.1/"}]}},
            }
        )
    assert "i-understand-lab" in str(ei.value) or "lab/staging" in str(ei.value)


def test_open_internet_allowed_with_triple_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("desync-inet-ok")
    scope = _write_scope("desync-inet-ok", ["app.example"])
    result = run_pack(
        "http_desync",
        "desync-inet-ok",
        scope_path=scope,
        i_own_this=True,
        i_understand_lab=True,
        urls=["https://app.example/"],
        fixtures={
            "desync_scenarios": [
                {
                    "name": "scoped-cl-te",
                    "kind": "cl_te",
                    "url": "https://app.example/desync",
                    "host": "app.example",
                    "interpretation_a": {"status": 200, "body": "a", "marker": "A"},
                    "interpretation_b": {"status": 404, "body": "b", "marker": "B"},
                    "expect": {"differential": True},
                }
            ]
        },
    )
    assert result["pack_id"] == "http_desync"
    assert result["findings_emitted"] >= 1
    for e in result["events"]:
        assert e["verification"] == "needs_human"


def test_happy_path_fixture_default(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("desync-ok")
    # Pure fixtures: i_own_this alone is enough (no lab flag).
    result = run_pack(
        "http_desync",
        "desync-ok",
        i_own_this=True,
        max_requests=6,
    )
    assert result["pack_id"] == "http_desync"
    assert result["findings_emitted"] >= 1
    assert result["caps"]["max_requests"] == 6
    assert result["caps"]["hard_max_requests"] == 10
    for e in result["events"]:
        assert e["verification"] == "needs_human"
        assert e.get("auto_verified") is not True
    with open_graph("desync-ok") as g:
        findings = g.list_by_type("FINDING")
        assert any(
            (ev.payload or {}).get("pack_id") == "http_desync" for ev in findings
        )


def test_live_mock_respects_hard_cap():
    calls: list[dict] = []

    def opener(call):
        calls.append(call)

    r = run_checks(
        {
            "i_own_this": True,
            "i_understand_lab": True,
            "max_requests": 3,
            "opener": opener,
            "fixtures": {
                "live_mock": {
                    "calls": [{"n": i} for i in range(10)],
                },
                "desync_scenarios": default_lab_scenarios()[:1],
            },
        }
    )
    assert r["caps"]["requests_used"] == 3
    assert r["caps"]["requests_rejected"] >= 1
    assert len(calls) == 3


def test_prior_packs_intact(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("desync-legacy")
    scope = _write_scope("desync-legacy", ["lab.example"])
    _write_role("desync-legacy", "a")
    _write_role("desync-legacy", "b")

    ato = run_pack(
        "ato_oauth_oidc",
        "desync-legacy",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    assert ato["pack_id"] == "ato_oauth_oidc"

    bola = run_pack(
        "bola_idor_bfla",
        "desync-legacy",
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
        "desync-legacy",
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
        "desync-legacy",
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

    for pid in (
        "graphql",
        "xss_dom",
        "csrf_state",
        "open_redirect",
        "cache_host",
        "jwt_session",
    ):
        out = run_pack(pid, "desync-legacy", i_own_this=True)
        assert out["pack_id"] == pid
        assert out["findings_emitted"] >= 1


def test_cli_pack_list_includes_http_desync(tmp_path, monkeypatch):
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
    assert "http_desync" in ids
    assert "jwt_session" in ids
    assert "race_toctou" in ids


def test_cli_fail_closed_without_lab_flag_on_live_url(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-desync-gate")
    scope = _write_scope("cli-desync-gate", ["app.example"])
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
            "http_desync",
            "--program",
            "cli-desync-gate",
            "--scope",
            str(scope),
            "--i-own-this",
            "--url",
            "https://app.example/",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stdout + proc.stderr).lower()
    assert (
        "open-internet" in blob
        or "i-understand-lab" in blob
        or "lab/staging" in blob
        or "written auth" in blob
    )


def test_cli_happy_fixture_and_lab_dual_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-desync-ok")
    env = dict(os.environ)
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    # Fixture-only happy path (no lab flag)
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "pack",
            "run",
            "http_desync",
            "--program",
            "cli-desync-ok",
            "--i-own-this",
            "--max-requests",
            "6",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["pack_id"] == "http_desync"
    assert data["findings_emitted"] >= 1
    for e in data["events"]:
        assert e["verification"] == "needs_human"

    # Dual-flag example path (lab mock / acknowledged)
    proc2 = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "pack",
            "run",
            "http_desync",
            "--program",
            "cli-desync-ok",
            "--i-own-this",
            "--i-understand-lab",
            "--max-requests",
            "6",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc2.returncode == 0, proc2.stdout + proc2.stderr


def test_cli_over_limit_hard_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-desync-cap")
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
            "http_desync",
            "--program",
            "cli-desync-cap",
            "--i-own-this",
            "--max-requests",
            "99",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stdout + proc.stderr).lower()
    assert "hard" in blob or "cap" in blob or "lab/staging" in blob


def test_export_report_pack_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("desync-report")
    run_pack("http_desync", "desync-report", i_own_this=True)
    out = tmp_path / "desync-report.md"
    result = export_report("desync-report", pack_id="http_desync", output=out)
    assert result["findings"] >= 1
    text = out.read_text(encoding="utf-8")
    assert "http_desync" in text or "desync" in text.lower()


def test_coach_constants():
    assert "lab/staging" in COACH_LAB_FIRST
    assert "written auth" in COACH_LAB_FIRST
    assert "lab/staging" in COACH_DESYNC
    assert "cdn" in CANNOT_PROD_SMUGGLING.lower() or "waf" in CANNOT_PROD_SMUGGLING.lower()
    assert "open-internet" in COACH_OPEN_INTERNET.lower()
    assert "i-understand-lab" in COACH_NON_FIXTURE_LAB
    for kind in PATTERN_KINDS:
        qs = hints_for_pattern(kind)
        assert qs
        assert any("human" in q.lower() or "lab" in q.lower() for q in qs)
