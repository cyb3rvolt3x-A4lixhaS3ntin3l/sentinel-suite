"""Phase C slice14 — ssrf_collaborator pack v0 (owned collaborator + metadata refuse)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import PackRunError, discover_packs, list_pack_manifests, run_pack
from gungnir.packs.confirm import confirm_finding, list_findings
from gungnir.packs.report import export_report
from gungnir.packs.ssrf_collaborator.caps import (
    COACH_LAB_FIRST,
    COACH_METADATA_REFUSED,
    COACH_NON_FIXTURE_LAB,
    COACH_OPEN_INTERNET,
    DEFAULT_COLLABORATOR,
    DEFAULT_REQUESTS,
    HARD_MAX_REQUESTS,
    CapExceededError,
    RequestBudget,
    assert_collaborator_allowed,
    assert_lab_dual_flag,
    assert_metadata_refused,
    assert_target_allowed,
    is_cloud_metadata_target,
    resolve_caps,
)
from gungnir.packs.ssrf_collaborator.checks import (
    CANNOT_CLOUD_METADATA,
    COACH_SSRF,
    run_checks,
)
from gungnir.packs.ssrf_collaborator.fixture_mock import (
    analyze_fixture_scenario,
    default_lab_scenarios,
)
from gungnir.packs.ssrf_collaborator.hints import PATTERN_KINDS, hints_for_pattern
from gungnir.packs.http_desync.caps import (
    HARD_MAX_REQUESTS as DESYNC_HARD_MAX_REQUESTS,
    assert_lab_dual_flag as desync_assert_lab_dual_flag,
)
from gungnir.packs.race_toctou.caps import (
    HARD_MAX_DURATION_S as RACE_HARD_MAX_DURATION_S,
    HARD_MAX_REQUESTS as RACE_HARD_MAX_REQUESTS,
    HARD_MAX_WORKERS as RACE_HARD_MAX_WORKERS,
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


def test_engine_allowlist_still_empty_slice14():
    assert ENGINE_ALLOWLIST == {}


def test_prior_hard_caps_untouched():
    assert RACE_HARD_MAX_WORKERS == 4
    assert RACE_HARD_MAX_REQUESTS == 20
    assert RACE_HARD_MAX_DURATION_S == 5.0
    assert DESYNC_HARD_MAX_REQUESTS == 10
    desync_assert_lab_dual_flag(
        i_own_this=False, i_understand_lab=False, fixtures_only=True
    )


def test_pack_listed_needs_roles_0():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "ssrf_collaborator" in manifests
    m = manifests["ssrf_collaborator"]
    assert m.needs_roles == 0
    assert m.pack_class == "ssrf_collaborator"
    assert m.version == "0"
    for pid in PRIOR_PACKS:
        assert pid in manifests


def test_discover_twelve_packs():
    packs = discover_packs()
    assert set(packs) >= {"ssrf_collaborator", *PRIOR_PACKS}
    assert callable(packs["ssrf_collaborator"]["run"])


def test_resolve_caps_defaults_under_maxima():
    caps = resolve_caps()
    assert caps.max_requests <= HARD_MAX_REQUESTS
    assert caps.max_requests == DEFAULT_REQUESTS
    assert caps.collaborator == DEFAULT_COLLABORATOR


def test_resolve_caps_over_limit_hard_fails():
    with pytest.raises(CapExceededError) as ei:
        resolve_caps(max_requests=HARD_MAX_REQUESTS + 1)
    msg = str(ei.value).lower()
    assert "hard" in msg or "cap" in msg


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


@pytest.mark.parametrize(
    "target",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.com/",
        "169.254.169.254",
        "http://169.254.169.253/",
        "http://100.100.100.200/latest/meta-data/",
    ],
)
def test_metadata_target_detection(target):
    assert is_cloud_metadata_target(target) is True


def test_assert_metadata_refused_fail_closed():
    with pytest.raises(CapExceededError) as ei:
        assert_metadata_refused(
            "http://169.254.169.254/latest/meta-data/",
            i_understand_lab=False,
            lab_fixture_mode=False,
        )
    blob = str(ei.value).lower()
    assert "metadata" in blob or "169.254" in blob


def test_assert_metadata_refused_lab_flag_alone_not_enough():
    with pytest.raises(CapExceededError):
        assert_metadata_refused(
            "http://169.254.169.254/",
            i_understand_lab=True,
            lab_fixture_mode=False,
        )


def test_assert_metadata_allowed_with_lab_and_fixture_mode():
    assert_metadata_refused(
        "http://169.254.169.254/",
        i_understand_lab=True,
        lab_fixture_mode=True,
    )


def test_assert_collaborator_metadata_refused():
    with pytest.raises(CapExceededError) as ei:
        assert_collaborator_allowed(
            "http://169.254.169.254/ssrf",
            i_own_this=True,
            i_understand_lab=False,
            lab_fixture_mode=False,
            fixtures_only=True,
        )
    blob = str(ei.value).lower()
    assert "metadata" in blob or "169.254" in blob


def test_assert_open_internet_triple_gate():
    with pytest.raises(CapExceededError):
        assert_target_allowed(
            "https://app.example/",
            scope_present=True,
            i_own_this=True,
            i_understand_lab=False,
            fixtures_only=False,
        )
    with pytest.raises(CapExceededError) as ei:
        assert_target_allowed(
            "https://app.example/",
            scope_present=False,
            i_own_this=True,
            i_understand_lab=True,
            fixtures_only=False,
        )
    assert "open-internet" in str(ei.value).lower() or "scope" in str(ei.value).lower()
    assert_target_allowed(
        "https://app.example/",
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
    assert "i-understand-lab" in str(ei.value) or "lab-first" in str(ei.value)
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
            "http://127.0.0.1/lab/ssrf",
            scope_present=False,
            i_own_this=True,
            i_understand_lab=False,
            fixtures_only=False,
        )
    assert_target_allowed(
        "http://127.0.0.1/lab/ssrf",
        scope_present=False,
        i_own_this=True,
        i_understand_lab=True,
        fixtures_only=False,
    )


def test_fixture_analyzer_detects_collaborator_hit():
    caps = resolve_caps()
    obs = analyze_fixture_scenario(default_lab_scenarios()[0], caps)
    assert obs["candidate_signal"] is True
    assert obs["hit"]["hit"] is True
    assert obs["kind"] == "url_param"


def test_dns_rebind_default_is_coach_only():
    caps = resolve_caps()
    rebind = [s for s in default_lab_scenarios() if s["kind"] == "dns_rebind"][0]
    obs = analyze_fixture_scenario(rebind, caps)
    assert obs["dns_rebind_coach_only"] is True
    assert obs["candidate_signal"] is False


def test_default_fixtures_emit_needs_human_without_lab_flag():
    r = run_checks({"i_own_this": True, "fixtures": {}})
    assert r["fixtures_only"] is True
    assert r["candidates"]
    checks = {c["check"] for c in r["candidates"]}
    assert "ssrf_collaborator_url_param" in checks
    assert "ssrf_collaborator_header_injection" in checks
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
        assert stub["response"].get("evidence_signal") == "collaborator_callback"
        hints = c.get("coach_hints") or []
        assert any("collaborator" in h.lower() or "lab-first" in h for h in hints)
    assert r["hints"]
    assert any(h.get("pattern_kind") == "url_param" for h in r["hints"])
    assert r.get("cannot")
    assert any(
        "metadata" in str(x).lower() or "internet" in str(x).lower()
        for x in r["cannot"]
    )


def test_no_hit_no_candidate():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "ssrf_scenarios": [
                    {
                        "name": "no-callback",
                        "kind": "url_param",
                        "url": "http://127.0.0.1/lab",
                        "collaborator_callback": {
                            "received": False,
                            "outbound_url": "http://10.0.0.2/other",
                        },
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


def test_fail_closed_metadata_collaborator_via_checks():
    with pytest.raises(PackRunError) as ei:
        run_checks(
            {
                "i_own_this": True,
                "collaborator": "http://169.254.169.254/latest/meta-data/",
                "fixtures": {},
            }
        )
    msg = str(ei.value).lower()
    assert "metadata" in msg or "169.254" in msg or "attack kit" in msg


def test_fail_closed_open_internet_without_lab_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ssrf-inet")
    scope = _write_scope("ssrf-inet", ["app.example"])
    with pytest.raises(PackRunError) as ei:
        run_pack(
            "ssrf_collaborator",
            "ssrf-inet",
            scope_path=scope,
            i_own_this=True,
            i_understand_lab=False,
            urls=["https://app.example/"],
        )
    msg = str(ei.value).lower()
    assert (
        "open-internet" in msg
        or "i-understand-lab" in msg
        or "lab-first" in msg
        or "collaborator" in msg
    )


def test_fail_closed_lab_local_live_without_lab_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ssrf-local")
    with pytest.raises(PackRunError) as ei:
        run_pack(
            "ssrf_collaborator",
            "ssrf-local",
            i_own_this=True,
            i_understand_lab=False,
            urls=["http://127.0.0.1/lab/ssrf"],
        )
    assert "i-understand-lab" in str(ei.value) or "lab-first" in str(ei.value)


def test_fail_closed_live_mock_without_lab_flag():
    with pytest.raises(PackRunError) as ei:
        run_checks(
            {
                "i_own_this": True,
                "i_understand_lab": False,
                "fixtures": {"live_mock": {"calls": [{"url": "http://127.0.0.1/"}]}},
            }
        )
    assert "i-understand-lab" in str(ei.value) or "lab-first" in str(ei.value)


def test_fail_closed_open_internet_missing_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ssrf-noscope")
    with pytest.raises(PackRunError) as ei:
        run_pack(
            "ssrf_collaborator",
            "ssrf-noscope",
            i_own_this=True,
            i_understand_lab=True,
            urls=["https://app.example/"],
        )
    msg = str(ei.value).lower()
    assert "open-internet" in msg or "scope" in msg


def test_open_internet_allowed_with_triple_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ssrf-inet-ok")
    scope = _write_scope("ssrf-inet-ok", ["app.example"])
    result = run_pack(
        "ssrf_collaborator",
        "ssrf-inet-ok",
        scope_path=scope,
        i_own_this=True,
        i_understand_lab=True,
        urls=["https://app.example/"],
        fixtures={
            "ssrf_scenarios": [
                {
                    "name": "scoped-url-param",
                    "kind": "url_param",
                    "url": "https://app.example/ssrf?url=http://127.0.0.1:9/ssrf-callback",
                    "host": "app.example",
                    "collaborator_callback": {
                        "received": True,
                        "marker": "HIT",
                        "outbound_url": "http://127.0.0.1:9/ssrf-callback",
                    },
                    "expect": {"collaborator_hit": True},
                }
            ]
        },
    )
    assert result["pack_id"] == "ssrf_collaborator"
    assert result["findings_emitted"] >= 1
    for e in result["events"]:
        assert e["verification"] == "needs_human"


def test_happy_path_fixture_default(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ssrf-ok")
    result = run_pack(
        "ssrf_collaborator",
        "ssrf-ok",
        i_own_this=True,
        max_requests=6,
    )
    assert result["pack_id"] == "ssrf_collaborator"
    assert result["findings_emitted"] >= 1
    assert result["caps"]["max_requests"] == 6
    assert result["caps"]["hard_max_requests"] == 10
    for e in result["events"]:
        assert e["verification"] == "needs_human"
        assert e.get("auto_verified") is not True
    with open_graph("ssrf-ok") as g:
        findings = g.list_by_type("FINDING")
        assert any(
            (ev.payload or {}).get("pack_id") == "ssrf_collaborator" for ev in findings
        )


def test_custom_collaborator_local(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ssrf-collab")
    collab = "http://127.0.0.1:9999/my-callback"
    result = run_pack(
        "ssrf_collaborator",
        "ssrf-collab",
        i_own_this=True,
        collaborator=collab,
    )
    assert result["pack_id"] == "ssrf_collaborator"
    assert result["caps"]["collaborator"] == collab
    assert result["findings_emitted"] >= 1


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
                "live_mock": {"calls": [{"n": i} for i in range(10)]},
                "ssrf_scenarios": default_lab_scenarios()[:1],
            },
        }
    )
    assert r["caps"]["requests_used"] == 3
    assert r["caps"]["requests_rejected"] >= 1
    assert len(calls) == 3


def test_prior_packs_intact(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ssrf-legacy")
    scope = _write_scope("ssrf-legacy", ["lab.example"])
    _write_role("ssrf-legacy", "a")
    _write_role("ssrf-legacy", "b")

    ato = run_pack(
        "ato_oauth_oidc",
        "ssrf-legacy",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    assert ato["pack_id"] == "ato_oauth_oidc"

    bola = run_pack(
        "bola_idor_bfla",
        "ssrf-legacy",
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
        "ssrf-legacy",
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
        "ssrf-legacy",
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
        "http_desync",
    ):
        out = run_pack(pid, "ssrf-legacy", i_own_this=True)
        assert out["pack_id"] == pid
        assert out["findings_emitted"] >= 1


def test_cli_pack_list_includes_ssrf_collaborator(tmp_path, monkeypatch):
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
    assert "ssrf_collaborator" in ids
    assert "http_desync" in ids
    assert "race_toctou" in ids
    assert len(ids) >= 12


def test_cli_fail_closed_without_lab_flag_on_live_url(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-ssrf-gate")
    scope = _write_scope("cli-ssrf-gate", ["app.example"])
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
            "ssrf_collaborator",
            "--program",
            "cli-ssrf-gate",
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
        or "lab-first" in blob
        or "collaborator" in blob
    )


def test_cli_fail_closed_metadata_collaborator(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-ssrf-meta")
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
            "ssrf_collaborator",
            "--program",
            "cli-ssrf-meta",
            "--i-own-this",
            "--collaborator",
            "http://169.254.169.254/latest/meta-data/",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stdout + proc.stderr).lower()
    assert "metadata" in blob or "169.254" in blob or "attack kit" in blob


def test_cli_happy_fixture_and_lab_dual_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-ssrf-ok")
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
            "ssrf_collaborator",
            "--program",
            "cli-ssrf-ok",
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
    assert data["pack_id"] == "ssrf_collaborator"
    assert data["findings_emitted"] >= 1
    for e in data["events"]:
        assert e["verification"] == "needs_human"

    proc2 = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "pack",
            "run",
            "ssrf_collaborator",
            "--program",
            "cli-ssrf-ok",
            "--i-own-this",
            "--i-understand-lab",
            "--collaborator",
            "http://127.0.0.1:9999/cb",
            "--max-requests",
            "6",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc2.returncode == 0, proc2.stdout + proc2.stderr
    data2 = json.loads(proc2.stdout)
    assert data2["caps"]["collaborator"] == "http://127.0.0.1:9999/cb"


def test_cli_over_limit_hard_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-ssrf-cap")
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
            "ssrf_collaborator",
            "--program",
            "cli-ssrf-cap",
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
    assert "hard" in blob or "cap" in blob or "lab-first" in blob


def test_export_report_pack_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ssrf-report")
    run_pack("ssrf_collaborator", "ssrf-report", i_own_this=True)
    out = tmp_path / "ssrf-report.md"
    result = export_report("ssrf-report", pack_id="ssrf_collaborator", output=out)
    assert result["findings"] >= 1
    text = out.read_text(encoding="utf-8")
    assert "ssrf_collaborator" in text or "ssrf" in text.lower()


def test_confirm_report_polish_still_works(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ssrf-confirm")
    run_pack("ssrf_collaborator", "ssrf-confirm", i_own_this=True)
    rows = list_findings("ssrf-confirm", pack_id="ssrf_collaborator")
    assert rows
    fid = rows[0]["id"]
    confirmed = confirm_finding(
        "ssrf-confirm",
        fid,
        note="lab review of collaborator callback fixture",
        status="confirmed",
    )
    assert confirmed.get("status") == "confirmed" or confirmed.get("verification") in {
        "confirmed",
        "verified",
    }


def test_coach_constants():
    assert "lab-first" in COACH_LAB_FIRST
    assert "collaborator" in COACH_LAB_FIRST
    assert "collaborator" in COACH_SSRF.lower()
    assert "metadata" in CANNOT_CLOUD_METADATA.lower()
    assert "open-internet" in COACH_OPEN_INTERNET.lower()
    assert "i-understand-lab" in COACH_NON_FIXTURE_LAB
    assert "metadata" in COACH_METADATA_REFUSED.lower()
    for kind in PATTERN_KINDS:
        qs = hints_for_pattern(kind)
        assert qs
        assert any(
            "human" in q.lower() or "lab" in q.lower() or "collaborator" in q.lower()
            for q in qs
        )
