"""Phase C slice5 — race_toctou pack with hard caps (lab-first scaffolding)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import PackRunError, discover_packs, list_pack_manifests, run_pack
from gungnir.packs.race_toctou.caps import (
    COACH_LAB_FIRST,
    HARD_MAX_DURATION_S,
    HARD_MAX_REQUESTS,
    HARD_MAX_WORKERS,
    CapExceededError,
    assert_target_allowed,
    resolve_caps,
)
from gungnir.packs.race_toctou.checks import run_checks
from gungnir.packs.race_toctou.fixture_mock import RequestBudget, run_fixture_race
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


def test_engine_allowlist_still_empty_slice5():
    assert ENGINE_ALLOWLIST == {}


def test_pack_listed_needs_roles_1():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "race_toctou" in manifests
    m = manifests["race_toctou"]
    assert m.needs_roles == 1
    assert m.pack_class == "race_toctou"
    assert m.version == "0"
    assert "ato_oauth_oidc" in manifests
    assert "bola_idor_bfla" in manifests
    assert "business_logic" in manifests


def test_discover_four_packs():
    packs = discover_packs()
    assert set(packs) >= {
        "race_toctou",
        "ato_oauth_oidc",
        "bola_idor_bfla",
        "business_logic",
    }
    assert callable(packs["race_toctou"]["run"])


def test_resolve_caps_defaults_under_maxima():
    caps = resolve_caps()
    assert caps.workers <= HARD_MAX_WORKERS
    assert caps.max_requests <= HARD_MAX_REQUESTS
    assert caps.max_duration_s <= HARD_MAX_DURATION_S


@pytest.mark.parametrize(
    "kwargs",
    [
        {"workers": HARD_MAX_WORKERS + 1},
        {"max_requests": HARD_MAX_REQUESTS + 1},
        {"max_duration": HARD_MAX_DURATION_S + 0.1},
        {"workers": 99, "i_understand_lab": True},
        {"max_requests": 1000, "i_understand_lab": True},
        {"max_duration": 60, "i_understand_lab": True},
    ],
)
def test_resolve_caps_over_limit_hard_fails(kwargs):
    with pytest.raises(CapExceededError) as ei:
        resolve_caps(**kwargs)
    msg = str(ei.value)
    assert "hard cap" in msg.lower()
    assert "lab-first" in msg


def test_assert_open_internet_triple_gate():
    with pytest.raises(CapExceededError) as ei:
        assert_target_allowed(
            "https://bank.example/transfer",
            scope_present=True,
            i_own_this=True,
            i_understand_lab=False,
            fixtures_only=False,
        )
    assert "lab-first" in str(ei.value)
    assert_target_allowed(
        "https://bank.example/transfer",
        scope_present=True,
        i_own_this=True,
        i_understand_lab=True,
        fixtures_only=False,
    )


def test_request_budget_refuses_past_max():
    b = RequestBudget(3)
    assert b.try_acquire()
    assert b.try_acquire()
    assert b.try_acquire()
    assert not b.try_acquire()
    assert b.used == 3
    assert b.rejected >= 1


def test_fixture_race_respects_caps():
    caps = resolve_caps(
        workers=2, max_requests=6, max_duration=2.0, i_understand_lab=True
    )
    obs = run_fixture_race(
        {
            "kind": "coupon_toctou",
            "name": "unit",
            "uses_left": 1,
            "force_candidate_signal": True,
        },
        caps,
    )
    assert obs["requests_used"] <= 6
    assert obs["workers_used"] == 2
    assert obs["candidate_signal"] is True


def test_checks_emit_needs_human_only():
    r = run_checks({"i_own_this": True, "i_understand_lab": True, "fixtures": {}})
    assert r["candidates"]
    assert r.get("caps")
    assert r["caps"]["workers"] <= HARD_MAX_WORKERS
    for c in r["candidates"]:
        assert c["verification"] == "needs_human"
        assert c.get("auto_verified") is False
        hints = c.get("coach_hints") or []
        assert any("lab-first" in h for h in hints)


def test_checks_over_limit_raises_pack_run_error():
    with pytest.raises(PackRunError) as ei:
        run_checks({"i_own_this": True, "max_workers": 99})
    assert ei.value.exit_code != 0
    assert "lab-first" in str(ei.value)


def test_fail_closed_without_role_a(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("race-no-a")
    with pytest.raises(PackRunError) as ei:
        run_pack("race_toctou", "race-no-a", i_own_this=True)
    assert "role" in str(ei.value).lower()


def test_happy_path_fixture_default(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("race-ok")
    _write_role("race-ok", "a")
    result = run_pack(
        "race_toctou",
        "race-ok",
        i_own_this=True,
        i_understand_lab=True,
        max_workers=2,
        max_requests=8,
        max_duration=2.0,
    )
    assert result["pack_id"] == "race_toctou"
    assert result["findings_emitted"] >= 1
    assert result["caps"]["workers"] == 2
    assert result["caps"]["max_requests"] == 8
    for e in result["events"]:
        assert e["verification"] == "needs_human"
    with open_graph("race-ok") as g:
        findings = g.list_by_type("FINDING")
        assert any(
            (ev.payload or {}).get("pack_id") == "race_toctou" for ev in findings
        )
        assert all(
            (ev.payload or {}).get("verification") == "needs_human" for ev in findings
        )


def test_run_pack_over_limit_hard_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("race-cap")
    _write_role("race-cap", "a")
    with pytest.raises(PackRunError) as ei:
        run_pack(
            "race_toctou",
            "race-cap",
            i_own_this=True,
            max_workers=HARD_MAX_WORKERS + 1,
        )
    assert "hard cap" in str(ei.value).lower() or "lab-first" in str(ei.value)


def test_open_internet_refused_without_lab_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("race-inet")
    scope = _write_scope("race-inet", ["app.example"])
    _write_role("race-inet", "a")
    with pytest.raises(PackRunError) as ei:
        run_pack(
            "race_toctou",
            "race-inet",
            scope_path=scope,
            i_own_this=True,
            i_understand_lab=False,
            urls=["https://app.example/wallet/withdraw"],
        )
    assert "open-internet" in str(ei.value).lower() or "lab-first" in str(ei.value)


def test_open_internet_allowed_with_triple_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("race-inet-ok")
    scope = _write_scope("race-inet-ok", ["app.example"])
    _write_role("race-inet-ok", "a")
    result = run_pack(
        "race_toctou",
        "race-inet-ok",
        scope_path=scope,
        i_own_this=True,
        i_understand_lab=True,
        urls=["https://app.example/wallet/withdraw"],
        fixtures={
            "race_scenarios": [
                {
                    "name": "scoped-coupon",
                    "kind": "coupon_toctou",
                    "url": "https://app.example/coupon",
                    "host": "app.example",
                    "uses_left": 1,
                    "force_candidate_signal": True,
                }
            ]
        },
    )
    assert result["pack_id"] == "race_toctou"
    assert result["findings_emitted"] >= 1


def test_prior_packs_intact(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("race-legacy")
    scope = _write_scope("race-legacy", ["lab.example"])
    _write_role("race-legacy", "a")
    _write_role("race-legacy", "b")

    ato = run_pack(
        "ato_oauth_oidc",
        "race-legacy",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    assert ato["pack_id"] == "ato_oauth_oidc"

    bola = run_pack(
        "bola_idor_bfla",
        "race-legacy",
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
        "race-legacy",
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


def test_cli_pack_list_includes_race(tmp_path, monkeypatch):
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
    assert "race_toctou" in ids
    assert "business_logic" in ids
    assert "bola_idor_bfla" in ids
    assert "ato_oauth_oidc" in ids


def test_cli_over_limit_hard_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-race-cap")
    _write_role("cli-race-cap", "a")
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
            "race_toctou",
            "--program",
            "cli-race-cap",
            "--i-own-this",
            "--max-workers",
            "99",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stdout + proc.stderr).lower()
    assert "hard cap" in blob or "lab-first" in blob


def test_cli_happy_lab_run(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-race-ok")
    _write_role("cli-race-ok", "a")
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
            "race_toctou",
            "--program",
            "cli-race-ok",
            "--i-own-this",
            "--i-understand-lab",
            "--max-workers",
            "2",
            "--max-requests",
            "8",
            "--max-duration",
            "2",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["pack_id"] == "race_toctou"
    assert data["findings_emitted"] >= 1
    assert data["caps"]["workers"] == 2
    for e in data["events"]:
        assert e["verification"] == "needs_human"


def test_coach_message_constant():
    assert "lab-first" in COACH_LAB_FIRST
    assert "written authorization" in COACH_LAB_FIRST
    assert "rate limits" in COACH_LAB_FIRST


def test_assert_fixtures_only_skips_host_gate():
    assert_target_allowed(
        "https://anywhere.example/",
        scope_present=False,
        i_own_this=False,
        i_understand_lab=False,
        fixtures_only=True,
    )


def test_lab_local_allowed_with_i_own_this():
    assert_target_allowed(
        "http://127.0.0.1/lab/race",
        scope_present=False,
        i_own_this=True,
        i_understand_lab=False,
        fixtures_only=False,
    )
