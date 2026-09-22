"""Phase C slice6 — graphql pack v0 (fixture-driven, Role A optional)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from gungnir.packs import PackRunError, discover_packs, list_pack_manifests, run_pack
from gungnir.packs.graphql.caps import (
    COACH_CAPS,
    DEFAULT_REQUESTS,
    HARD_MAX_REQUESTS,
    GraphqlCapExceededError,
    RequestBudget,
    resolve_caps,
)
from gungnir.packs.graphql.checks import COACH_GRAPHQL, run_checks
from gungnir.packs.report import export_report
from gungnir.packs.roles import coach_optional_role_a_missing_graphql
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


def test_engine_allowlist_still_empty_slice6():
    assert ENGINE_ALLOWLIST == {}


def test_pack_listed_needs_roles_0():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "graphql" in manifests
    m = manifests["graphql"]
    assert m.needs_roles == 0
    assert m.pack_class == "graphql"
    assert m.version == "0"
    # prior packs intact
    assert "ato_oauth_oidc" in manifests
    assert "bola_idor_bfla" in manifests
    assert "business_logic" in manifests
    assert "race_toctou" in manifests


def test_discover_five_packs():
    packs = discover_packs()
    assert set(packs) >= {
        "graphql",
        "ato_oauth_oidc",
        "bola_idor_bfla",
        "business_logic",
        "race_toctou",
    }
    assert callable(packs["graphql"]["run"])


def test_resolve_caps_defaults_under_maxima():
    caps = resolve_caps()
    assert caps.max_requests <= HARD_MAX_REQUESTS
    assert caps.max_requests == DEFAULT_REQUESTS


def test_resolve_caps_over_limit_hard_fails():
    with pytest.raises(GraphqlCapExceededError) as ei:
        resolve_caps(max_requests=HARD_MAX_REQUESTS + 1)
    assert "hard" in str(ei.value).lower() or "cap" in str(ei.value).lower()


def test_request_budget_refuses_past_max():
    b = RequestBudget(max_requests=2)
    assert b.try_acquire()
    assert b.try_acquire()
    assert not b.try_acquire()
    assert b.used == 2
    assert b.rejected >= 1


def test_default_introspection_fixture_emits_needs_human():
    r = run_checks({"i_own_this": True, "fixtures": {}})
    assert r["candidates"]
    assert any(c["check"] == "graphql_introspection_enabled" for c in r["candidates"])
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


def test_introspection_disabled_observation_optional():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "introspection": [
                    {
                        "name": "disabled",
                        "url": "http://127.0.0.1/graphql",
                        "response": {
                            "status": 200,
                            "errors": [
                                {"message": "GraphQL introspection is not allowed"}
                            ],
                        },
                        "expect": {
                            "introspection_disabled": True,
                            "report_disabled": True,
                        },
                    }
                ]
            },
        }
    )
    assert any(c["check"] == "graphql_introspection_disabled" for c in r["candidates"])
    for c in r["candidates"]:
        assert c["verification"] in {"needs_human", "unverified"}
        assert c.get("auto_verified") is False


def test_mutation_soft_skip_without_role_a():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "mutations": [
                    {
                        "url": "http://127.0.0.1/graphql",
                        "mutation": "createUser",
                        "unauth_response": {
                            "status": 200,
                            "body": '{"data":{"createUser":{"id":"1"}}}',
                        },
                        "auth_response": {
                            "status": 200,
                            "body": '{"data":{"createUser":{"id":"1"}}}',
                        },
                        "expect": {"unauth_mutation_allowed": True},
                    }
                ]
            },
        }
    )
    assert not any("mutation" in c["check"] for c in r["candidates"])
    blob = " ".join(r["notes"]).lower()
    assert "role a" in blob
    assert "soft" in blob or "skip" in blob


def test_mutation_emits_with_role_a():
    role = SimpleNamespace(is_usable=lambda: True)
    r = run_checks(
        {
            "i_own_this": True,
            "roles": {"a": role},
            "fixtures": {
                "mutations": [
                    {
                        "url": "http://127.0.0.1/graphql",
                        "mutation": "createUser",
                        "unauth_response": {
                            "status": 200,
                            "body": '{"data":{"createUser":{"id":"1"}}}',
                        },
                        "auth_response": {
                            "status": 200,
                            "body": '{"data":{"createUser":{"id":"1"}}}',
                        },
                        "expect": {"unauth_mutation_allowed": True},
                    }
                ]
            },
        }
    )
    assert any(c["check"] == "graphql_mutation_unauth_allowed" for c in r["candidates"])
    for c in r["candidates"]:
        assert c["verification"] == "needs_human"
        assert c.get("auto_verified") is False


def test_global_id_enumeration_candidate():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "global_ids": [
                    {
                        "url": "http://127.0.0.1/graphql",
                        "samples": ["VXNlcjox", "VXNlcjoy"],
                        "responses": [
                            {
                                "status": 200,
                                "body": '{"data":{"node":{"id":"1","n":"a"}}}',
                            },
                            {
                                "status": 200,
                                "body": '{"data":{"node":{"id":"2","n":"b"}}}',
                            },
                        ],
                        "expect": {"enumerable": True},
                    }
                ]
            },
        }
    )
    assert any(
        c["check"] == "graphql_global_id_enumeration_candidate" for c in r["candidates"]
    )
    for c in r["candidates"]:
        assert c["verification"] == "needs_human"


def test_batch_alias_hints_only():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "batch_alias": [
                    {
                        "url": "http://127.0.0.1/graphql",
                        "alias_count": 40,
                        "expect": {"alias_abuse": True},
                    }
                ]
            },
        }
    )
    assert r["hints"]
    assert all(h.get("verification") == "needs_human" for h in r["hints"])
    assert not any("alias_flood" in c.get("check", "") for c in r["candidates"])


def test_checks_over_limit_raises_pack_run_error():
    with pytest.raises(PackRunError) as ei:
        run_checks({"i_own_this": True, "max_requests": HARD_MAX_REQUESTS + 5})
    assert ei.value.exit_code != 0


def test_live_mock_respects_hard_caps():
    calls: list[dict] = []

    def opener(payload):
        calls.append(payload)
        return {"status": 200, "body": '{"data":{"__typename":"Query"}}'}

    r = run_checks(
        {
            "i_own_this": True,
            "opener": opener,
            "max_requests": 3,
            "fixtures": {
                "live_mock": {
                    "calls": [
                        {"query": "{ __typename }"},
                        {"query": "{ __typename }"},
                        {"query": "{ __typename }"},
                        {"query": "{ __typename }"},
                        {"query": "{ __typename }"},
                    ]
                }
            },
        }
    )
    assert r["caps"]["max_requests"] == 3
    assert r["caps"].get("requests_used", 0) <= 3
    assert len(calls) <= 3
    assert r.get("fixtures_only") is False


def test_run_pack_without_role_a_still_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("gq-no-a")
    result = run_pack("graphql", "gq-no-a", i_own_this=True)
    assert result["pack_id"] == "graphql"
    assert result["roles_loaded"] == []
    assert result["findings_emitted"] >= 1
    notes = " ".join(result.get("pack_notes") or []).lower()
    # default introspection still ran
    for e in result["events"]:
        assert e["verification"] in {"needs_human", "unverified"}


def test_run_pack_mutation_with_role_a(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("gq-mut")
    _write_role("gq-mut", "a")
    result = run_pack(
        "graphql",
        "gq-mut",
        i_own_this=True,
        fixtures={
            "mutations": [
                {
                    "url": "http://127.0.0.1/graphql",
                    "mutation": "updateProfile",
                    "unauth_response": {
                        "status": 200,
                        "body": '{"data":{"updateProfile":{"ok":true}}}',
                    },
                    "auth_response": {
                        "status": 200,
                        "body": '{"data":{"updateProfile":{"ok":true}}}',
                    },
                    "expect": {"unauth_mutation_allowed": True},
                }
            ]
        },
    )
    assert result["pack_id"] == "graphql"
    assert "a" in result["roles_loaded"]
    assert result["findings_emitted"] >= 1
    checks = []
    with open_graph("gq-mut") as g:
        for ev in g.list_by_type("FINDING"):
            payload = ev.payload or {}
            if payload.get("pack_id") == "graphql":
                assert payload.get("verification") in {"needs_human", "unverified"}
                assert payload.get("verified") is False
                checks.append(payload.get("check"))
    assert "graphql_mutation_unauth_allowed" in checks


def test_oos_host_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("gq-oos")
    scope = _write_scope("gq-oos", ["lab.example"])
    result = run_pack(
        "graphql",
        "gq-oos",
        scope_path=scope,
        fixtures={
            "introspection": [
                {
                    "url": "https://evil.example/graphql",
                    "response": {
                        "status": 200,
                        "body": '{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                        "data": {"__schema": {"queryType": {"name": "Query"}}},
                    },
                    "expect": {"introspection_enabled": True},
                }
            ]
        },
    )
    assert result["findings_emitted"] == 0


def test_prior_packs_intact(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("gq-legacy")
    scope = _write_scope("gq-legacy", ["lab.example"])
    _write_role("gq-legacy", "a")
    _write_role("gq-legacy", "b")

    ato = run_pack(
        "ato_oauth_oidc",
        "gq-legacy",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    assert ato["pack_id"] == "ato_oauth_oidc"

    bola = run_pack(
        "bola_idor_bfla",
        "gq-legacy",
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
        "gq-legacy",
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
        "gq-legacy",
        i_own_this=True,
        i_understand_lab=True,
        max_workers=2,
        max_requests=6,
        max_duration=2.0,
    )
    assert race["pack_id"] == "race_toctou"
    assert race["findings_emitted"] >= 1


def test_cli_pack_list_includes_graphql(tmp_path, monkeypatch):
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
    assert "graphql" in ids
    assert "race_toctou" in ids
    assert "business_logic" in ids
    assert "bola_idor_bfla" in ids
    assert "ato_oauth_oidc" in ids


def test_cli_happy_lab_run_and_report(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-gq")
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
            "graphql",
            "--program",
            "cli-gq",
            "--i-own-this",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["pack_id"] == "graphql"
    assert data["findings_emitted"] >= 1
    for e in data["events"]:
        assert e["verification"] in {"needs_human", "unverified"}

    out = tmp_path / "gq-report.md"
    rep = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "report",
            "cli-gq",
            "--pack",
            "graphql",
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
    assert "graphql" in text.lower()


def test_export_report_pack_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("gq-rep")
    run_pack("graphql", "gq-rep", i_own_this=True)
    result = export_report("gq-rep", pack_id="graphql")
    assert result["pack_id"] == "graphql"
    assert result["findings"] >= 1


def test_coach_constants():
    assert "GraphQL" in COACH_GRAPHQL or "graphql" in COACH_GRAPHQL.lower()
    assert "cap" in COACH_CAPS.lower() or "request" in COACH_CAPS.lower()
    msg = coach_optional_role_a_missing_graphql()
    assert "Role A" in msg
    assert "soft" in msg.lower() or "skip" in msg.lower()


def test_manifest_needs_roles_0_allowed():
    from gungnir.packs.manifest import PackManifest

    m = PackManifest(id="x", pack_class="y", needs_roles=0)
    assert m.needs_roles == 0
    with pytest.raises(ValueError):
        PackManifest(id="x", pack_class="y", needs_roles=3)
