"""Phase C slice3 — BOLA/IDOR/BFLA pack v0 (dual-role fixtures)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import (
    PackRunError,
    discover_packs,
    export_report,
    list_pack_manifests,
    render_report_markdown,
    run_pack,
)
from gungnir.packs.bola_idor_bfla.checks import run_checks
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


def _lab_fixtures() -> dict:
    return {
        "horizontal_idor": [
            {
                "url": "https://lab.example/api/objects/obj-b",
                "object_id_a": "obj-a",
                "object_id_b": "obj-b",
                "role_a_on_b": {
                    "method": "GET",
                    "status": 200,
                    "body": '{"owner":"b","secret":"b-data"}',
                },
                "role_b_on_b": {
                    "method": "GET",
                    "status": 200,
                    "body": '{"owner":"b","secret":"b-data"}',
                },
                "role_a_on_a": {
                    "method": "GET",
                    "status": 200,
                    "body": '{"owner":"a","secret":"a-data"}',
                },
                "expect": {"idor": True},
            }
        ],
        "vertical_bfla": [
            {
                "url": "https://lab.example/admin/users",
                "role_a": {
                    "method": "GET",
                    "status": 200,
                    "body": '[{"id":1,"email":"admin@lab.example"}]',
                },
                "role_b_admin": {
                    "method": "GET",
                    "status": 200,
                    "body": '[{"id":1,"email":"admin@lab.example"}]',
                },
                "expect": {"bfla": True},
            }
        ],
        "sibling_methods": [
            {
                "url": "https://lab.example/api/objects/1",
                "get_response": {"status": 200, "body": '{"id":1}'},
                "probe_method": "DELETE",
                "probe_response": {"status": 200, "body": "deleted"},
                "expected_deny_statuses": [401, 403, 405],
                "expect": {"method_confusion": True},
            }
        ],
    }


def test_engine_allowlist_still_empty_slice3():
    assert ENGINE_ALLOWLIST == {}


def test_pack_listed_needs_roles_2():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "bola_idor_bfla" in manifests
    m = manifests["bola_idor_bfla"]
    assert m.needs_roles == 2
    assert m.pack_class == "bola_idor"
    assert m.version == "0"
    assert "ato_oauth_oidc" in manifests
    assert manifests["ato_oauth_oidc"].needs_roles == 1


def test_discover_both_packs():
    packs = discover_packs()
    assert "bola_idor_bfla" in packs
    assert "ato_oauth_oidc" in packs
    assert callable(packs["bola_idor_bfla"]["run"])


def test_fail_closed_without_role_b(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bola-no-b")
    _write_scope("bola-no-b", ["lab.example"])
    _write_role("bola-no-b", "a")
    with pytest.raises(PackRunError) as ei:
        run_pack(
            "bola_idor_bfla",
            "bola-no-b",
            i_own_this=True,
            fixtures=_lab_fixtures(),
        )
    msg = str(ei.value)
    assert "Role B" in msg or "role b" in msg.lower() or "B" in msg
    assert "fail" in msg.lower() or "missing" in msg.lower() or "closed" in msg.lower()
    assert ei.value.exit_code != 0


def test_fail_closed_without_any_roles(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bola-no-roles")
    with pytest.raises(PackRunError) as ei:
        run_pack("bola_idor_bfla", "bola-no-roles", i_own_this=True)
    msg = str(ei.value).lower()
    assert "role" in msg
    assert ei.value.exit_code != 0


def test_cli_fail_closed_without_role_b(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    create_program("cli-bola-no-b")
    _write_role("cli-bola-no-b", "a")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "pack",
            "run",
            "bola_idor_bfla",
            "--program",
            "cli-bola-no-b",
            "--i-own-this",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stderr + proc.stdout).lower()
    assert "role" in blob


def test_happy_path_fixtures_emit_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bola-ok")
    scope = _write_scope("bola-ok", ["lab.example"])
    _write_role("bola-ok", "a")
    _write_role("bola-ok", "b")

    result = run_pack(
        "bola_idor_bfla",
        "bola-ok",
        scope_path=scope,
        fixtures=_lab_fixtures(),
    )
    assert result["pack_id"] == "bola_idor_bfla"
    assert sorted(result["roles_loaded"]) == ["a", "b"]
    assert result["findings_emitted"] >= 3
    for e in result["events"]:
        cl = e["checklist"]
        for key in ("in_scope", "reproducible", "impact", "evidence_attached"):
            assert key in cl
        assert cl["in_scope"] is True
        assert cl["evidence_attached"] is True
        assert e["verification"] in {
            "confirmed",
            "unverified",
            "skipped",
            "not_reproduced",
            "needs_human",
            "verified",
        }

    with open_graph("bola-ok") as g:
        findings = g.list_by_type("FINDING")
        assert any(
            (ev.payload or {}).get("pack_id") == "bola_idor_bfla" for ev in findings
        )


def test_checks_horizontal_vertical_sibling_unit():
    r = run_checks({"i_own_this": True, "roles": {"a": object(), "b": object()}, "fixtures": _lab_fixtures()})
    by_check = {c["check"]: c for c in r["candidates"]}
    assert "horizontal_idor_confirmed" in by_check
    assert "vertical_bfla_confirmed" in by_check
    assert "sibling_method_confusion_confirmed" in by_check
    for c in r["candidates"]:
        assert c["evidence_stub"]["request"]["url"]
        assert "response" in c["evidence_stub"]
        assert c["checklist"]["evidence_attached"] is True


def test_oos_hard_kill_filters_candidates(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bola-oos")
    scope = _write_scope("bola-oos", ["in-scope.example"])
    _write_role("bola-oos", "a")
    _write_role("bola-oos", "b")

    oos_fixtures = {
        "horizontal_idor": [
            {
                "url": "https://evil-out.example/api/objects/x",
                "role_a_on_b": {"status": 200, "body": "secret"},
                "role_b_on_b": {"status": 200, "body": "secret"},
                "expect": {"idor": True},
            }
        ]
    }
    result = run_pack(
        "bola_idor_bfla",
        "bola-oos",
        scope_path=scope,
        fixtures=oos_fixtures,
    )
    assert result["findings_emitted"] == 0


def test_sibling_denied_no_finding():
    r = run_checks(
        {
            "i_own_this": True,
            "roles": {"a": 1, "b": 1},
            "fixtures": {
                "sibling_methods": [
                    {
                        "url": "https://lab.example/api/objects/1",
                        "probe_method": "DELETE",
                        "probe_response": {"status": 403, "body": "forbidden"},
                        "expected_deny_statuses": [401, 403, 405],
                    }
                ]
            },
        }
    )
    assert r["candidates"] == []


def test_ato_pack_still_runnable(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("ato-still")
    scope = _write_scope("ato-still", ["lab.example"])
    _write_role("ato-still", "a")
    result = run_pack(
        "ato_oauth_oidc",
        "ato-still",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    assert result["pack_id"] == "ato_oauth_oidc"
    assert "a" in result["roles_loaded"]
    assert "b" not in result["roles_loaded"]


def test_cli_pack_list_includes_bola(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
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
    assert "bola_idor_bfla" in ids
    assert "ato_oauth_oidc" in ids
    bola = next(p for p in data["packs"] if p["id"] == "bola_idor_bfla")
    assert bola["needs_roles"] == 2


def test_report_pack_bola(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bola-rpt")
    scope = _write_scope("bola-rpt", ["lab.example"])
    _write_role("bola-rpt", "a")
    _write_role("bola-rpt", "b")
    run_pack(
        "bola_idor_bfla",
        "bola-rpt",
        scope_path=scope,
        fixtures=_lab_fixtures(),
    )
    md = render_report_markdown("bola-rpt", pack_id="bola_idor_bfla")
    assert "# Hunt report" in md
    assert "### Steps to Reproduce" in md
    out = tmp_path / "bola.md"
    meta = export_report("bola-rpt", pack_id="bola_idor_bfla", output=out)
    assert meta["findings"] >= 1
    assert out.is_file()


def test_role_a_and_b_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bola-paths")
    scope = _write_scope("bola-paths", ["lab.example"])
    a = tmp_path / "custom-a.json"
    b = tmp_path / "custom-b.json"
    a.write_text(json.dumps({"bearer": "token-a"}), encoding="utf-8")
    b.write_text(json.dumps({"bearer": "token-b"}), encoding="utf-8")
    result = run_pack(
        "bola_idor_bfla",
        "bola-paths",
        scope_path=scope,
        role_a_path=a,
        role_b_path=b,
        fixtures=_lab_fixtures(),
    )
    assert result["findings_emitted"] >= 1
    assert sorted(result["roles_loaded"]) == ["a", "b"]
