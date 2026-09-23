"""Phase C slice13 — confirm-finding harden + report polish (no new pack)."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from gungnir.packs import (
    ConfirmError,
    confirm_finding,
    list_findings,
    list_pack_manifests,
    run_pack,
)
from gungnir.packs.confirm import refuse_pack_auto_confirm
from gungnir.packs.report import export_report, render_report_markdown
from sentinel_core import ENGINE_ALLOWLIST, create_program, open_graph, program_dir


EXPECTED_PACKS = {
    "ato_oauth_oidc",
    "bola_idor_bfla",
    "business_logic",
    "cache_host",
    "csrf_state",
    "graphql",
    "http_desync",
    "jwt_session",
    "open_redirect",
    "race_toctou",
    "xss_dom",
}


def _write_role(program_id: str, role: str = "a") -> None:
    root = program_dir(program_id)
    roles = root / "roles"
    roles.mkdir(parents=True, exist_ok=True)
    (roles / f"{role}.json").write_text(
        json.dumps({"cookies": {"session": f"lab-{role}"}, "headers": {}, "bearer": None}),
        encoding="utf-8",
    )


def _write_scope(program_id: str, allow: list[str]) -> str:
    root = program_dir(program_id)
    path = root / "scope.txt"
    path.write_text("\n".join(allow) + "\n", encoding="utf-8")
    return str(path)


def _lab_fixtures() -> dict:
    return {
        "flows": [
            {
                "name": "cart-checkout",
                "url": "https://lab.example/cart",
                "steps": [
                    {"name": "cart", "url": "https://lab.example/cart", "method": "GET"},
                    {
                        "name": "checkout",
                        "url": "https://lab.example/checkout",
                        "method": "POST",
                    },
                ],
            }
        ],
        "price_tamper": [
            {
                "url": "https://lab.example/checkout",
                "listed_price": 50,
                "paid_price": 1,
                "expect": {"accepted": True},
            }
        ],
    }


def test_eleven_packs_intact_and_allowlist_empty():
    ids = {m.id for m in list_pack_manifests()}
    assert EXPECTED_PACKS <= ids
    assert len(EXPECTED_PACKS) == 11
    assert ENGINE_ALLOWLIST == {}


def test_refuse_pack_auto_confirm_helper():
    status, extra = refuse_pack_auto_confirm("confirmed")
    assert status == "needs_human"
    assert extra["pack_auto_confirm_refused"] is True
    assert extra["pack_claimed_verification"] == "confirmed"
    assert extra["human_confirmed"] is False
    status2, extra2 = refuse_pack_auto_confirm("needs_human")
    assert status2 == "needs_human"
    assert extra2 == {}


def test_confirm_requires_note(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("c13-note")
    with pytest.raises(ConfirmError, match="note"):
        confirm_finding("c13-note", "missing", status="confirmed")


def test_confirm_transitions_and_stamps(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("c13-confirm")
    scope = _write_scope("c13-confirm", ["lab.example"])
    _write_role("c13-confirm", "a")
    result = run_pack(
        "business_logic",
        "c13-confirm",
        scope_path=scope,
        fixtures=_lab_fixtures(),
    )
    assert result["findings_emitted"] >= 1
    fid = result["events"][0]["id"]
    assert result["events"][0]["verification"] in {"needs_human", "unverified"}

    out = confirm_finding(
        "c13-confirm",
        fid,
        status="confirmed",
        note="reproduced in lab",
        mark_role="a",
        who="hunter-c13",
    )
    assert out["verification"] == "confirmed"
    assert out["previous_verification"] in {"needs_human", "unverified"}
    assert out["who"] == "hunter-c13"
    assert out["note"] == "reproduced in lab"
    assert out["confirmed_at"]

    with open_graph("c13-confirm") as g:
        ev = g.get(fid)
        assert ev is not None
        assert ev.payload["verification"] == "confirmed"
        assert ev.payload["human_confirmed"] is True
        assert ev.payload["human_confirm_note"] == "reproduced in lab"
        assert ev.payload["human_confirm_by"] == "hunter-c13"
        assert ev.payload["human_confirm_at"]
        assert ev.confidence >= 0.7

    out2 = confirm_finding(
        "c13-confirm",
        fid,
        status="not_reproduced",
        note="could not reproduce on staging",
        who="hunter-c13",
    )
    assert out2["verification"] == "not_reproduced"
    assert out2["verified"] is False

    out3 = confirm_finding(
        "c13-confirm",
        fid,
        status="rejected",
        note="duplicate / out of scope",
        who="hunter-c13",
    )
    assert out3["verification"] == "rejected"

    out4 = confirm_finding(
        "c13-confirm",
        fid,
        status="skipped",
        note="deferred this finding",
        who="hunter-c13",
    )
    assert out4["verification"] == "skipped"


def test_pack_emit_refuses_auto_confirm(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("c13-refuse")
    scope = _write_scope("c13-refuse", ["lab.example"])
    _write_role("c13-refuse", "a")
    result = run_pack(
        "ato_oauth_oidc",
        "c13-refuse",
        scope_path=scope,
        urls=[],
        fixtures={
            "nonce_pkce_verify": [
                {
                    "url": (
                        "https://lab.example/oauth/authorize?client_id=1"
                        "&response_type=code&redirect_uri=https://lab.example/cb"
                    ),
                    "expect": {"pkce_absent": True},
                }
            ],
            "client_type_hints": [
                {
                    "url": "https://lab.example/.well-known/openid-configuration",
                    "discovery": {
                        "token_endpoint_auth_methods_supported": ["none"]
                    },
                }
            ],
        },
    )
    assert result["findings_emitted"] >= 1
    with open_graph("c13-refuse") as g:
        findings = [
            e
            for e in g.list_by_type("FINDING")
            if (e.payload or {}).get("pack_id") == "ato_oauth_oidc"
        ]
        assert findings
        for f in findings:
            assert f.payload.get("verification") not in {"confirmed", "verified"}
            assert f.payload.get("human_confirmed") is not True



def test_list_findings_pending(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("c13-list")
    scope = _write_scope("c13-list", ["lab.example"])
    _write_role("c13-list", "a")
    run_pack(
        "business_logic",
        "c13-list",
        scope_path=scope,
        fixtures=_lab_fixtures(),
    )
    rows = list_findings("c13-list", status="needs_human")
    assert rows
    assert all(r["verification"] in {"needs_human", "unverified"} for r in rows)
    rows_pack = list_findings(
        "c13-list", pack_id="business_logic", status="pending"
    )
    assert rows_pack


def test_report_has_scope_checklist_no_llm_steps(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("c13-report")
    scope = _write_scope("c13-report", ["lab.example"])
    _write_role("c13-report", "a")
    run_pack(
        "business_logic",
        "c13-report",
        scope_path=scope,
        fixtures=_lab_fixtures(),
    )
    md = render_report_markdown("c13-report", pack_id="business_logic")
    assert "### Summary" in md
    assert "### Scope" in md
    assert "### Steps to Reproduce" in md
    assert "### Impact" in md
    assert "### Remediation" in md
    assert "Checklist:" in md or "in_scope=" in md
    assert "as an AI" not in md.lower()

    all_md = render_report_markdown("c13-report", all_packs=True)
    assert "Findings included:" in all_md or "findings" in all_md.lower()

    out = tmp_path / "c13.md"
    meta = export_report("c13-report", pack_id="business_logic", output=out)
    assert meta["findings"] >= 1
    assert out.is_file()
    assert "### Scope" in out.read_text(encoding="utf-8")


def test_cli_findings_confirm_report(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("c13-cli")
    scope = _write_scope("c13-cli", ["lab.example"])
    _write_role("c13-cli", "a")
    result = run_pack(
        "business_logic",
        "c13-cli",
        scope_path=scope,
        fixtures=_lab_fixtures(),
    )
    fid = result["events"][0]["id"]
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "findings",
            "c13-cli",
            "--status",
            "needs_human",
            "--pack",
            "business_logic",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["count"] >= 1

    proc_bad = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "confirm-finding",
            "c13-cli",
            fid,
            "--status",
            "confirmed",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc_bad.returncode != 0

    proc_ok = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "confirm-finding",
            "c13-cli",
            fid,
            "--status",
            "confirmed",
            "--note",
            "cli lab review",
            "--who",
            "cli-hunter",
            "--mark-role",
            "a",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc_ok.returncode == 0, proc_ok.stdout + proc_ok.stderr
    conf = json.loads(proc_ok.stdout)
    assert conf["verification"] == "confirmed"
    assert conf["who"] == "cli-hunter"

    out = tmp_path / "all.md"
    proc_rep = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "report",
            "c13-cli",
            "--all-packs",
            "-o",
            str(out),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc_rep.returncode == 0, proc_rep.stdout + proc_rep.stderr
    assert out.is_file()
    body = out.read_text(encoding="utf-8")
    assert "### Scope" in body
    assert "### Steps to Reproduce" in body
