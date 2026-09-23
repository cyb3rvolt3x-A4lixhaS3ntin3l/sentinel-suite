"""Phase C slice2 — nonce/PKCE stubs, client hints, report markdown."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import (
    export_report,
    list_pack_manifests,
    render_report_markdown,
    run_pack,
)
from gungnir.packs.ato_oauth_oidc.checks import run_checks
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


def test_engine_allowlist_still_empty_slice2():
    assert ENGINE_ALLOWLIST == {}


def test_pack_version_bumped_slice2():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "ato_oauth_oidc" in manifests
    assert manifests["ato_oauth_oidc"].version == "0.2"


def test_nonce_pkce_confirmed_only_with_expect_fixture():
    url = (
        "https://lab.example/oauth/authorize?client_id=1&response_type=code"
        "&redirect_uri=https://lab.example/cb"
    )
    bare = run_checks(
        {
            "i_own_this": True,
            "surface": [
                {
                    "url": url,
                    "kinds": ["oauth_authorize"],
                    "query_keys": ["client_id", "response_type", "redirect_uri"],
                }
            ],
            "fixtures": {},
        }
    )
    for c in bare["candidates"]:
        if c["check"].endswith("_confirmed") or "confirmed" in c["check"]:
            if c["verification"] == "confirmed":
                pytest.fail(f"confirmed without expect: {c['check']}")

    proved = run_checks(
        {
            "i_own_this": True,
            "surface": [],
            "fixtures": {
                "nonce_pkce_verify": [
                    {"url": url, "expect": {"nonce_absent": True, "pkce_absent": True}}
                ]
            },
        }
    )
    proved_map = {c["check"]: c["verification"] for c in proved["candidates"]}
    assert proved_map.get("missing_nonce_confirmed") == "confirmed"
    assert proved_map.get("missing_pkce_confirmed") == "confirmed"
    for c in proved["candidates"]:
        if c["verification"] == "confirmed":
            assert c["evidence_stub"]["response"]["expect"]


def test_nonce_format_and_method_confirmed():
    bad = (
        "https://lab.example/oauth/authorize?client_id=1&response_type=code"
        "&nonce=bad!&code_challenge=short"
        "&code_challenge_method=not-a-method"
        "&redirect_uri=https://lab.example/cb"
    )
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "nonce_pkce_verify": [
                    {
                        "url": bad,
                        "expect": {
                            "nonce_format_bad": True,
                            "code_challenge_format_bad": True,
                            "code_challenge_method_bad": True,
                        },
                    }
                ]
            },
        }
    )
    checks = {c["check"]: c["verification"] for c in r["candidates"]}
    assert checks.get("nonce_format_bad_confirmed") == "confirmed"
    assert checks.get("code_challenge_format_bad_confirmed") == "confirmed"
    assert checks.get("code_challenge_method_bad_confirmed") == "confirmed"


def test_client_type_hints_low_confidence():
    r = run_checks(
        {
            "i_own_this": True,
            "fixtures": {
                "client_type_hints": [
                    {
                        "url": "https://lab.example/.well-known/openid-configuration",
                        "discovery": {
                            "token_endpoint_auth_methods_supported": ["none"]
                        },
                    },
                    {
                        "url": "https://lab.example/login",
                        "html": "<p>confidential client with client_secret</p>",
                    },
                ]
            },
        }
    )
    hints = [c for c in r["candidates"] if c["check"] == "client_type_hint"]
    assert len(hints) >= 2
    for h in hints:
        assert h["verification"] == "unverified"
        assert h["confidence"] <= 0.3
        assert h["client_type_hint"] in {
            "public_client_hint",
            "confidential_client_hint",
            "mixed_low_confidence",
        }


def test_report_markdown_steps_from_evidence_only(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("rpt-lab")
    scope = _write_scope("rpt-lab", ["lab.example"])
    _write_role("rpt-lab", "a")
    result = run_pack(
        "ato_oauth_oidc",
        "rpt-lab",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
        fixtures={
            "nonce_pkce_verify": [
                {
                    "url": (
                        "https://lab.example/oauth/authorize?client_id=1"
                        "&response_type=code&redirect_uri=https://lab.example/cb"
                    ),
                    "expect": {"pkce_absent": True, "nonce_absent": True},
                }
            ]
        },
    )
    assert result["findings_emitted"] >= 1
    assert any(e.get("evidence_id") for e in result["events"])

    md = render_report_markdown("rpt-lab", pack_id="ato_oauth_oidc")
    assert "# Hunt report" in md
    assert "## " in md
    assert "### Summary" in md
    assert "### Steps to Reproduce" in md
    assert "### Impact" in md
    assert "### Remediation" in md
    assert "Request:" in md or "Evidence summary:" in md or "no evidence" in md.lower()
    assert "as an AI" not in md.lower()

    out = tmp_path / "out.md"
    meta = export_report("rpt-lab", pack_id="ato_oauth_oidc", output=out)
    assert meta["findings"] >= 1
    assert out.is_file()
    assert "## " in out.read_text(encoding="utf-8")


def test_cli_hunt_report(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    create_program("cli-rpt")
    scope = _write_scope("cli-rpt", ["lab.example"])
    _write_role("cli-rpt", "a")
    run_pack(
        "ato_oauth_oidc",
        "cli-rpt",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    out = tmp_path / "cli-report.md"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "report",
            "cli-rpt",
            "--pack",
            "ato_oauth_oidc",
            "-o",
            str(out),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["findings"] >= 1
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "Steps to Reproduce" in text


def test_slice2_docs_and_pack_readme_honesty():
    root = Path(__file__).resolve().parents[1]
    docs = root / "docs" / "PHASE_C_SLICE2.md"
    assert docs.is_file()
    dtext = docs.read_text(encoding="utf-8")
    assert "cannot" in dtext.lower()
    assert "ENGINE_ALLOWLIST" in dtext
    assert "nonce" in dtext.lower() and "pkce" in dtext.lower()
    assert "report" in dtext.lower()

    pack_readme = (
        root
        / "packages"
        / "gungnir"
        / "src"
        / "gungnir"
        / "packs"
        / "ato_oauth_oidc"
        / "README.md"
    )
    assert pack_readme.is_file()
    pr = pack_readme.read_text(encoding="utf-8")
    assert "Can" in pr and "Cannot" in pr
    assert "BOLA" in pr or "bola" in pr.lower()

    greadme = root / "packages" / "gungnir" / "README.md"
    gt = greadme.read_text(encoding="utf-8")
    assert "cannot" in gt.lower()
    assert "BOLA" in gt or "bola" in gt.lower()
    assert "report" in gt.lower()
    assert "nonce" in gt.lower() or "PKCE" in gt


def test_run_pack_emits_confirmed_nonce_pkce(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("np-lab")
    scope = _write_scope("np-lab", ["lab.example"])
    _write_role("np-lab", "a")
    result = run_pack(
        "ato_oauth_oidc",
        "np-lab",
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
    assert result["findings_emitted"] >= 2
    with open_graph("np-lab") as g:
        findings = [
            e
            for e in g.list_by_type("FINDING")
            if e.payload.get("pack_id") == "ato_oauth_oidc"
        ]
        verifs = {f.payload.get("verification") for f in findings}
        # Pack auto-confirm is refused on graph emit (Phase C slice13) —
        # fixture-proved candidates stay needs_human until confirm-finding.
        assert "needs_human" in verifs or "unverified" in verifs
        assert "confirmed" not in verifs
        assert any(
            (f.payload or {}).get("pack_auto_confirm_refused") for f in findings
        )
