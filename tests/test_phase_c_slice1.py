"""Phase C slice1 — hunt pack framework + ato_oauth_oidc v0."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import (
    PackRunError,
    discover_packs,
    list_pack_manifests,
    load_role_session,
    run_pack,
)
from gungnir.packs.surface import detect_auth_surface_candidates
from sentinel_core import ENGINE_ALLOWLIST, ScopeDenied, create_program, open_graph, program_dir


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


def test_engine_allowlist_still_empty():
    assert ENGINE_ALLOWLIST == {}


def test_pack_list_includes_ato_oauth_oidc():
    manifests = list_pack_manifests()
    ids = [m.id for m in manifests]
    assert "ato_oauth_oidc" in ids
    pack = discover_packs()["ato_oauth_oidc"]
    m = pack["manifest"]
    assert m.pack_class == "ato_oauth"
    assert m.needs_roles == 1
    d = m.to_dict()
    assert d["class"] == "ato_oauth"
    assert "FINDING" in d["emits"]


def test_cli_pack_list(tmp_path, monkeypatch):
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
    assert data["count"] >= 1
    assert any(p["id"] == "ato_oauth_oidc" for p in data["packs"])


def test_run_without_role_a_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("no-role")
    _write_scope("no-role", ["lab.example"])
    with pytest.raises(PackRunError) as ei:
        run_pack(
            "ato_oauth_oidc",
            "no-role",
            i_own_this=True,
            urls=["https://lab.example/oauth/authorize?client_id=1&response_type=code"],
        )
    msg = str(ei.value).lower()
    assert "role" in msg and ("fail" in msg or "missing" in msg or "closed" in msg)
    assert ei.value.exit_code != 0


def test_cli_run_without_role_a_nonzero(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    create_program("cli-no-role")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "pack",
            "run",
            "ato_oauth_oidc",
            "--program",
            "cli-no-role",
            "--i-own-this",
            "--url",
            "https://lab.example/login",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode != 0
    assert "role" in (proc.stderr + proc.stdout).lower()


def test_run_with_role_a_mocked_emits_checklist(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("pack-ok")
    scope = _write_scope("pack-ok", ["lab.example"])
    _write_role("pack-ok", "a")

    fixtures = {
        "token_leak_responses": [
            {
                "url": "https://lab.example/oauth/callback",
                "status": 302,
                "location": "https://lab.example/app#access_token=REDACTED&token_type=bearer",
                "body": "",
                "reproducible": True,
            }
        ],
        "reset_enumeration": [
            {
                "url": "https://lab.example/forgot-password",
                "label": "known",
                "status": 200,
                "body": "If that account exists, we sent email.",
                "headers": {},
            },
            {
                "url": "https://lab.example/forgot-password",
                "label": "unknown",
                "status": 200,
                "body": "No account found for that email.",
                "headers": {},
            },
        ],
    }

    class FakeResp:
        status = 200
        headers = {"set-cookie": ""}

        def read(self):
            return b"ok"

    def fake_opener(req, timeout=15.0):  # noqa: ARG001
        return FakeResp()

    result = run_pack(
        "ato_oauth_oidc",
        "pack-ok",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=abc&response_type=code"
            "&redirect_uri=https://evil.example/cb",
            "https://lab.example/forgot-password",
            "https://lab.example/app#access_token=should_not_store_value",
        ],
        opener=fake_opener,
        fixtures=fixtures,
    )
    assert result["findings_emitted"] >= 1
    assert "a" in result["roles_loaded"]
    # checklist fields present
    for ev in result["events"]:
        cl = ev["checklist"]
        for key in ("in_scope", "reproducible", "impact", "evidence_attached"):
            assert key in cl

    with open_graph("pack-ok") as g:
        findings = [e for e in g.list_by_type("FINDING") if e.payload.get("pack_id") == "ato_oauth_oidc"]
        assert findings
        for f in findings:
            assert "checklist" in f.payload
            assert f.payload["verification"] in {
                "unverified",
                "skipped",
                "confirmed",
                "not_reproduced",
                "needs_human",
                "verified",
            }
            assert "in_scope" in f.payload
            assert "evidence_attached" in f.payload


def test_oos_url_hard_killed(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("pack-oos")
    scope = _write_scope("pack-oos", ["in-scope.example"])
    _write_role("pack-oos", "a")
    result = run_pack(
        "ato_oauth_oidc",
        "pack-oos",
        scope_path=scope,
        urls=[
            "https://evil-oos.example/oauth/authorize?client_id=1&response_type=code",
            "https://in-scope.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://evil.example/cb",
        ],
        fixtures={},
    )
    # OOS hosts must not appear on emitted findings
    for ev in result["events"]:
        assert ev.get("host") != "evil-oos.example"
        if ev.get("host"):
            assert ev["host"] == "in-scope.example"


def test_surface_heuristics_detect_kinds():
    cands = detect_auth_surface_candidates(
        [
            "https://a.example/oauth/authorize?client_id=1",
            "https://a.example/static/logo.png",
            "https://a.example/forgot-password",
            "https://a.example/saml/acs",
            "https://a.example/magic-link/verify",
        ]
    )
    urls = {c["url"] for c in cands}
    assert "https://a.example/static/logo.png" not in urls
    kinds = {k for c in cands for k in c["kinds"]}
    assert "oauth_authorize" in kinds or "login" in kinds or "auth_surface" in kinds
    assert any("password_reset" in c["kinds"] or "reset" in c["path"] for c in cands)


def test_role_session_load(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("roles-lab")
    _write_role("roles-lab", "a", bearer="tok")
    s = load_role_session("roles-lab", "a")
    assert s.is_usable()
    hdrs = s.as_request_headers()
    assert "Authorization" in hdrs
    assert "Cookie" in hdrs


def test_pack_requires_scope_or_lab(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("pack-scope")
    _write_role("pack-scope", "a")
    # empty scope.txt from create_program → require_scope_or_lab fails without i_own_this
    with pytest.raises(ScopeDenied):
        run_pack(
            "ato_oauth_oidc",
            "pack-scope",
            i_own_this=False,
            scope_path=None,
            urls=["https://lab.example/login"],
        )


def test_cli_pack_run_happy(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    create_program("cli-pack")
    _write_scope("cli-pack", ["lab.example"])
    _write_role("cli-pack", "a")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "pack",
            "run",
            "ato_oauth_oidc",
            "--program",
            "cli-pack",
            "--i-own-this",
            "--url",
            "https://lab.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://lab.example/cb",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["pack_id"] == "ato_oauth_oidc"
    assert data["findings_emitted"] >= 1
    assert data["events"][0]["checklist"]["in_scope"] is True


def test_manifest_needs_roles_validation():
    from gungnir.packs.manifest import PackManifest

    with pytest.raises(ValueError):
        PackManifest(id="x", pack_class="y", needs_roles=3)


def test_missing_pkce_and_state_candidates(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("pkce-lab")
    scope = _write_scope("pkce-lab", ["lab.example"])
    _write_role("pkce-lab", "a")
    result = run_pack(
        "ato_oauth_oidc",
        "pkce-lab",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=pub&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    checks = {e.get("title", "") + str(e) for e in result["events"]}
    blob = json.dumps(result["events"]).lower()
    assert "missing_state" in blob or "state" in blob
    assert "pkce" in blob or result["findings_emitted"] >= 1
    assert checks  # emitted something


def test_surface_from_eye_inventory(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("inv-lab")
    root = program_dir("inv-lab")
    runs = root / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    (runs / "latest.json").write_text(
        json.dumps(
            {
                "inventory": {
                    "http": [
                        {"url": "https://lab.example/login"},
                        {"url": "https://lab.example/oauth/callback"},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    scope = _write_scope("inv-lab", ["lab.example"])
    _write_role("inv-lab", "a")
    result = run_pack("ato_oauth_oidc", "inv-lab", scope_path=scope, urls=None)
    assert result["surface_candidates"] >= 1


def test_evidence_event_linked(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("evi-lab")
    scope = _write_scope("evi-lab", ["lab.example"])
    _write_role("evi-lab", "a")
    result = run_pack(
        "ato_oauth_oidc",
        "evi-lab",
        scope_path=scope,
        urls=["https://lab.example/app#id_token=x.y.z"],
        fixtures={
            "token_leak_responses": [
                {
                    "url": "https://lab.example/cb",
                    "location": "https://lab.example/#id_token=abc",
                    "status": 302,
                }
            ]
        },
    )
    assert any(e.get("evidence_id") for e in result["events"])
    with open_graph("evi-lab") as g:
        assert g.list_by_type("EVIDENCE")


def test_cli_pack_run_requires_scope_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    create_program("cli-scope")
    _write_role("cli-scope", "a")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "pack",
            "run",
            "ato_oauth_oidc",
            "--program",
            "cli-scope",
            "--url",
            "https://lab.example/login",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode != 0


def test_open_redirect_uri_star_candidate(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("redir-lab")
    scope = _write_scope("redir-lab", ["lab.example"])
    _write_role("redir-lab", "a")
    result = run_pack(
        "ato_oauth_oidc",
        "redir-lab",
        scope_path=scope,
        urls=[
            "https://lab.example/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/*&state=ok&code_challenge=x"
        ],
    )
    blob = json.dumps(result).lower()
    assert "redirect" in blob
    assert result["findings_emitted"] >= 1


def test_gungnir_readme_honesty():
    readme = Path(__file__).resolve().parents[1] / "packages" / "gungnir" / "README.md"
    text = readme.read_text(encoding="utf-8")
    assert "cannot" in text.lower()
    assert "BOLA" in text or "bola" in text.lower()
    assert "ato_oauth_oidc" in text
    docs = Path(__file__).resolve().parents[1] / "docs" / "PHASE_C_SLICE1.md"
    assert docs.is_file()
    dtext = docs.read_text(encoding="utf-8")
    assert "cannot" in dtext.lower()
    assert "ENGINE_ALLOWLIST" in dtext
