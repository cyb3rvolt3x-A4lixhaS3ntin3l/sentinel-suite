"""Phase C slice4 — business_logic assistant v0 (flow map + coach hints + human gate)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from gungnir.packs import (
    ConfirmError,
    PackRunError,
    confirm_finding,
    discover_packs,
    list_pack_manifests,
    run_pack,
)
from gungnir.packs.business_logic.checks import run_checks
from gungnir.packs.business_logic.flow_mapper import (
    infer_flow_kind,
    map_flows_from_fixtures,
    parse_html_flow_stubs,
)
from gungnir.packs.business_logic.hints import hints_for_flow_kind
from sentinel_core import (
    ENGINE_ALLOWLIST,
    EVENT_TYPES,
    create_program,
    load_scope_file,
    open_graph,
    program_dir,
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
            },
            {
                "name": "invite-accept",
                "kind": "invite_accept",
                "url": "https://lab.example/invite/token",
                "steps": [
                    {"name": "invite", "url": "https://lab.example/invite/token"},
                    {"name": "accept", "url": "https://lab.example/invite/accept"},
                ],
            },
        ],
        "html_pages": [
            {
                "url": "https://lab.example/shop",
                "html": (
                    '<form action="/cart/add" method="post"></form>'
                    '<a href="/checkout">Checkout</a>'
                ),
            }
        ],
    }


def test_engine_allowlist_still_empty_slice4():
    assert ENGINE_ALLOWLIST == {}


def test_event_types_include_flow_and_step():
    assert "FLOW" in EVENT_TYPES
    assert "STEP" in EVENT_TYPES


def test_pack_listed_needs_roles_1():
    manifests = {m.id: m for m in list_pack_manifests()}
    assert "business_logic" in manifests
    m = manifests["business_logic"]
    assert m.needs_roles == 1
    assert m.pack_class == "business_logic"
    assert m.version == "0"
    assert "ato_oauth_oidc" in manifests
    assert "bola_idor_bfla" in manifests
    assert manifests["bola_idor_bfla"].needs_roles == 2


def test_discover_three_packs():
    packs = discover_packs()
    assert "business_logic" in packs
    assert "ato_oauth_oidc" in packs
    assert "bola_idor_bfla" in packs
    assert callable(packs["business_logic"]["run"])


def test_infer_flow_kinds():
    assert (
        infer_flow_kind("shop", [{"name": "cart"}, {"name": "checkout"}])
        == "cart_checkout"
    )
    assert (
        infer_flow_kind("team", [{"path": "/invite"}, {"path": "/accept"}])
        == "invite_accept"
    )
    assert (
        infer_flow_kind("bank", [{"name": "transfer"}, {"name": "confirm"}])
        == "transfer_confirm"
    )
    assert (
        infer_flow_kind("hr", [{"name": "apply"}, {"name": "approve"}])
        == "apply_approve"
    )


def test_coach_hints_not_empty():
    for kind in (
        "cart_checkout",
        "invite_accept",
        "transfer_confirm",
        "apply_approve",
        "generic_multi_step",
    ):
        qs = hints_for_flow_kind(kind)
        assert len(qs) >= 4
        blob = " ".join(qs).lower()
        assert any(w in blob for w in ("tamper", "replay", "skip", "overflow", "privilege"))


def test_html_stub_scope_gated_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("html-scope")
    scope_path = _write_scope("html-scope", ["lab.example"])
    scope = load_scope_file(scope_path)
    rows = parse_html_flow_stubs(
        '<form action="/cart"></form><a href="/checkout">x</a>',
        base_url="https://lab.example/shop",
        scope=scope,
        i_own_this=False,
    )
    assert len(rows) == 1
    assert rows[0]["kind"] == "cart_checkout"
    assert parse_html_flow_stubs(
        '<form action="/cart"></form><a href="/checkout">x</a>',
        base_url="https://evil.example/shop",
        scope=scope,
        i_own_this=False,
    ) == []


def test_checks_emit_needs_human_only():
    r = run_checks({"i_own_this": True, "fixtures": _lab_fixtures()})
    assert r["candidates"]
    assert r["flows"]
    assert r["steps"]
    assert r["hints"]
    for c in r["candidates"]:
        assert c["verification"] in {"needs_human", "unverified"}
        assert c["verification"] not in {"confirmed", "verified"}
        assert c.get("auto_verified") is False
        assert c.get("coach_hints")
        assert c["checklist"]["evidence_attached"] is True
        assert c["reproducible"] is False


def test_fail_closed_without_role_a(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bl-no-a")
    with pytest.raises(PackRunError) as ei:
        run_pack(
            "business_logic",
            "bl-no-a",
            i_own_this=True,
            fixtures=_lab_fixtures(),
        )
    msg = str(ei.value).lower()
    assert "role" in msg
    assert ei.value.exit_code != 0


def test_happy_path_emits_flow_step_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bl-ok")
    scope = _write_scope("bl-ok", ["lab.example"])
    _write_role("bl-ok", "a")

    result = run_pack(
        "business_logic",
        "bl-ok",
        scope_path=scope,
        fixtures=_lab_fixtures(),
    )
    assert result["pack_id"] == "business_logic"
    assert result["roles_loaded"] == ["a"]
    assert result["findings_emitted"] >= 2
    assert result["flows_emitted"] >= 2
    assert result["steps_emitted"] >= 4
    for e in result["events"]:
        assert e["verification"] == "needs_human"
        assert e["checklist"]["in_scope"] is True

    with open_graph("bl-ok") as g:
        flows = g.list_by_type("FLOW")
        steps = g.list_by_type("STEP")
        findings = g.list_by_type("FINDING")
        assert len(flows) >= 2
        assert len(steps) >= 4
        assert any(
            (ev.payload or {}).get("pack_id") == "business_logic" for ev in findings
        )
        assert all(f.confidence <= 0.45 for f in flows)
        flow_ids = {f.id for f in flows}
        assert any(set(s.parents) & flow_ids for s in steps)


def test_oos_hard_kill_filters_flows(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bl-oos")
    scope = _write_scope("bl-oos", ["in-scope.example"])
    _write_role("bl-oos", "a")
    oos = {
        "flows": [
            {
                "name": "evil-cart",
                "url": "https://evil-out.example/cart",
                "steps": [
                    {"name": "cart", "url": "https://evil-out.example/cart"},
                    {"name": "checkout", "url": "https://evil-out.example/checkout"},
                ],
            }
        ]
    }
    result = run_pack(
        "business_logic",
        "bl-oos",
        scope_path=scope,
        fixtures=oos,
    )
    assert result["findings_emitted"] == 0
    assert result["flows_emitted"] == 0


def test_confirm_finding_human_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bl-confirm")
    scope = _write_scope("bl-confirm", ["lab.example"])
    _write_role("bl-confirm", "a")
    result = run_pack(
        "business_logic",
        "bl-confirm",
        scope_path=scope,
        fixtures=_lab_fixtures(),
    )
    fid = result["events"][0]["id"]
    assert result["events"][0]["verification"] == "needs_human"

    out = confirm_finding(
        "bl-confirm",
        fid,
        status="confirmed",
        note="reproduced price tamper in lab",
        mark_role="a",
    )
    assert out["verification"] == "confirmed"
    assert out["verified"] is True
    assert out["previous_verification"] == "needs_human"

    with open_graph("bl-confirm") as g:
        ev = g.get(fid)
        assert ev is not None
        assert ev.payload["verification"] == "confirmed"
        assert ev.payload["human_confirmed"] is True
        assert ev.payload.get("human_confirm_note")
        assert ev.confidence >= 0.7


def test_confirm_finding_rejects_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bl-bad-confirm")
    with pytest.raises(ConfirmError):
        confirm_finding("bl-bad-confirm", "does-not-exist")


def test_ato_and_bola_still_runnable(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("legacy-ok")
    scope = _write_scope("legacy-ok", ["lab.example"])
    _write_role("legacy-ok", "a")
    _write_role("legacy-ok", "b")

    ato = run_pack(
        "ato_oauth_oidc",
        "legacy-ok",
        scope_path=scope,
        urls=[
            "https://lab.example/oauth/authorize?client_id=1&response_type=code"
            "&redirect_uri=https://lab.example/cb"
        ],
    )
    assert ato["pack_id"] == "ato_oauth_oidc"

    bola = run_pack(
        "bola_idor_bfla",
        "legacy-ok",
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


def test_cli_pack_list_includes_business_logic(tmp_path, monkeypatch):
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
    assert "business_logic" in ids
    assert "bola_idor_bfla" in ids
    assert "ato_oauth_oidc" in ids


def test_cli_confirm_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("cli-bl-confirm")
    scope = _write_scope("cli-bl-confirm", ["lab.example"])
    _write_role("cli-bl-confirm", "a")
    result = run_pack(
        "business_logic",
        "cli-bl-confirm",
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
            "confirm-finding",
            "cli-bl-confirm",
            fid,
            "--status",
            "confirmed",
            "--note",
            "lab review",
            "--mark-role",
            "a",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["verification"] == "confirmed"
    assert data["verified"] is True


def test_map_flows_unit_fixture():
    mapped = map_flows_from_fixtures({"i_own_this": True, "fixtures": _lab_fixtures()})
    assert len(mapped["flows"]) >= 2
    assert len(mapped["steps"]) >= 4
    assert len(mapped["hints"]) >= 2
    for h in mapped["hints"]:
        assert h["questions"]
        assert "Coach hints" in (h.get("note") or "") or h.get("kind") == "coach_hints"
