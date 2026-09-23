"""http_desync checks — fixture-driven CL.TE / TE.CL / header-smuggle evidence.

Defensive scaffolding ONLY:
- Default refuse open-internet targets
- Beyond pure fixtures: BOTH --i-own-this AND --i-understand-lab
- Prefer 127.0.0.1 / in-process fixture differentials (no live smuggle)
- Hard request caps ≤10 for any non-pure-fixture path
- Findings always needs_human; never auto-VERIFIED
- Cannot: production CDN/WAF smuggling, DoS/flood, open-internet without dual lab flag
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from gungnir.packs.http_desync.caps import (
    COACH_LAB_FIRST,
    HARD_MAX_REQUESTS,
    CapExceededError,
    RequestBudget,
    assert_lab_dual_flag,
    assert_target_allowed,
    host_of,
    is_lab_local_host,
    resolve_caps,
)
from gungnir.packs.http_desync.fixture_mock import (
    analyze_fixture_scenario,
    default_lab_scenarios,
)
from gungnir.packs.http_desync.hints import build_hint_record, hints_for_pattern
from gungnir.packs.manifest import finding_gate_checklist
from gungnir.packs.runner import PackRunError
from sentinel_core import ScopeDenied

_AUTO_STATUSES = frozenset({"needs_human", "unverified"})

COACH_DESYNC = (
    "desync is lab/staging; production needs written auth + careful coordination. "
    "Evidence = differential response markers across ambiguous request "
    "interpretations (CL.TE / TE.CL / header-smuggle). Fixture-driven only by "
    "default — not a production smuggling weapon."
)

CANNOT_PROD_SMUGGLING = (
    "Cannot: production CDN/WAF smuggling campaigns, DoS/flood, live desync "
    "weaponization against open-internet hosts without written auth + "
    "--i-own-this AND --i-understand-lab (and --scope for open-internet). "
    "Lab/staging fixture evidence only."
)


def _scenarios_from_fixtures(fixtures: dict[str, Any]) -> list[dict[str, Any]]:
    raw = (
        fixtures.get("desync_scenarios")
        or fixtures.get("http_desync")
        or fixtures.get("scenarios")
        or []
    )
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            out.append(dict(item))
    # Also accept typed lists
    for key, kind in (
        ("cl_te", "cl_te"),
        ("te_cl", "te_cl"),
        ("header_smuggle", "header_smuggle"),
    ):
        for item in fixtures.get(key) or []:
            if isinstance(item, dict):
                row = dict(item)
                row.setdefault("kind", kind)
                out.append(row)
    return out


def _live_urls(ctx: dict[str, Any]) -> list[str]:
    urls = list(ctx.get("urls") or [])
    fixtures = ctx.get("fixtures") or {}
    for u in fixtures.get("target_urls") or []:
        if isinstance(u, str) and u.strip():
            urls.append(u.strip())
    return urls


def _has_live_mock(ctx: dict[str, Any]) -> bool:
    fixtures = ctx.get("fixtures") or {}
    return bool(ctx.get("opener") or fixtures.get("live_mock"))


def _candidate_from_obs(obs: dict[str, Any]) -> dict[str, Any]:
    host = str(obs.get("host") or "127.0.0.1")
    url = str(obs.get("url") or f"http://{host}/lab/desync")
    kind = str(obs.get("kind") or "desync")
    verification = "needs_human"
    diff = obs.get("diff") or {}
    title = (
        f"HTTP desync candidate ({kind}): "
        f"{obs.get('name') or host} — {obs.get('signal_reason') or 'differential'}"
    )
    coach = [COACH_DESYNC, COACH_LAB_FIRST] + hints_for_pattern(kind)[:3]
    return {
        "title": title,
        "host": host,
        "url": url,
        "check": f"http_desync_{kind}",
        "verification": verification,
        "confidence": 0.3,
        "impact": "http_desync_review_candidate",
        "reproducible": False,
        "in_scope": True,
        "evidence_attached": True,
        "human_gate": True,
        "auto_verified": False,
        "coach_hints": coach,
        "caps": {
            "max_requests": obs.get("max_requests"),
            "requests_used": obs.get("requests_used"),
        },
        "evidence_summary": (
            f"Fixture desync differential kind={kind} signal={obs.get('signal_reason')} "
            f"status_diff={diff.get('status_diff')} body_diff={diff.get('body_diff')} "
            f"marker_diff={diff.get('marker_diff')} — awaiting human confirm "
            f"(verification={verification})"
        ),
        "evidence_stub": {
            "check": f"http_desync_{kind}",
            "response": {
                "evidence_signal": "differential_responses",
                "diff": {
                    k: diff.get(k)
                    for k in (
                        "status_diff",
                        "body_diff",
                        "header_diffs",
                        "marker_diff",
                        "marker_a",
                        "marker_b",
                        "has_differential",
                    )
                    if diff.get(k) is not None
                },
                "interpretation_a": obs.get("interpretation_a"),
                "interpretation_b": obs.get("interpretation_b"),
                "observed": True,
            },
            "observation": {
                k: obs.get(k)
                for k in ("kind", "name", "signal_reason", "requests_used")
                if obs.get(k) is not None
            },
            "note": (
                "Detection scaffolding only — fixture differential evidence, "
                "not a verified exploit or live smuggle. Hard caps applied. "
                "Use `sentinel hunt confirm-finding` after human review. "
                + CANNOT_PROD_SMUGGLING
            ),
        },
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=False,
            impact="http_desync_review_candidate",
            evidence_attached=True,
        ),
    }


def _maybe_live_mock(
    ctx: dict[str, Any],
    caps_dict: dict[str, Any],
    notes: list[str],
    *,
    i_own_this: bool,
    i_understand_lab: bool,
) -> RequestBudget | None:
    """Account for opener/live_mock under dual lab flag + hard caps. No payloads."""
    if not _has_live_mock(ctx):
        return None
    try:
        assert_lab_dual_flag(
            i_own_this=i_own_this,
            i_understand_lab=i_understand_lab,
            fixtures_only=False,
        )
    except CapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    budget = RequestBudget(max_requests=int(caps_dict["max_requests"]))
    notes.append(
        f"live mock path active — requires --i-own-this AND --i-understand-lab; "
        f"hard cap requests≤{caps_dict['max_requests']} "
        f"(hard_max={HARD_MAX_REQUESTS}); no live CDN/WAF smuggling"
    )
    fixtures = ctx.get("fixtures") or {}
    live_mock = fixtures.get("live_mock") if isinstance(fixtures, dict) else None
    opener = ctx.get("opener")
    calls = live_mock.get("calls") if isinstance(live_mock, dict) else None
    if isinstance(calls, list):
        for call in calls:
            if not budget.try_acquire():
                notes.append(
                    f"live mock request refused past cap "
                    f"(used={budget.used}, rejected={budget.rejected})"
                )
                break
            if callable(opener):
                try:
                    opener(call)
                except Exception as exc:  # noqa: BLE001 — lab mock soft
                    notes.append(f"live mock call soft-fail: {exc}")
        notes.append(f"live mock requests_used={budget.used}/{budget.max_requests}")
        caps_dict["requests_used"] = budget.used
        caps_dict["requests_rejected"] = budget.rejected
    elif callable(opener):
        if budget.try_acquire():
            try:
                opener({"probe": "http_desync_basename"})
            except Exception as exc:  # noqa: BLE001
                notes.append(f"live mock opener soft-fail: {exc}")
        caps_dict["requests_used"] = budget.used
    return budget


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """
    Run http_desync pack v0.

    Caps resolved first (over-limit → PackRunError). Default path uses
    in-process fixtures only (no lab flag required). Open-internet / live
    URLs / live_mock require dual --i-own-this + --i-understand-lab
    (and --scope for open-internet).
    """
    notes: list[str] = [
        "http_desync v0: fixture-driven CL.TE / TE.CL / header-smuggle differentials",
        COACH_DESYNC,
        COACH_LAB_FIRST,
        CANNOT_PROD_SMUGGLING,
        "findings default needs_human; never auto-VERIFIED/confirmed",
        f"hard caps: requests≤{HARD_MAX_REQUESTS} (non-overridable) for non-fixture paths",
    ]

    try:
        caps = resolve_caps(
            max_requests=ctx.get("max_requests"),
            i_understand_lab=bool(ctx.get("i_understand_lab")),
        )
    except CapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    caps_dict = caps.to_dict()
    fixtures = dict(ctx.get("fixtures") or {})
    scenarios = _scenarios_from_fixtures(fixtures)
    live = _live_urls(ctx)
    has_live_mock = _has_live_mock(ctx)

    scope = ctx.get("scope")
    scope_present = scope is not None or bool(ctx.get("scope_path"))
    i_own_this = bool(ctx.get("i_own_this"))
    i_understand_lab = caps.i_understand_lab

    # Pure fixtures = no live URLs and no live_mock/opener.
    # Built-in / caller fixture scenarios alone stay fixtures_only.
    fixtures_only = not live and not has_live_mock

    # Gate live URLs (prefer fixture + 127.0.0.1)
    for u in live:
        host = host_of(u)
        if not host:
            continue
        try:
            assert_target_allowed(
                u,
                scope_present=scope_present,
                i_own_this=i_own_this,
                i_understand_lab=i_understand_lab,
                fixtures_only=False,
            )
        except CapExceededError as exc:
            raise PackRunError(str(exc), exit_code=exc.exit_code) from exc
        fixtures_only = False
        if not is_lab_local_host(host):
            notes.append(
                f"open-internet target allowed under triple gate: "
                f"{urlparse(u).hostname}"
            )
        else:
            notes.append(f"lab-local live URL under dual lab flag: {host}")

    if has_live_mock:
        fixtures_only = False

    # Dual-flag for any non-fixture path (also covers live_mock without urls)
    try:
        assert_lab_dual_flag(
            i_own_this=i_own_this,
            i_understand_lab=i_understand_lab,
            fixtures_only=fixtures_only,
        )
    except CapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    budget = _maybe_live_mock(
        ctx,
        caps_dict,
        notes,
        i_own_this=i_own_this,
        i_understand_lab=i_understand_lab,
    )

    if not scenarios:
        scenarios = default_lab_scenarios()
        notes.append("using built-in 127.0.0.1 fixture differential scenarios")
        # Built-in defaults keep fixtures_only True unless live URLs/mock set.
        if not live and not has_live_mock:
            fixtures_only = True

    # Soft scope filter for scenario hosts when scope is set
    filtered: list[dict[str, Any]] = []
    for sc in scenarios:
        host = str(sc.get("host") or host_of(str(sc.get("url") or "")) or "127.0.0.1")
        sc = {**sc, "host": host}
        if scope is not None and host and not is_lab_local_host(host):
            try:
                scope.hard_kill(host)
            except ScopeDenied:
                notes.append(f"skipped OOS scenario host={host}")
                continue
        filtered.append(sc)

    observations: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    hints: list[dict[str, Any]] = []
    seen_kinds: set[str] = set()

    for sc in filtered:
        obs = analyze_fixture_scenario(sc, caps, budget=budget)
        observations.append(obs)
        notes.append(
            f"scenario={obs.get('name')} kind={obs.get('kind')} "
            f"signal={obs.get('signal_reason')} "
            f"diff={bool((obs.get('diff') or {}).get('has_differential'))}"
        )
        if obs.get("candidate_signal"):
            cand = _candidate_from_obs(obs)
            assert cand["verification"] in _AUTO_STATUSES
            assert cand.get("auto_verified") is False
            candidates.append(cand)
            kind = str(obs.get("kind") or "generic_desync")
            if kind not in seen_kinds:
                seen_kinds.add(kind)
                hints.append(
                    build_hint_record(
                        pattern_kind=kind,
                        host=str(obs.get("host") or ""),
                        url=str(obs.get("url") or ""),
                        extra=[COACH_LAB_FIRST],
                    )
                )

    if not hints:
        hints.append(
            build_hint_record(
                pattern_kind="generic_desync",
                extra=[COACH_LAB_FIRST],
            )
        )

    if not candidates:
        notes.append(
            "no http_desync candidates signaled — provide fixtures.desync_scenarios "
            "/ cl_te / te_cl / header_smuggle with differential responses, "
            "or rely on built-in lab fixtures"
        )

    if budget is not None:
        caps_dict.setdefault("requests_used", budget.used)
        caps_dict.setdefault("requests_rejected", budget.rejected)

    return {
        "candidates": candidates,
        "flows": [],
        "steps": [],
        "hints": hints,
        "notes": notes,
        "caps": caps_dict,
        "observations": observations,
        "fixtures_only": fixtures_only,
        "cannot": [CANNOT_PROD_SMUGGLING],
    }


__all__ = [
    "run_checks",
    "COACH_DESYNC",
    "CANNOT_PROD_SMUGGLING",
    "COACH_LAB_FIRST",
]
