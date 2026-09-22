"""race_toctou checks — fixture-driven TOCTOU/race candidate detection.

Defensive scaffolding ONLY:
- Hard caps on workers / requests / duration (never above HARD_MAX_*)
- Default target = in-process fixture mock
- Findings always needs_human; never auto-VERIFIED
- No unlimited threads, no lockout/flood, no payment capture
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from gungnir.packs.manifest import finding_gate_checklist
from gungnir.packs.race_toctou.caps import (
    COACH_LAB_FIRST,
    CapExceededError,
    assert_target_allowed,
    host_of,
    is_lab_local_host,
    resolve_caps,
)
from gungnir.packs.race_toctou.fixture_mock import run_fixture_race
from gungnir.packs.runner import PackRunError
from sentinel_core import ScopeDenied

_AUTO_STATUSES = frozenset({"needs_human", "unverified"})


def _default_scenarios() -> list[dict[str, Any]]:
    """Built-in lab fixtures (127.0.0.1) when caller provides none."""
    return [
        {
            "name": "lab-coupon-toctou",
            "kind": "coupon_toctou",
            "url": "http://127.0.0.1/lab/coupon/redeem",
            "host": "127.0.0.1",
            "uses_left": 1,
            "check_delay_s": 0.015,
            "force_candidate_signal": True,
        },
        {
            "name": "lab-balance-race",
            "kind": "balance_race",
            "url": "http://127.0.0.1/lab/wallet/withdraw",
            "host": "127.0.0.1",
            "balance": 100,
            "withdraw_amount": 80,
            "check_delay_s": 0.015,
            "force_candidate_signal": True,
        },
    ]


def _scenarios_from_fixtures(fixtures: dict[str, Any]) -> list[dict[str, Any]]:
    raw = fixtures.get("race_scenarios") or fixtures.get("scenarios") or []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            out.append(dict(item))
    return out


def _live_urls(ctx: dict[str, Any]) -> list[str]:
    urls = list(ctx.get("urls") or [])
    fixtures = ctx.get("fixtures") or {}
    for u in fixtures.get("target_urls") or []:
        if isinstance(u, str) and u.strip():
            urls.append(u.strip())
    return urls


def _candidate_from_obs(obs: dict[str, Any]) -> dict[str, Any]:
    host = str(obs.get("host") or "127.0.0.1")
    url = str(obs.get("url") or f"http://{host}/lab/race")
    kind = str(obs.get("kind") or "race")
    verification = "needs_human"
    title = (
        f"Race/TOCTOU candidate ({kind}): "
        f"{obs.get('name') or host} — {obs.get('signal_reason') or 'timing_window'}"
    )
    return {
        "title": title,
        "host": host,
        "url": url,
        "check": f"race_toctou_{kind}",
        "verification": verification,
        "confidence": 0.3,
        "impact": "race_toctou_review_candidate",
        "reproducible": False,
        "in_scope": True,
        "evidence_attached": True,
        "human_gate": True,
        "auto_verified": False,
        "coach_hints": [
            COACH_LAB_FIRST,
            "Was the timing window reproducible under the hard caps?",
            "Does the app use atomic compare-and-swap / row locks / idempotency keys?",
            "Is this authorized lab/bounty scope — not other-customer harm?",
        ],
        "caps": {
            "workers_used": obs.get("workers_used"),
            "requests_used": obs.get("requests_used"),
            "max_requests": obs.get("max_requests"),
            "max_duration_s": obs.get("max_duration_s"),
            "elapsed_s": obs.get("elapsed_s"),
        },
        "evidence_summary": (
            f"Fixture race observation kind={kind} signal={obs.get('signal_reason')} "
            f"successes={obs.get('successes')} requests={obs.get('requests_used')}/"
            f"{obs.get('max_requests')} — awaiting human confirm "
            f"(verification={verification})"
        ),
        "evidence_stub": {
            "check": f"race_toctou_{kind}",
            "observation": {
                k: obs.get(k)
                for k in (
                    "kind",
                    "name",
                    "signal_reason",
                    "successes",
                    "requests_used",
                    "workers_used",
                    "elapsed_s",
                    "redeem_count",
                    "total_withdrawn",
                    "final_balance",
                )
                if obs.get(k) is not None
            },
            "note": (
                "Detection scaffolding only — not a verified exploit. "
                "Hard caps applied. Use `sentinel hunt confirm-finding` "
                "after human review."
            ),
        },
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=False,
            impact="race_toctou_review_candidate",
            evidence_attached=True,
        ),
    }


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """
    Run race_toctou pack v0.

    Caps are resolved first (over-limit → PackRunError). Default path uses
    in-process fixtures only. Open-internet URLs require scope + i_own_this +
    i_understand_lab.
    """
    notes: list[str] = [
        "race_toctou v0: fixture-driven TOCTOU/race candidate detection",
        COACH_LAB_FIRST,
        "findings default needs_human; never auto-VERIFIED/confirmed",
        "hard caps: workers≤4, requests≤20, duration≤5s (non-overridable)",
    ]

    try:
        caps = resolve_caps(
            workers=ctx.get("max_workers"),
            max_requests=ctx.get("max_requests"),
            max_duration=ctx.get("max_duration"),
            i_understand_lab=bool(ctx.get("i_understand_lab")),
        )
    except CapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    fixtures = dict(ctx.get("fixtures") or {})
    scenarios = _scenarios_from_fixtures(fixtures)
    fixtures_only = True
    live = _live_urls(ctx)

    scope = ctx.get("scope")
    scope_present = scope is not None or bool(ctx.get("scope_path"))
    i_own_this = bool(ctx.get("i_own_this"))
    i_understand_lab = caps.i_understand_lab

    # Open-internet / live URL gate (prefer fixture + 127.0.0.1)
    for u in live:
        host = host_of(u)
        if not host:
            continue
        if is_lab_local_host(host):
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
            # Lab-local live URL still uses fixture scenarios unless provided
            fixtures_only = False
            continue
        # Open internet
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
        notes.append(
            f"open-internet target allowed under triple gate: {urlparse(u).hostname}"
        )

    if not scenarios:
        scenarios = _default_scenarios()
        notes.append("using built-in 127.0.0.1 fixture mock scenarios")
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
    for sc in filtered:
        obs = run_fixture_race(sc, caps)
        observations.append(obs)
        notes.append(
            f"scenario={obs.get('name')} requests={obs.get('requests_used')}/"
            f"{obs.get('max_requests')} workers={obs.get('workers_used')} "
            f"signal={obs.get('signal_reason')}"
        )
        if obs.get("candidate_signal"):
            cand = _candidate_from_obs(obs)
            assert cand["verification"] in _AUTO_STATUSES
            assert cand.get("auto_verified") is False
            candidates.append(cand)

    if not candidates:
        notes.append(
            "no race/TOCTOU candidates signaled — provide fixtures.race_scenarios "
            "or rely on built-in lab mock"
        )

    return {
        "candidates": candidates,
        "flows": [],
        "steps": [],
        "hints": [
            {
                "kind": "coach_hints",
                "note": COACH_LAB_FIRST,
                "questions": [
                    COACH_LAB_FIRST,
                    "Confirm written authorization before any non-lab target.",
                    "Keep workers≤4, requests≤20, duration≤5s.",
                ],
            }
        ],
        "notes": notes,
        "caps": caps.to_dict(),
        "observations": observations,
        "fixtures_only": fixtures_only,
    }


__all__ = ["run_checks"]
