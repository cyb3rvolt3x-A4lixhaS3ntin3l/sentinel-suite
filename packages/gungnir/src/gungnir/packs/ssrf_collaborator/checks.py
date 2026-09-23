"""ssrf_collaborator checks — fixture-driven owned-collaborator evidence.

Defensive scaffolding ONLY:
- Default collaborator = local 127.0.0.1 fixture callback mock
- Optional --collaborator must be operator-owned; refuse cloud metadata
  unless --i-understand-lab AND fixtures.lab_fixture_mode
- Beyond pure fixtures: BOTH --i-own-this AND --i-understand-lab
- Open-internet SSRF probes: --scope + --i-own-this + --i-understand-lab
- Hard request caps ≤10 for any non-pure-fixture path
- Findings always needs_human; never auto-VERIFIED
- DNS rebinding = coach hints only (no live rebind tooling)
- Cannot: live cloud metadata campaigns, random internet SSRF scan
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from gungnir.packs.manifest import finding_gate_checklist
from gungnir.packs.runner import PackRunError
from gungnir.packs.ssrf_collaborator.caps import (
    COACH_LAB_FIRST,
    DEFAULT_COLLABORATOR,
    HARD_MAX_REQUESTS,
    CapExceededError,
    RequestBudget,
    assert_collaborator_allowed,
    assert_lab_dual_flag,
    assert_metadata_refused,
    assert_target_allowed,
    host_of,
    is_cloud_metadata_target,
    is_lab_local_host,
    resolve_caps,
)
from gungnir.packs.ssrf_collaborator.fixture_mock import (
    analyze_fixture_scenario,
    default_lab_scenarios,
)
from gungnir.packs.ssrf_collaborator.hints import build_hint_record, hints_for_pattern
from sentinel_core import ScopeDenied

_AUTO_STATUSES = frozenset({"needs_human", "unverified"})

COACH_SSRF = (
    "ssrf packs are lab-first with an operator-owned collaborator; "
    "never spray cloud metadata or random internet hosts. "
    "Evidence = collaborator callback markers / outbound URL resolved to "
    "collaborator in fixtures — not live metadata fetches."
)

CANNOT_CLOUD_METADATA = (
    "Cannot: live cloud metadata campaigns (169.254.169.254 / "
    "metadata.google.internal / Azure IMDS / equivalents), random "
    "internet SSRF scanning, or auto-VERIFIED findings. "
    "Owned collaborator + fixture evidence only; open-internet needs "
    "--scope AND --i-own-this AND --i-understand-lab."
)


def _scenarios_from_fixtures(fixtures: dict[str, Any]) -> list[dict[str, Any]]:
    raw = (
        fixtures.get("ssrf_scenarios")
        or fixtures.get("ssrf_collaborator")
        or fixtures.get("scenarios")
        or []
    )
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            out.append(dict(item))
    for key, kind in (
        ("url_param", "url_param"),
        ("header_injection", "header_injection"),
        ("dns_rebind", "dns_rebind"),
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
    url = str(obs.get("url") or f"http://{host}/lab/ssrf")
    kind = str(obs.get("kind") or "ssrf")
    verification = "needs_human"
    hit = obs.get("hit") or {}
    title = (
        f"SSRF collaborator candidate ({kind}): "
        f"{obs.get('name') or host} — {obs.get('signal_reason') or 'callback'}"
    )
    coach = [COACH_SSRF, COACH_LAB_FIRST] + hints_for_pattern(kind)[:3]
    return {
        "title": title,
        "host": host,
        "url": url,
        "check": f"ssrf_collaborator_{kind}",
        "verification": verification,
        "confidence": 0.3,
        "impact": "ssrf_collaborator_review_candidate",
        "reproducible": False,
        "in_scope": True,
        "evidence_attached": True,
        "human_gate": True,
        "auto_verified": False,
        "coach_hints": coach,
        "caps": {
            "max_requests": obs.get("max_requests"),
            "requests_used": obs.get("requests_used"),
            "collaborator": obs.get("collaborator"),
        },
        "evidence_summary": (
            f"Fixture SSRF collaborator evidence kind={kind} "
            f"signal={obs.get('signal_reason')} "
            f"received={hit.get('received')} "
            f"url_to_collab={hit.get('url_resolved_to_collaborator')} "
            f"marker={hit.get('marker')} — awaiting human confirm "
            f"(verification={verification})"
        ),
        "evidence_stub": {
            "check": f"ssrf_collaborator_{kind}",
            "response": {
                "evidence_signal": "collaborator_callback",
                "hit": {
                    k: hit.get(k)
                    for k in (
                        "hit",
                        "received",
                        "url_resolved_to_collaborator",
                        "marker",
                        "outbound_url",
                        "collaborator",
                        "header_influenced_outbound",
                    )
                    if hit.get(k) is not None
                },
                "observed": True,
            },
            "observation": {
                k: obs.get(k)
                for k in (
                    "kind",
                    "name",
                    "signal_reason",
                    "requests_used",
                    "collaborator",
                )
                if obs.get(k) is not None
            },
            "note": (
                "Detection scaffolding only — fixture collaborator evidence, "
                "not a verified exploit or live metadata fetch. Hard caps applied. "
                "Use `sentinel hunt confirm-finding` after human review. "
                + CANNOT_CLOUD_METADATA
            ),
        },
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=False,
            impact="ssrf_collaborator_review_candidate",
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
        f"(hard_max={HARD_MAX_REQUESTS}); no cloud-metadata / random-host spray"
    )
    fixtures = ctx.get("fixtures") or {}
    live_mock = fixtures.get("live_mock") if isinstance(fixtures, dict) else None
    opener = ctx.get("opener")
    lab_fixture_mode = bool(
        isinstance(fixtures, dict) and fixtures.get("lab_fixture_mode")
    )
    calls = live_mock.get("calls") if isinstance(live_mock, dict) else None
    if isinstance(calls, list):
        for call in calls:
            target = None
            if isinstance(call, dict):
                target = call.get("url") or call.get("collaborator") or call.get("host")
            if target and is_cloud_metadata_target(str(target)):
                try:
                    assert_metadata_refused(
                        str(target),
                        i_understand_lab=i_understand_lab,
                        lab_fixture_mode=lab_fixture_mode,
                    )
                except CapExceededError as exc:
                    raise PackRunError(str(exc), exit_code=exc.exit_code) from exc
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
                opener({"probe": "ssrf_collaborator_basename"})
            except Exception as exc:  # noqa: BLE001
                notes.append(f"live mock opener soft-fail: {exc}")
        caps_dict["requests_used"] = budget.used
    return budget


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """
    Run ssrf_collaborator pack v0.

    Caps + collaborator resolved first (over-limit / metadata → PackRunError).
    Default path uses in-process fixtures + local collaborator mock (no lab
    flag required). Open-internet / live URLs / live_mock require dual
    --i-own-this + --i-understand-lab (and --scope for open-internet).
    """
    notes: list[str] = [
        "ssrf_collaborator v0: fixture-driven URL-param / header-injection "
        "with owned collaborator callback markers",
        COACH_SSRF,
        COACH_LAB_FIRST,
        CANNOT_CLOUD_METADATA,
        "findings default needs_human; never auto-VERIFIED/confirmed",
        f"hard caps: requests≤{HARD_MAX_REQUESTS} (non-overridable) for non-fixture paths",
        f"default collaborator: {DEFAULT_COLLABORATOR}",
    ]

    try:
        caps = resolve_caps(
            max_requests=ctx.get("max_requests"),
            i_understand_lab=bool(ctx.get("i_understand_lab")),
            collaborator=ctx.get("collaborator"),
        )
    except CapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    caps_dict = caps.to_dict()
    fixtures = dict(ctx.get("fixtures") or {})
    lab_fixture_mode = bool(fixtures.get("lab_fixture_mode"))
    scenarios = _scenarios_from_fixtures(fixtures)
    live = _live_urls(ctx)
    has_live_mock = _has_live_mock(ctx)

    scope = ctx.get("scope")
    scope_present = scope is not None or bool(ctx.get("scope_path"))
    i_own_this = bool(ctx.get("i_own_this"))
    i_understand_lab = caps.i_understand_lab

    fixtures_only = not live and not has_live_mock

    try:
        assert_collaborator_allowed(
            caps.collaborator,
            i_own_this=i_own_this,
            i_understand_lab=i_understand_lab,
            lab_fixture_mode=lab_fixture_mode,
            fixtures_only=fixtures_only,
        )
    except CapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    notes.append(f"collaborator={caps.collaborator}")
    if ctx.get("listen"):
        notes.append(
            "owned collaborator listener active (--listen); "
            "inbound callbacks log COLLABORATOR_HIT on the program graph; "
            "default bind 127.0.0.1; no outbound scan; no interactsh"
        )

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
                lab_fixture_mode=lab_fixture_mode,
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
        scenarios = default_lab_scenarios(caps.collaborator)
        notes.append("using built-in 127.0.0.1 fixture collaborator scenarios")
        if not live and not has_live_mock:
            fixtures_only = True

    filtered: list[dict[str, Any]] = []
    for sc in scenarios:
        host = str(sc.get("host") or host_of(str(sc.get("url") or "")) or "127.0.0.1")
        sc = {**sc, "host": host}
        sc.setdefault("collaborator", caps.collaborator)
        try:
            assert_metadata_refused(
                sc.get("collaborator"),
                i_understand_lab=i_understand_lab,
                lab_fixture_mode=lab_fixture_mode,
            )
            cb = (
                sc.get("collaborator_callback")
                or sc.get("callback")
                or sc.get("evidence")
                or {}
            )
            if isinstance(cb, dict):
                assert_metadata_refused(
                    cb.get("outbound_url") or cb.get("url"),
                    i_understand_lab=i_understand_lab,
                    lab_fixture_mode=lab_fixture_mode,
                )
        except CapExceededError as exc:
            raise PackRunError(str(exc), exit_code=exc.exit_code) from exc
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
            f"hit={bool((obs.get('hit') or {}).get('hit'))} "
            f"dns_coach={bool(obs.get('dns_rebind_coach_only'))}"
        )
        if obs.get("candidate_signal"):
            cand = _candidate_from_obs(obs)
            assert cand["verification"] in _AUTO_STATUSES
            assert cand.get("auto_verified") is False
            candidates.append(cand)
            kind = str(obs.get("kind") or "generic_ssrf")
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
        elif obs.get("dns_rebind_coach_only"):
            kind = "dns_rebind"
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
                pattern_kind="generic_ssrf",
                extra=[COACH_LAB_FIRST],
            )
        )

    if not candidates:
        notes.append(
            "no ssrf_collaborator candidates signaled — provide "
            "fixtures.ssrf_scenarios / url_param / header_injection with "
            "collaborator_callback markers, or rely on built-in lab fixtures"
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
        "cannot": [CANNOT_CLOUD_METADATA],
        "collaborator": caps.collaborator,
    }


__all__ = [
    "run_checks",
    "COACH_SSRF",
    "CANNOT_CLOUD_METADATA",
    "COACH_LAB_FIRST",
]
