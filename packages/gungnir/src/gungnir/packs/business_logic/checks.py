"""Business-logic assistant v0 — flow map + coach hints; human gate.

Defensive only: no payment capture, no other-customer harm, no live abuse.
Findings stay needs_human / unverified until explicit human confirm.
Never auto-emits verified/confirmed.
"""

from __future__ import annotations

from typing import Any

from gungnir.packs.business_logic.flow_mapper import map_flows_from_fixtures
from gungnir.packs.business_logic.hints import hints_for_flow_kind
from gungnir.packs.manifest import finding_gate_checklist

# Statuses the pack may auto-emit (human gate).
_AUTO_STATUSES = frozenset({"needs_human", "unverified"})


def _finding_from_flow(
    flow: dict[str, Any],
    hint: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a needs_human finding candidate with coach hints on payload."""
    kind = str(flow.get("kind") or "generic_multi_step")
    questions = list((hint or {}).get("questions") or hints_for_flow_kind(kind))
    host = str(flow.get("host") or "")
    url = str(flow.get("url") or "")
    title = (
        f"Business-logic flow candidate ({kind}): "
        f"{flow.get('name') or flow.get('local_id')}"
    )
    verification = "needs_human"
    return {
        "title": title,
        "host": host,
        "url": url or None,
        "check": f"business_logic_flow_{kind}",
        "verification": verification,
        "confidence": float(flow.get("confidence") or 0.25),
        "impact": "business_logic_review_candidate",
        "reproducible": False,
        "in_scope": True,
        "evidence_attached": True,
        "flow_local_id": flow.get("local_id"),
        "flow_kind": kind,
        "coach_hints": questions,
        "human_gate": True,
        "auto_verified": False,
        "evidence_summary": (
            f"Mapped multi-step flow '{flow.get('name')}' ({kind}) with "
            f"{flow.get('step_count')} steps; coach hints attached — "
            f"awaiting human confirm (verification={verification})"
        ),
        "evidence_stub": {
            "check": f"business_logic_flow_{kind}",
            "flow": {
                "local_id": flow.get("local_id"),
                "kind": kind,
                "name": flow.get("name"),
                "steps": flow.get("step_names"),
                "source": flow.get("source"),
            },
            "coach_hints": questions,
            "note": (
                "Coach hints only — not a confirmed vulnerability. "
                "Use `sentinel hunt confirm-finding` after human review."
            ),
        },
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=False,
            impact="business_logic_review_candidate",
            evidence_attached=True,
        ),
    }


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """
    Run business_logic assistant v0.

    Returns candidates (needs_human), flows, steps, hints, notes.
    Never sets verification to verified/confirmed.
    """
    mapped = map_flows_from_fixtures(ctx)
    flows = list(mapped.get("flows") or [])
    steps = list(mapped.get("steps") or [])
    hints = list(mapped.get("hints") or [])
    notes = list(mapped.get("notes") or [])
    notes.extend(
        [
            "business_logic assistant v0: map flows + coach hints only",
            "findings default needs_human; never auto-VERIFIED/confirmed",
            "no payment capture; no other-customer harm; no live abuse",
            "use confirm-finding / role mark for explicit human confirm",
        ]
    )

    hints_by_flow = {h.get("flow_id"): h for h in hints if h.get("flow_id")}
    candidates: list[dict[str, Any]] = []
    for flow in flows:
        hint = hints_by_flow.get(flow.get("local_id"))
        cand = _finding_from_flow(flow, hint)
        assert cand["verification"] in _AUTO_STATUSES
        assert cand.get("auto_verified") is False
        candidates.append(cand)

    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for c in candidates:
        key = (str(c.get("title")), str(c.get("url")), str(c.get("check")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    if not unique:
        notes.append(
            "no business_logic candidates — provide fixtures.flows with ≥2 steps"
        )

    return {
        "candidates": unique,
        "flows": flows,
        "steps": steps,
        "hints": hints,
        "notes": notes,
    }


__all__ = ["run_checks"]
