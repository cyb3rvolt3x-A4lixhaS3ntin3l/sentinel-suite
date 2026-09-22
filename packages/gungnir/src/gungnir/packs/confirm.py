"""Human gate — explicit confirm of hunt findings (never auto-VERIFIED)."""

from __future__ import annotations

from typing import Any

from gungnir.bridge import VERIFICATION_STATUSES
from sentinel_core import open_graph

# Statuses a human may set via confirm-finding.
_HUMAN_CONFIRM_STATUSES = frozenset(
    {
        "confirmed",
        "verified",
        "needs_human",
        "unverified",
        "not_reproduced",
        "skipped",
    }
)


class ConfirmError(Exception):
    """Finding confirm refused (missing id, wrong type, bad status)."""

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def confirm_finding(
    program_id: str,
    finding_id: str,
    *,
    status: str = "confirmed",
    note: str | None = None,
    mark_role: str | None = None,
) -> dict[str, Any]:
    """
    Explicitly mark a FINDING after human review.

    Default pack emits stay ``needs_human`` / ``unverified``; this is the
    only supported path to ``confirmed`` / ``verified`` for business_logic.
    """
    status_n = (status or "confirmed").strip().lower()
    if status_n not in VERIFICATION_STATUSES:
        raise ConfirmError(
            f"invalid confirm status {status!r}; "
            f"expected one of {sorted(VERIFICATION_STATUSES)}"
        )
    if status_n not in _HUMAN_CONFIRM_STATUSES:
        raise ConfirmError(
            f"status {status_n!r} not allowed via confirm-finding; "
            f"expected one of {sorted(_HUMAN_CONFIRM_STATUSES)}"
        )

    with open_graph(program_id) as graph:
        ev = graph.get(finding_id)
        if ev is None:
            raise ConfirmError(f"finding not found: {finding_id}")
        if ev.type != "FINDING":
            raise ConfirmError(
                f"event {finding_id} is type {ev.type!r}, expected FINDING"
            )

        payload = dict(ev.payload or {})
        prev = str(
            payload.get("verification")
            or payload.get("verification_status")
            or "unverified"
        )
        payload["verification"] = status_n
        payload["verification_status"] = status_n
        payload["verified"] = status_n in ("verified", "confirmed")
        payload["human_confirmed"] = status_n in ("verified", "confirmed")
        payload["human_gate_prev"] = prev
        if note:
            payload["human_confirm_note"] = str(note)
        if mark_role:
            payload["human_confirm_role"] = str(mark_role).strip().lower()

        new_conf = float(ev.confidence)
        if status_n in ("verified", "confirmed") and new_conf < 0.7:
            new_conf = 0.7

        updated = graph.update_event(
            finding_id, payload=payload, confidence=new_conf
        )

        for parent_id in list(updated.parents or []):
            parent = graph.get(parent_id)
            if parent is None or parent.type != "FLOW":
                continue
            pp = dict(parent.payload or {})
            pp["human_marked"] = True
            conf = float(parent.confidence)
            if status_n in ("verified", "confirmed"):
                conf = max(conf, 0.7)
                pp["confidence"] = conf
            graph.update_event(parent_id, payload=pp, confidence=conf)

    return {
        "program_id": program_id,
        "finding_id": finding_id,
        "previous_verification": prev,
        "verification": status_n,
        "verified": status_n in ("verified", "confirmed"),
        "confidence": new_conf,
        "mark_role": mark_role,
    }


__all__ = ["ConfirmError", "confirm_finding"]
