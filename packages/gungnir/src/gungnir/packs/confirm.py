"""Human gate — explicit confirm of hunt findings (never auto-VERIFIED)."""

from __future__ import annotations

import getpass
import os
from datetime import datetime, timezone
from typing import Any

from gungnir.bridge import VERIFICATION_STATUSES
from sentinel_core import open_graph

# Primary human confirm statuses (Phase C slice13).
# Keep needs_human / verified as workflow aliases so prior packs stay intact.
HUMAN_CONFIRM_STATUSES = frozenset(
    {
        "confirmed",
        "not_reproduced",
        "unverified",
        "skipped",
        "rejected",
        "verified",  # alias of confirmed
        "needs_human",  # re-queue
    }
)

PENDING_CONFIRM_STATUSES = frozenset({"needs_human", "unverified"})

# Pack emits must never land these on the graph without confirm-finding.
AUTO_CONFIRM_REFUSED = frozenset({"confirmed", "verified"})


class ConfirmError(Exception):
    """Finding confirm refused (missing id, wrong type, bad status, no note)."""

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _resolve_who(*, who: str | None, mark_role: str | None) -> str:
    if who and str(who).strip():
        return str(who).strip()
    if mark_role and str(mark_role).strip():
        return f"role:{str(mark_role).strip().lower()}"
    env_who = os.environ.get("SENTINEL_HUNTER") or os.environ.get("USER")
    if env_who and str(env_who).strip():
        return str(env_who).strip()
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"


def refuse_pack_auto_confirm(verification: str) -> tuple[str, dict[str, Any]]:
    """
    Coerce pack-emitted confirmed/verified → needs_human.

    Returns (graph_verification, extra_payload_fields).
    """
    status = (verification or "unverified").strip().lower() or "unverified"
    if status in AUTO_CONFIRM_REFUSED:
        return "needs_human", {
            "pack_auto_confirm_refused": True,
            "pack_claimed_verification": status,
            "human_confirmed": False,
            "verified": False,
        }
    return status, {}


def confirm_finding(
    program_id: str,
    finding_id: str,
    *,
    status: str = "confirmed",
    note: str | None = None,
    mark_role: str | None = None,
    who: str | None = None,
) -> dict[str, Any]:
    """
    Explicitly mark a FINDING after human review.

    Default pack emits stay ``needs_human`` / ``unverified``; this is the
    only supported path to ``confirmed`` / ``verified``. Note is required.
    Stamps ``human_confirm_by`` + ``human_confirm_at`` (UTC).
    """
    note_s = (note or "").strip()
    if not note_s:
        raise ConfirmError(
            "confirm-finding requires --note (human review note is mandatory)"
        )

    status_n = (status or "confirmed").strip().lower()
    if status_n not in VERIFICATION_STATUSES:
        raise ConfirmError(
            f"invalid confirm status {status!r}; "
            f"expected one of {sorted(VERIFICATION_STATUSES)}"
        )
    if status_n not in HUMAN_CONFIRM_STATUSES:
        raise ConfirmError(
            f"status {status_n!r} not allowed via confirm-finding; "
            f"expected one of {sorted(HUMAN_CONFIRM_STATUSES)}"
        )

    who_s = _resolve_who(who=who, mark_role=mark_role)
    when_s = datetime.now(timezone.utc).isoformat()

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
        if payload.get("pack_auto_confirm_refused") and status_n in AUTO_CONFIRM_REFUSED:
            payload["pack_auto_confirm_cleared_by_human"] = True

        payload["verification"] = status_n
        payload["verification_status"] = status_n
        payload["verified"] = status_n in ("verified", "confirmed")
        payload["human_confirmed"] = status_n in ("verified", "confirmed")
        payload["human_gate_prev"] = prev
        payload["human_confirm_note"] = note_s
        payload["human_confirm_by"] = who_s
        payload["human_confirm_at"] = when_s
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
        "note": note_s,
        "who": who_s,
        "confirmed_at": when_s,
    }


def list_findings(
    program_id: str,
    *,
    pack_id: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """
    List FINDING events for a program.

    ``status`` filters by payload verification. Special values:
      - ``needs_human`` / ``pending`` → pending confirm queue
        (needs_human + unverified)
      - ``all`` → no status filter
    """
    status_filter: frozenset[str] | None = None
    if status:
        s = status.strip().lower()
        if s in ("pending", "needs_human"):
            status_filter = PENDING_CONFIRM_STATUSES
        elif s == "all":
            status_filter = None
        else:
            status_filter = frozenset({s})

    rows: list[dict[str, Any]] = []
    with open_graph(program_id) as graph:
        for finding in graph.list_by_type("FINDING"):
            payload = finding.payload or {}
            fid_pack = str(payload.get("pack_id") or "")
            if pack_id:
                src = getattr(finding, "source_module", "") or ""
                if fid_pack != pack_id and pack_id not in src:
                    continue
            ver = str(
                payload.get("verification")
                or payload.get("verification_status")
                or "unverified"
            )
            if status_filter is not None and ver not in status_filter:
                continue
            checklist = payload.get("checklist") or {}
            rows.append(
                {
                    "id": finding.id,
                    "title": payload.get("title") or "",
                    "pack_id": fid_pack or None,
                    "verification": ver,
                    "host": payload.get("host"),
                    "url": payload.get("url"),
                    "check": payload.get("check"),
                    "confidence": finding.confidence,
                    "human_confirmed": bool(payload.get("human_confirmed")),
                    "human_confirm_by": payload.get("human_confirm_by"),
                    "human_confirm_at": payload.get("human_confirm_at"),
                    "checklist": checklist if isinstance(checklist, dict) else {},
                    "pack_auto_confirm_refused": bool(
                        payload.get("pack_auto_confirm_refused")
                    ),
                    "pack_claimed_verification": payload.get(
                        "pack_claimed_verification"
                    ),
                }
            )
    return rows


__all__ = [
    "AUTO_CONFIRM_REFUSED",
    "ConfirmError",
    "HUMAN_CONFIRM_STATUSES",
    "PENDING_CONFIRM_STATUSES",
    "confirm_finding",
    "list_findings",
    "refuse_pack_auto_confirm",
]
