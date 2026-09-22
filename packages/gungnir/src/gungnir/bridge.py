"""Emit Gungnir-shaped finding/evidence events + scope/lab gate."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel_core import Event, EventGraph, Scope, ScopeDenied, load_scope_file

# Honest verification statuses (aligned lightly with gungnir-harden verify.py
# plus Sprint 0 needs_human / verified aliases from the product plan).
VERIFICATION_STATUSES = frozenset(
    {
        "unverified",
        "needs_human",
        "verified",
        "confirmed",
        "not_reproduced",
        "skipped",
    }
)


def require_scope_or_lab(
    scope_path: str | Path | None = None,
    *,
    i_own_this: bool = False,
) -> None:
    """
    Scope gate stub: hunt must have a scope file OR explicit lab override.

    Raises ScopeDenied unless scope_path is a readable file or i_own_this is True.
    Does not run any network activity.
    """
    if i_own_this:
        return
    if scope_path is None:
        raise ScopeDenied(
            "scope required: pass scope_path or set i_own_this=True for lab use"
        )
    path = Path(scope_path)
    if not path.is_file():
        raise ScopeDenied(f"scope file not found: {path}")
    # Touch-parse to ensure file is usable
    load_scope_file(path)


def emit_finding_event(
    graph: EventGraph,
    *,
    program_id: str,
    title: str,
    parents: list[str] | None = None,
    confidence: float = 0.5,
    payload: dict[str, Any] | None = None,
    source_module: str = "gungnir.bridge",
) -> Event:
    """Create and insert a FINDING event. Does not run exploits or scans."""
    body = {"title": title, **(payload or {})}
    event = Event(
        type="FINDING",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload=body,
    )
    graph.insert(event)
    return event


def emit_evidence_event(
    graph: EventGraph,
    *,
    program_id: str,
    summary: str,
    parents: list[str] | None = None,
    confidence: float = 0.7,
    payload: dict[str, Any] | None = None,
    source_module: str = "gungnir.bridge",
) -> Event:
    """Create and insert an EVIDENCE event linked to findings/parents."""
    body = {"summary": summary, **(payload or {})}
    event = Event(
        type="EVIDENCE",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload=body,
    )
    graph.insert(event)
    return event


def emit_verified_finding(
    graph: EventGraph,
    *,
    program_id: str,
    title: str,
    verification: str = "unverified",
    parents: list[str] | None = None,
    confidence: float = 0.5,
    payload: dict[str, Any] | None = None,
    host: str | None = None,
    scope: Scope | None = None,
    source_module: str = "gungnir.bridge",
) -> Event:
    """
    FINDING with honest verification status fields.

    verification: unverified | needs_human | verified | confirmed |
                  not_reproduced | skipped

    If ``scope`` and ``host`` are provided, hard_kill(host) before insert.
    """
    status = (verification or "unverified").strip().lower()
    if status not in VERIFICATION_STATUSES:
        raise ValueError(
            f"unknown verification status: {verification!r}; "
            f"expected one of {sorted(VERIFICATION_STATUSES)}"
        )
    if scope is not None and host:
        scope.hard_kill(host)

    body: dict[str, Any] = {
        "title": title,
        "verification": status,
        "verification_status": status,
        **(payload or {}),
    }
    if host:
        body.setdefault("host", host)
    # Boolean compat: True only for verified/confirmed
    body["verified"] = status in ("verified", "confirmed")

    event = Event(
        type="FINDING",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload=body,
    )
    graph.insert(event)
    return event


def scoped_emit_finding(
    graph: EventGraph,
    scope: Scope,
    *,
    program_id: str,
    title: str,
    host: str,
    parents: list[str] | None = None,
    confidence: float = 0.5,
    payload: dict[str, Any] | None = None,
) -> Event:
    """hard_kill finding host, then emit FINDING."""
    scope.hard_kill(host)
    body = {"host": host, **(payload or {})}
    return emit_finding_event(
        graph,
        program_id=program_id,
        title=title,
        parents=parents,
        confidence=confidence,
        payload=body,
    )
