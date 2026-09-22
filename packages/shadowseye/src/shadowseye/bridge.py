"""Emit minimal ShadowsEye-shaped events into sentinel_core graph."""

from __future__ import annotations

from sentinel_core import Event, EventGraph


def emit_domain_event(
    graph: EventGraph,
    *,
    program_id: str,
    domain: str,
    parents: list[str] | None = None,
    confidence: float = 0.9,
    source_module: str = "shadowseye.bridge",
) -> Event:
    """Create and insert a DOMAIN event. Does not perform DNS or recon."""
    event = Event(
        type="DOMAIN",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload={"domain": domain},
    )
    graph.insert(event)
    return event
