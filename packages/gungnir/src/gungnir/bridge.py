"""Emit minimal Gungnir-shaped events + scope/lab gate stub."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel_core import Event, EventGraph, ScopeDenied, load_scope_file


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
