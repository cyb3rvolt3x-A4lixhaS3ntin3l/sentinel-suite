"""Optional anonymous usage telemetry — OFF by default (Phase G0).

Gate: env ``SENTINEL_TELEMETRY`` (default ``0`` / unset = off).
Opt-in values: ``1``, ``true``, ``yes``, ``on`` (case-insensitive).

Even when opted in, G0 ships a **local-only** stub: events append to
``SENTINEL_HOME/telemetry/local.jsonl``. No network phone-home endpoint
is configured or called. Do not invent metrics from this file.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel_core.programs import get_sentinel_home

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_ENV_KEY = "SENTINEL_TELEMETRY"


def telemetry_env_raw() -> str:
    """Raw env value (empty string if unset)."""
    return (os.environ.get(_ENV_KEY) or "").strip()


def telemetry_enabled() -> bool:
    """True only when SENTINEL_TELEMETRY is an explicit opt-in value."""
    raw = telemetry_env_raw().lower()
    if not raw:
        return False
    return raw in _TRUTHY


def telemetry_dir(home: Path | None = None) -> Path:
    return (home or get_sentinel_home()) / "telemetry"


def telemetry_local_path(home: Path | None = None) -> Path:
    return telemetry_dir(home) / "local.jsonl"


def telemetry_status(home: Path | None = None) -> dict[str, Any]:
    """User-visible status for Settings / CLI — never implies phone-home."""
    enabled = telemetry_enabled()
    return {
        "enabled": enabled,
        "default": "off",
        "env_key": _ENV_KEY,
        "env_value": telemetry_env_raw() or None,
        "opt_in_values": sorted(_TRUTHY),
        "sink": "local_jsonl" if enabled else "noop",
        "local_path": str(telemetry_local_path(home)),
        "network": False,
        "phone_home": False,
        "note": (
            "Telemetry is OFF by default. Set SENTINEL_TELEMETRY=1 to opt in. "
            "G0 collector writes local JSONL only — no network endpoint."
            if not enabled
            else (
                "Opt-in active: events append to local JSONL only. "
                "No phone-home / remote sink in G0."
            )
        ),
    }


def emit_event(
    name: str,
    props: dict[str, Any] | None = None,
    *,
    home: Path | None = None,
) -> dict[str, Any]:
    """
    Emit an anonymous usage event.

    No-ops (returns ``{"emitted": False, ...}``) unless telemetry is opted in.
    When opted in, appends one JSON line under SENTINEL_HOME/telemetry/ — never HTTP.
    """
    status = telemetry_status(home)
    if not status["enabled"]:
        return {
            "emitted": False,
            "reason": "telemetry_off",
            "name": name,
            "status": status,
        }
    root = telemetry_dir(home)
    root.mkdir(parents=True, exist_ok=True)
    path = telemetry_local_path(home)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "name": str(name),
        "props": dict(props or {}),
        "anonymous": True,
        "network": False,
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    return {
        "emitted": True,
        "name": name,
        "path": str(path),
        "network": False,
        "status": status,
    }


__all__ = [
    "emit_event",
    "telemetry_dir",
    "telemetry_enabled",
    "telemetry_env_raw",
    "telemetry_local_path",
    "telemetry_status",
]
