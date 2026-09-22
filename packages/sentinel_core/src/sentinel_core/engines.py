"""Engine pin MVP — binaries under SENTINEL_HOME/bin with version stamps."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel_core.programs import get_sentinel_home


def bin_dir(home: Path | None = None) -> Path:
    root = home or get_sentinel_home()
    path = root / "bin"
    path.mkdir(parents=True, exist_ok=True)
    return path


def stamps_path(home: Path | None = None) -> Path:
    return bin_dir(home) / "stamps.json"


def _load_stamps(home: Path | None = None) -> dict[str, Any]:
    path = stamps_path(home)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _save_stamps(data: dict[str, Any], home: Path | None = None) -> None:
    path = stamps_path(home)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def list_pinned(home: Path | None = None) -> dict[str, Any]:
    """Return {name: {version, path, stamped_at}} for pinned engines."""
    return dict(_load_stamps(home))


def pin_engine(
    name: str,
    version: str,
    binary_path: str | Path | None = None,
    home: Path | None = None,
) -> dict[str, Any]:
    """
    Record a pinned engine version under SENTINEL_HOME/bin stamps.
    Does not download binaries in Sprint 0 — stamp only.
    """
    stamps = _load_stamps(home)
    entry = {
        "name": name,
        "version": version,
        "path": str(binary_path) if binary_path else str(bin_dir(home) / name),
        "stamped_at": datetime.now(timezone.utc).isoformat(),
    }
    stamps[name] = entry
    _save_stamps(stamps, home)
    return entry


def stamp_run(
    engine: str,
    version: str | None = None,
    home: Path | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Stamp a run: append to run log and return the stamp record.
    Used so every orchestration run can record which engine version was used.
    """
    stamps = _load_stamps(home)
    pinned = stamps.get(engine, {})
    ver = version or pinned.get("version") or "unknown"
    record = {
        "engine": engine,
        "version": ver,
        "at": datetime.now(timezone.utc).isoformat(),
        **(extra or {}),
    }
    log_path = bin_dir(home) / "run_stamps.jsonl"
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return record
