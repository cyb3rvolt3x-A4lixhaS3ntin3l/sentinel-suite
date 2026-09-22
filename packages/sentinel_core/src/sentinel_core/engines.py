"""Engine pin MVP — detect on PATH/bin, stamp versions; download deferred."""

from __future__ import annotations

import json
import shutil
import subprocess
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


def _probe_version(binary: Path | str) -> str | None:
    """Light --version / -version probe; degrade gracefully on failure."""
    path = str(binary)
    for flag in ("--version", "-version", "-V", "version"):
        try:
            proc = subprocess.run(
                [path, flag],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            out = (proc.stdout or proc.stderr or "").strip()
            if out:
                # First non-empty line, truncated
                line = out.splitlines()[0].strip()
                return line[:120] if line else None
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def detect_engine(name: str, home: Path | None = None) -> dict[str, Any] | None:
    """
    Look for an engine binary on PATH and under bin_dir().

    Returns {name, path, version, source} or None if not found.
    Version probe failures degrade to version=None (still a detection).
    """
    candidates: list[tuple[str, Path]] = []
    which = shutil.which(name)
    if which:
        candidates.append(("path", Path(which)))
    local = bin_dir(home) / name
    if local.is_file():
        candidates.append(("bin_dir", local))

    if not candidates:
        return None

    source, path = candidates[0]
    version = _probe_version(path)
    return {
        "name": name,
        "path": str(path),
        "version": version,
        "source": source,
    }


def ensure_engine(
    name: str,
    *,
    version: str | None = None,
    download: bool = False,
    home: Path | None = None,
) -> dict[str, Any]:
    """
    Detect an engine; optionally request download (deferred in Sprint 0).

    If found: returns {status:\"ok\", ...detection fields, pinned?}.
    If missing and download=False: {status:\"missing\", message:...}.
    If missing and download=True: {status:\"download_deferred\", message:...}
    — Sprint 0 does not download arbitrary binaries from the internet
    (honesty > fake download). Pin remains detect+stamp only.
    """
    found = detect_engine(name, home=home)
    pinned = list_pinned(home).get(name)

    if found:
        status: dict[str, Any] = {
            "status": "ok",
            **found,
            "pinned": pinned,
        }
        if version and found.get("version") and version not in str(found["version"]):
            status["version_note"] = (
                f"requested {version!r}; detected {found['version']!r}"
            )
        return status

    if download:
        return {
            "status": "download_deferred",
            "name": name,
            "requested_version": version,
            "pinned": pinned,
            "message": (
                "Engine download is deferred in Sprint 0 — pin is detect+stamp "
                "only. Place the binary under SENTINEL_HOME/bin or on PATH, "
                "then pin_engine(name, version)."
            ),
        }

    return {
        "status": "missing",
        "name": name,
        "requested_version": version,
        "pinned": pinned,
        "message": (
            f"engine {name!r} not found on PATH or under {bin_dir(home)}; "
            "download=False so no fetch attempted"
        ),
    }
