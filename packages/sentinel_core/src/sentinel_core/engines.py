"""Engine pin MVP — detect, stamp, allowlist-only download under SENTINEL_HOME/bin."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel_core.engine_allowlist import (
    COMMON_DETECT,
    DEFERRED_ENGINES,
    ENGINE_ALLOWLIST,
    describe_allowlist,
    get_allowlist_entry,
    is_allowlisted,
    is_deferred,
)
from sentinel_core.programs import get_sentinel_home

# Schemes permitted for allowlisted downloads (file:// for tests only when allowlisted).
_ALLOWED_SCHEMES = frozenset({"https", "http", "file"})


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
    Does not mutate system PATH.
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
    Never mutates PATH.
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


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _fetch_to_path(url: str, dest: Path) -> None:
    """Download url into dest. Only https/http/file schemes."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"refused URL scheme {parsed.scheme!r}; only {sorted(_ALLOWED_SCHEMES)} allowed"
        )
    # Reject arbitrary non-allowlisted use is enforced by caller; here scheme only.
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 — allowlist-gated
            data = resp.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"download failed for {url!r}: {exc}") from exc
    dest.write_bytes(data)


def download_allowlisted_engine(
    name: str,
    *,
    home: Path | None = None,
) -> dict[str, Any]:
    """
    Download an engine that is present in ENGINE_ALLOWLIST.

    - Rejects unknown names (not in allowlist).
    - Never mutates system PATH.
    - Writes only under SENTINEL_HOME/bin/ after sha256 verify.
    - Pins via pin_engine on success.
    """
    entry = get_allowlist_entry(name)
    if entry is None:
        raise ValueError(
            f"engine {name!r} is not in ENGINE_ALLOWLIST; "
            "refusing arbitrary download. See docs/ENGINES.md "
            f"(deferred={is_deferred(name)})."
        )

    url = entry.get("url") or ""
    expected_sha = (entry.get("sha256") or "").lower().strip()
    version = entry.get("version") or "unknown"
    filename = entry.get("filename") or name

    if not url or not expected_sha:
        raise ValueError(
            f"allowlist entry for {name!r} missing url or sha256"
        )

    from urllib.parse import urlparse

    if urlparse(url).scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"refused URL scheme for {name!r}: {url!r}")

    target_dir = bin_dir(home)
    final_path = target_dir / filename

    with tempfile.TemporaryDirectory(prefix="sentinel-engine-") as tmp:
        tmp_path = Path(tmp) / filename
        _fetch_to_path(url, tmp_path)
        actual = _sha256_file(tmp_path)
        if actual.lower() != expected_sha:
            raise ValueError(
                f"sha256 mismatch for {name!r}: expected {expected_sha}, got {actual}"
            )
        # Atomic-ish rename into place
        shutil.move(str(tmp_path), str(final_path))
        try:
            final_path.chmod(0o755)
        except OSError:
            pass

    pinned = pin_engine(name, version, binary_path=final_path, home=home)
    return {
        "status": "downloaded",
        "name": name,
        "version": version,
        "path": str(final_path),
        "sha256": expected_sha,
        "pinned": pinned,
        "url": url,
    }


def ensure_engine(
    name: str,
    *,
    version: str | None = None,
    download: bool = False,
    home: Path | None = None,
) -> dict[str, Any]:
    """
    Detect an engine; optionally download from ENGINE_ALLOWLIST only.

    If found: {status:\"ok\", ...}.
    If missing and download=False: {status:\"missing\", ...}.
    If missing and download=True:
      - allowlisted → download + pin → {status:\"downloaded\", ...} or raise on failure
      - not allowlisted → {status:\"not_allowlisted\", ...} clear error (no fetch)
    Never mutates PATH. Never fetches arbitrary URLs.
    """
    found = detect_engine(name, home=home)
    pinned = list_pinned(home).get(name)

    if found:
        status: dict[str, Any] = {
            "status": "ok",
            **found,
            "pinned": pinned,
            "allowlisted": is_allowlisted(name),
            "deferred": is_deferred(name),
        }
        if version and found.get("version") and version not in str(found["version"]):
            status["version_note"] = (
                f"requested {version!r}; detected {found['version']!r}"
            )
        return status

    if download:
        if not is_allowlisted(name):
            return {
                "status": "not_allowlisted",
                "name": name,
                "requested_version": version,
                "pinned": pinned,
                "deferred": is_deferred(name),
                "message": (
                    f"engine {name!r} is not in the vetted ENGINE_ALLOWLIST; "
                    "refusing download. Place a binary under SENTINEL_HOME/bin "
                    "or on PATH and pin_engine(name, version), or wait until "
                    "the engine is hashed and allowlisted (see docs/ENGINES.md)."
                ),
            }
        result = download_allowlisted_engine(name, home=home)
        if version and result.get("version") and version != result["version"]:
            result["version_note"] = (
                f"requested {version!r}; allowlist has {result['version']!r}"
            )
        return result

    return {
        "status": "missing",
        "name": name,
        "requested_version": version,
        "pinned": pinned,
        "allowlisted": is_allowlisted(name),
        "deferred": is_deferred(name),
        "message": (
            f"engine {name!r} not found on PATH or under {bin_dir(home)}; "
            "download=False so no fetch attempted"
        ),
    }


def list_engine_status(home: Path | None = None) -> list[dict[str, Any]]:
    """
    Doctor-facing status rows: detected / pinned / allowlisted / deferred.

    Covers COMMON_DETECT + DEFERRED_ENGINES + allowlisted + currently pinned.
    """
    names: set[str] = set()
    names.update(COMMON_DETECT)
    names.update(DEFERRED_ENGINES)
    names.update(ENGINE_ALLOWLIST.keys())
    names.update(list_pinned(home).keys())

    rows: list[dict[str, Any]] = []
    pinned_map = list_pinned(home)
    for name in sorted(names):
        det = detect_engine(name, home=home)
        pin = pinned_map.get(name)
        rows.append(
            {
                "name": name,
                "detected": det is not None,
                "detected_path": det.get("path") if det else None,
                "detected_version": det.get("version") if det else None,
                "pinned": pin is not None,
                "pinned_version": pin.get("version") if pin else None,
                "allowlisted": is_allowlisted(name),
                "deferred": is_deferred(name),
            }
        )
    return rows


def engine_catalog_summary() -> dict[str, Any]:
    """Allowlist / deferred snapshot for docs and doctor footer."""
    return describe_allowlist()
