"""Local program / graph zip export — free forever path (Phase G0).

Exports ``~/.sentinel/programs/<id>/`` (program.yml, scope, graph.sqlite,
roles, runs, reports, lab progress, …) into a zip under
``SENTINEL_HOME/exports/`` or an operator-chosen ``-o`` path.

100% local — no upload, no account, no network.
"""

from __future__ import annotations

import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel_core.programs import get_sentinel_home, program_dir

# Skip WAL sidecar noise and Python caches; include graph.sqlite itself.
_SKIP_NAMES = frozenset({".DS_Store", "Thumbs.db"})
_SKIP_SUFFIXES = frozenset({".pyc"})
_SKIP_DIR_NAMES = frozenset({"__pycache__", ".git"})


def exports_root(home: Path | None = None) -> Path:
    return (home or get_sentinel_home()) / "exports"


def _should_skip(rel: Path) -> bool:
    if any(part in _SKIP_DIR_NAMES for part in rel.parts):
        return True
    if rel.name in _SKIP_NAMES:
        return True
    if rel.suffix in _SKIP_SUFFIXES:
        return True
    # SQLite WAL/SHM are optional; include if present (not skipped)
    return False


def export_program_zip(
    program_id: str,
    *,
    output: str | Path | None = None,
    home: Path | None = None,
) -> dict[str, Any]:
    """
    Zip a program directory for offline backup / portability.

    Returns metadata: ``{program_id, zip_path, files, bytes, local_only}``.
    Raises ``FileNotFoundError`` if the program does not exist.
    """
    root = program_dir(program_id, home)
    if not root.is_dir():
        raise FileNotFoundError(
            f"no program {program_id!r} under {root.parent}; "
            f"run: sentinel program init {program_id}"
        )

    if output is not None:
        out = Path(output).expanduser().resolve()
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest_dir = exports_root(home)
        dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / f"{program_id}-{stamp}.zip"

    out.parent.mkdir(parents=True, exist_ok=True)

    files: list[str] = []
    total = 0
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Manifest first
        manifest = (
            f"# Sentinel Suite program export (local only)\n"
            f"program_id: {program_id}\n"
            f"exported_at: {datetime.now(timezone.utc).isoformat()}\n"
            f"source: {root}\n"
            f"phone_home: false\n"
            f"account_required: false\n"
        )
        zf.writestr(f"{program_id}/EXPORT_MANIFEST.txt", manifest)
        files.append(f"{program_id}/EXPORT_MANIFEST.txt")

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root)
            if _should_skip(rel):
                continue
            arcname = f"{program_id}/{rel.as_posix()}"
            zf.write(path, arcname=arcname)
            files.append(arcname)
            try:
                total += path.stat().st_size
            except OSError:
                pass

    return {
        "program_id": program_id,
        "zip_path": str(out),
        "files": files,
        "file_count": len(files),
        "source_bytes": total,
        "zip_bytes": out.stat().st_size if out.is_file() else 0,
        "local_only": True,
        "account_required": False,
        "network": False,
        "note": (
            "Offline zip of ~/.sentinel/programs/<id>/ — free forever path. "
            "No upload."
        ),
    }


__all__ = ["export_program_zip", "exports_root"]
