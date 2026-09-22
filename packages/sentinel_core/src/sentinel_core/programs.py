"""Program directory layout under SENTINEL_HOME."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from sentinel_core.graph import EventGraph

_DEFAULT_HOME = Path.home() / ".sentinel"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def get_sentinel_home() -> Path:
    """Return SENTINEL_HOME (env override) or ~/.sentinel."""
    raw = os.environ.get("SENTINEL_HOME")
    if raw:
        return Path(raw).expanduser().resolve()
    return _DEFAULT_HOME


def programs_root(home: Path | None = None) -> Path:
    return (home or get_sentinel_home()) / "programs"


def program_dir(program_id: str, home: Path | None = None) -> Path:
    if not _SAFE_ID.match(program_id):
        raise ValueError(f"invalid program_id: {program_id!r}")
    return programs_root(home) / program_id


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_program(program_id: str, home: Path | None = None) -> Path:
    """
    Create ~/.sentinel/programs/<id>/ with program.yml stub + empty graph.sqlite.
    Returns the program directory path.
    """
    root = program_dir(program_id, home)
    root.mkdir(parents=True, exist_ok=True)
    yml = root / "program.yml"
    if not yml.exists():
        yml.write_text(
            f"# Sentinel Suite program stub\n"
            f"id: {program_id}\n"
            f"name: {program_id}\n"
            f"platform: unknown\n"
            f"allow_count: 0\n"
            f"deny_count: 0\n"
            f"updated_at: {_utcnow_iso()}\n"
            f"layers_enabled: []\n"
            f"scope_file: scope.txt\n",
            encoding="utf-8",
        )
    scope = root / "scope.txt"
    if not scope.exists():
        scope.write_text(
            "# Allow one host/domain per line; lines starting with ! are deny\n",
            encoding="utf-8",
        )
    graph_path = root / "graph.sqlite"
    with EventGraph(graph_path):
        pass  # ensure WAL schema exists
    return root


def open_graph(program_id: str, home: Path | None = None) -> EventGraph:
    path = program_dir(program_id, home) / "graph.sqlite"
    if not path.exists():
        raise FileNotFoundError(
            f"no graph for program {program_id!r}; run: sentinel program init {program_id}"
        )
    return EventGraph(path)


def update_program_yml_fields(
    program_id: str,
    *,
    home: Path | None = None,
    name: str | None = None,
    platform: str | None = None,
    allow_count: int | None = None,
    deny_count: int | None = None,
    updated_at: str | None = None,
    layers_enabled: Sequence[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> Path:
    """
    Patch program.yml with L0 Program brain fields (minimal YAML, no PyYAML).

    Fields: name, platform, allow_count, deny_count, updated_at, layers_enabled.
    Also writes legacy aliases brief_platform / scope_allow_count / scope_deny_count
    when platform/counts are set (backward compatible with Sprint 0 import-brief).
    """
    root = program_dir(program_id, home)
    root.mkdir(parents=True, exist_ok=True)
    yml_path = root / "program.yml"
    text = yml_path.read_text(encoding="utf-8") if yml_path.exists() else ""
    lines = text.splitlines()

    keys: dict[str, str] = {}
    if name is not None:
        keys["name"] = str(name)
    if platform is not None:
        keys["platform"] = str(platform)
        keys["brief_platform"] = str(platform)
    if allow_count is not None:
        keys["allow_count"] = str(int(allow_count))
        keys["scope_allow_count"] = str(int(allow_count))
    if deny_count is not None:
        keys["deny_count"] = str(int(deny_count))
        keys["scope_deny_count"] = str(int(deny_count))
    if updated_at is not None:
        keys["updated_at"] = str(updated_at)
    elif keys:
        keys["updated_at"] = _utcnow_iso()
    if layers_enabled is not None:
        # YAML-ish inline list
        items = ", ".join(str(x) for x in layers_enabled)
        keys["layers_enabled"] = f"[{items}]"
    if extra:
        for k, v in extra.items():
            keys[str(k)] = str(v)

    if not keys:
        return yml_path

    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        stripped = line.strip()
        replaced = False
        for key, val in keys.items():
            if stripped.startswith(f"{key}:"):
                out.append(f"{key}: {val}")
                seen.add(key)
                replaced = True
                break
        if not replaced:
            out.append(line)
    for key, val in keys.items():
        if key not in seen:
            out.append(f"{key}: {val}")
    if not any(l.startswith("id:") for l in out):
        out.insert(0, f"id: {program_id}")
    yml_path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    return yml_path
