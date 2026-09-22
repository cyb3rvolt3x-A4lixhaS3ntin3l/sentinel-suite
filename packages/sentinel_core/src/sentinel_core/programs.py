"""Program directory layout under SENTINEL_HOME."""

from __future__ import annotations

import os
import re
from pathlib import Path

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
