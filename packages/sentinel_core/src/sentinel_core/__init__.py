"""sentinel_core — shared event graph, scope kernel, engine pin for Sentinel Suite."""

from sentinel_core.engines import bin_dir, list_pinned, pin_engine, stamp_run
from sentinel_core.events import EVENT_TYPES, Event
from sentinel_core.graph import EventGraph
from sentinel_core.programs import (
    create_program,
    get_sentinel_home,
    open_graph,
    program_dir,
)
from sentinel_core.scope import Scope, ScopeDenied, load_scope_file, load_scope_text, parse_brief_stub

__version__ = "0.1.0"

__all__ = [
    "EVENT_TYPES",
    "Event",
    "EventGraph",
    "Scope",
    "ScopeDenied",
    "bin_dir",
    "create_program",
    "get_sentinel_home",
    "list_pinned",
    "load_scope_file",
    "load_scope_text",
    "open_graph",
    "parse_brief_stub",
    "pin_engine",
    "program_dir",
    "stamp_run",
    "__version__",
]
