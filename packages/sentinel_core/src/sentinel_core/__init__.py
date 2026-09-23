"""sentinel_core — shared event graph, scope kernel, engine pin for Sentinel Suite."""

from sentinel_core.engine_allowlist import (
    COMMON_DETECT,
    DEFERRED_ENGINES,
    ENGINE_ALLOWLIST,
    describe_allowlist,
    is_allowlisted,
    is_deferred,
)
from sentinel_core.engines import (
    bin_dir,
    detect_engine,
    download_allowlisted_engine,
    ensure_engine,
    engine_catalog_summary,
    list_engine_status,
    list_pinned,
    pin_engine,
    stamp_run,
)
from sentinel_core.events import EVENT_TYPES, Event
from sentinel_core.graph import EventGraph
from sentinel_core.http_guard import (
    PreparedScopedRequest,
    assert_url_in_scope,
    host_from_url,
    prepare_scoped_request,
    scoped_request,
)
from sentinel_core.programs import (
    create_program,
    get_sentinel_home,
    list_programs,
    open_graph,
    program_dir,
    update_program_yml_fields,
)
from sentinel_core.scope import (
    Scope,
    ScopeDenied,
    detect_brief_platform,
    load_scope_file,
    load_scope_text,
    parse_brief,
    parse_brief_stub,
    scope_to_raw_text,
)

__version__ = "0.1.0"

__all__ = [
    "COMMON_DETECT",
    "DEFERRED_ENGINES",
    "ENGINE_ALLOWLIST",
    "EVENT_TYPES",
    "Event",
    "EventGraph",
    "PreparedScopedRequest",
    "Scope",
    "ScopeDenied",
    "assert_url_in_scope",
    "bin_dir",
    "create_program",
    "describe_allowlist",
    "detect_brief_platform",
    "detect_engine",
    "download_allowlisted_engine",
    "ensure_engine",
    "engine_catalog_summary",
    "get_sentinel_home",
    "host_from_url",
    "is_allowlisted",
    "is_deferred",
    "list_engine_status",
    "list_pinned",
    "list_programs",
    "load_scope_file",
    "load_scope_text",
    "open_graph",
    "parse_brief",
    "parse_brief_stub",
    "pin_engine",
    "prepare_scoped_request",
    "program_dir",
    "update_program_yml_fields",
    "scope_to_raw_text",
    "scoped_request",
    "stamp_run",
    "__version__",
]
