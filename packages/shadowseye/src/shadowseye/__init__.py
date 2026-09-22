"""ShadowsEye — L0/L2/L5 lite + ranker + watch (Phase B slice1)."""

from shadowseye.bridge import (
    emit_dns_name_event,
    emit_domain_event,
    emit_ip_event,
    emit_open_port_event,
    emit_url_event,
    inventory_to_events,
    scoped_emit_domain,
)
from shadowseye.passive import crtsh_query
from shadowseye.ranker import rank_inventory, score_hostname
from shadowseye.runner import gather_inventory, require_scope_or_lab, run_eye
from shadowseye.watch import diff_snapshots, watch_compare_and_persist

__version__ = "0.1.0"
__all__ = [
    "crtsh_query",
    "diff_snapshots",
    "emit_dns_name_event",
    "emit_domain_event",
    "emit_ip_event",
    "emit_open_port_event",
    "emit_url_event",
    "gather_inventory",
    "inventory_to_events",
    "rank_inventory",
    "require_scope_or_lab",
    "run_eye",
    "scoped_emit_domain",
    "score_hostname",
    "watch_compare_and_persist",
    "__version__",
]
