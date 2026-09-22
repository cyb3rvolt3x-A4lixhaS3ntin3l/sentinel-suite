"""ShadowsEye — L0/L1/L2/L5 + tech fingerprint + ranker + watch (Phase B slice3)."""

from shadowseye.bridge import (
    emit_dns_name_event,
    emit_domain_event,
    emit_identity_event,
    emit_ip_event,
    emit_open_port_event,
    emit_tech_event,
    emit_url_event,
    inventory_to_events,
    scoped_emit_domain,
)
from shadowseye.identity import gather_identity, merge_identity_into_inventory
from shadowseye.passive import crtsh_query, reverse_ip_neighbours
from shadowseye.tech_fingerprint import fingerprint, fingerprint_http_rows
from shadowseye.ranker import rank_inventory, score_hostname
from shadowseye.runner import gather_inventory, require_scope_or_lab, run_eye
from shadowseye.watch import diff_snapshots, watch_compare_and_persist

__version__ = "0.1.0"
__all__ = [
    "crtsh_query",
    "diff_snapshots",
    "emit_dns_name_event",
    "emit_domain_event",
    "emit_identity_event",
    "emit_ip_event",
    "emit_open_port_event",
    "emit_tech_event",
    "emit_url_event",
    "gather_identity",
    "fingerprint",
    "fingerprint_http_rows",
    "gather_inventory",
    "inventory_to_events",
    "merge_identity_into_inventory",
    "rank_inventory",
    "require_scope_or_lab",
    "reverse_ip_neighbours",
    "run_eye",
    "scoped_emit_domain",
    "score_hostname",
    "watch_compare_and_persist",
    "__version__",
]
