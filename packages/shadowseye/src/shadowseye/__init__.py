"""ShadowsEye thin bridge + runner for Sentinel Suite — inventory → graph."""

from shadowseye.bridge import (
    emit_dns_name_event,
    emit_domain_event,
    emit_ip_event,
    emit_open_port_event,
    inventory_to_events,
    scoped_emit_domain,
)
from shadowseye.runner import gather_inventory, require_scope_or_lab, run_eye

__version__ = "0.1.0"
__all__ = [
    "emit_dns_name_event",
    "emit_domain_event",
    "emit_ip_event",
    "emit_open_port_event",
    "gather_inventory",
    "inventory_to_events",
    "require_scope_or_lab",
    "run_eye",
    "scoped_emit_domain",
    "__version__",
]
