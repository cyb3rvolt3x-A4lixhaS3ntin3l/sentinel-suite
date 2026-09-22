"""ShadowsEye thin bridge for Sentinel Suite — inventory event emitters."""

from shadowseye.bridge import (
    emit_dns_name_event,
    emit_domain_event,
    emit_ip_event,
    emit_open_port_event,
    inventory_to_events,
    scoped_emit_domain,
)

__version__ = "0.1.0"
__all__ = [
    "emit_dns_name_event",
    "emit_domain_event",
    "emit_ip_event",
    "emit_open_port_event",
    "inventory_to_events",
    "scoped_emit_domain",
    "__version__",
]
