"""Gungnir thin bridge for Sentinel Suite — findings, evidence, scope gate."""

from gungnir.bridge import (
    VERIFICATION_STATUSES,
    emit_evidence_event,
    emit_finding_event,
    emit_verified_finding,
    require_scope_or_lab,
    scoped_emit_finding,
)

__version__ = "0.1.0"
__all__ = [
    "VERIFICATION_STATUSES",
    "emit_evidence_event",
    "emit_finding_event",
    "emit_verified_finding",
    "require_scope_or_lab",
    "scoped_emit_finding",
    "__version__",
]
