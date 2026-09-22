"""Gungnir thin bridge + runner for Sentinel Suite — findings, evidence, correlate."""

from gungnir.bridge import (
    VERIFICATION_STATUSES,
    emit_evidence_event,
    emit_finding_event,
    emit_verified_finding,
    require_scope_or_lab,
    scoped_emit_finding,
)
from gungnir.correlate import correlate_findings
from gungnir.runner import run_hunt

__version__ = "0.1.0"
__all__ = [
    "VERIFICATION_STATUSES",
    "correlate_findings",
    "emit_evidence_event",
    "emit_finding_event",
    "emit_verified_finding",
    "require_scope_or_lab",
    "run_hunt",
    "scoped_emit_finding",
    "__version__",
]
