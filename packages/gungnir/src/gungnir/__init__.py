"""Gungnir hunt bridge + packs for Sentinel Suite — findings, evidence, correlate."""

from gungnir.bridge import (
    VERIFICATION_STATUSES,
    emit_evidence_event,
    emit_finding_event,
    emit_verified_finding,
    require_scope_or_lab,
    scoped_emit_finding,
)
from gungnir.correlate import correlate_findings
from gungnir.packs import (
    PackManifest,
    PackRunError,
    RoleSession,
    RoleSessionError,
    discover_packs,
    get_pack,
    list_pack_manifests,
    load_role_session,
    run_pack,
)
from gungnir.runner import run_hunt

__version__ = "0.1.0"
__all__ = [
    "VERIFICATION_STATUSES",
    "PackManifest",
    "PackRunError",
    "RoleSession",
    "RoleSessionError",
    "correlate_findings",
    "discover_packs",
    "emit_evidence_event",
    "emit_finding_event",
    "emit_verified_finding",
    "get_pack",
    "list_pack_manifests",
    "load_role_session",
    "require_scope_or_lab",
    "run_hunt",
    "run_pack",
    "scoped_emit_finding",
    "__version__",
]
