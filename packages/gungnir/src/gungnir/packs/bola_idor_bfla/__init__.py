"""BOLA / IDOR / BFLA hunt pack — dual-role fixture candidates (Phase C slice3)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.bola_idor_bfla.checks import run_checks
from gungnir.packs.manifest import PackManifest

MANIFEST = PackManifest(
    id="bola_idor_bfla",
    pack_class="bola_idor",
    needs_roles=2,
    consumes=("URL", "ENDPOINT", "SESSION", "ROLE_A", "ROLE_B"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "Detect horizontal IDOR, vertical/BFLA, and sibling-method confusion "
        "candidates from dual-role lab fixtures (Role A + Role B required). "
        "Fixture-driven mocked HTTP only in tests; evidence stubs from fixtures. "
        "No live multi-tenant abuse, no data destruction. "
        "Authorized / lab / bounty use only."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns {candidates: [...], notes: [...]}."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
