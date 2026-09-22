"""Business-logic assistant hunt pack — flow map + coach hints (Phase C slice4)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.business_logic.checks import run_checks
from gungnir.packs.manifest import PackManifest

MANIFEST = PackManifest(
    id="business_logic",
    pack_class="business_logic",
    needs_roles=1,
    consumes=("URL", "ENDPOINT", "SESSION", "FLOW", "STEP"),
    emits=("FLOW", "STEP", "FINDING", "EVIDENCE"),
    noise_class="low",
    description=(
        "Map multi-step business flows (cart→checkout, invite→accept, "
        "transfer→confirm, apply→approve) from fixtures / HTML stubs; "
        "emit FLOW/STEP + coach-hint checklists. Findings stay needs_human "
        "until explicit human confirm. Not a chatbot that invents bugs; "
        "no payment capture; no live abuse. Authorized / lab only."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns candidates/flows/steps/hints/notes."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
