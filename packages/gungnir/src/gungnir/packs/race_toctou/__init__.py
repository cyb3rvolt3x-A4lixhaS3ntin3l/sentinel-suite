"""Race / TOCTOU hunt pack — hard-capped lab detection scaffolding (Phase C slice5)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.manifest import PackManifest
from gungnir.packs.race_toctou.checks import run_checks

MANIFEST = PackManifest(
    id="race_toctou",
    pack_class="race_toctou",
    needs_roles=1,
    consumes=("URL", "ENDPOINT", "SESSION"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "Detect TOCTOU / race candidates from fixture mock timing windows "
        "with hard caps (workers≤4, requests≤20, duration≤5s). "
        "Default target = in-process / 127.0.0.1 fixture mock. "
        "Findings stay needs_human; never auto-VERIFIED. "
        "Not a DoS weapon; no lockout/flood; no payment capture. "
        "Authorized / lab only — race packs are lab-first; production "
        "programs need written authorization + rate limits."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns candidates/notes/caps/observations."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
