"""HTTP desync / request-smuggling hunt pack — lab fixture evidence (Phase C slice12)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.http_desync.checks import run_checks
from gungnir.packs.manifest import PackManifest

MANIFEST = PackManifest(
    id="http_desync",
    pack_class="http_desync",
    needs_roles=0,
    consumes=("URL", "ENDPOINT", "SESSION"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "HTTP desync / request-smuggling pack v0 — fixture-driven CL.TE / TE.CL / "
        "header-smuggle candidates from differential response markers "
        "(status/body/header diffs across ambiguous interpretations). "
        "Off by default for open-internet; staging/lab first. Beyond pure "
        "fixtures requires BOTH --i-own-this AND --i-understand-lab "
        "(plus --scope for open-internet). Hard request caps ≤10. "
        "Findings stay needs_human; never auto-VERIFIED. "
        "Not a production CDN/WAF smuggling weapon; no DoS/flood. "
        "Coach: desync is lab/staging; production needs written auth + "
        "careful coordination. Authorized / lab only."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns candidates/notes/hints/caps/observations."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
