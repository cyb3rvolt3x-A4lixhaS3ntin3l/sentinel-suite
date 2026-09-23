"""Open redirect hunt pack — fixture-driven unvalidated redirect candidates (Phase C slice9)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.manifest import PackManifest
from gungnir.packs.open_redirect.checks import run_checks

MANIFEST = PackManifest(
    id="open_redirect",
    pack_class="open_redirect",
    needs_roles=0,
    consumes=("URL", "ENDPOINT", "SESSION"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "Open redirect / unvalidated redirect pack v0 — fixture-driven candidates "
        "for next/return/url/redirect/continue params that redirect to external "
        "hosts, protocol-relative //evil and encoded bypass forms, and Location "
        "header reflection — only when fixtures show concrete redirect evidence "
        "(never bare param-name noise). Allowlist vs denylist coach hints only. "
        "Hard request caps if any live mock used. Never auto-VERIFIED. No browser "
        "automation / live redirect farms. Authorized / lab only."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns candidates/notes/hints/caps."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
