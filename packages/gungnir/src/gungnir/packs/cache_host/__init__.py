"""Cache / Host-header deception hunt pack — fixture-driven evidence (Phase C slice10)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.cache_host.checks import run_checks
from gungnir.packs.manifest import PackManifest

MANIFEST = PackManifest(
    id="cache_host",
    pack_class="cache_host",
    needs_roles=0,
    consumes=("URL", "ENDPOINT", "SESSION"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "Cache deception / Host-header reflection pack v0 — fixture-driven "
        "candidates for Host / X-Forwarded-Host / X-Forwarded-Scheme reflection "
        "into cacheable body/headers, path-confusion / URL-normalization "
        "cache-key mismatch when fixtures show differing keys, and "
        "Cache-Control / Vary weakness coach hints only. Evidence must cite "
        "fixture diffs (header-in vs body/header-out; key A vs B). Never emit "
        "on header name alone. Staging/lab first — not a live CDN poison "
        "weapon. Hard request caps if any live mock used. Never auto-VERIFIED. "
        "Authorized / lab only."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns candidates/notes/hints/caps."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
