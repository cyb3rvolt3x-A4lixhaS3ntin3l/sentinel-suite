"""GraphQL hunt pack — introspection / mutation auth / global-id candidates (Phase C slice6)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.graphql.checks import run_checks
from gungnir.packs.manifest import PackManifest

MANIFEST = PackManifest(
    id="graphql",
    pack_class="graphql",
    needs_roles=0,
    consumes=("URL", "ENDPOINT", "SESSION"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "GraphQL is not 'a URL' — fixture-driven candidates for introspection "
        "enabled/disabled, unauth vs auth mutation diffs (Role A optional; "
        "soft coach if missing), opaque/global ID enumeration-ish signals, "
        "and batch/alias abuse as needs_human hints only. Hard request caps "
        "if any live mock used. Never auto-VERIFIED. No data-dump modules; "
        "no live third-party GraphQL hammering. Authorized / lab only."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns candidates/notes/hints/caps."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
