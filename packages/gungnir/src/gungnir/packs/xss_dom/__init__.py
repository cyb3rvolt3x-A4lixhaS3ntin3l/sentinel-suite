"""XSS/DOM hunt pack — source→sink sink-proof candidates (Phase C slice7)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.manifest import PackManifest
from gungnir.packs.xss_dom.checks import run_checks

MANIFEST = PackManifest(
    id="xss_dom",
    pack_class="xss_dom",
    needs_roles=0,
    consumes=("URL", "ENDPOINT", "SESSION"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "XSS/DOM sink-proof pack v0 — fixture-driven source→sink candidates "
        "(location/hash/postMessage → innerHTML/document.write/eval-ish) with "
        "evidence snippets proving a unique marker in sink context. Reflected/"
        "stored path stubs only in fixtures. Prefer marker-in-sink over alert(). "
        "Hard request caps if any live mock used. Never auto-VERIFIED. No dalfox "
        "binary / --tools / live mass scanning. Authorized / lab only."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns candidates/notes/hints/caps."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
