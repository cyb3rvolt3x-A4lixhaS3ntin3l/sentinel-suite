"""JWT / session-fixation hunt pack — fixture-driven evidence (Phase C slice11)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.jwt_session.checks import run_checks
from gungnir.packs.manifest import PackManifest

MANIFEST = PackManifest(
    id="jwt_session",
    pack_class="jwt_session",
    needs_roles=0,
    consumes=("URL", "ENDPOINT", "SESSION"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "JWT / session-fixation pack v0 — fixture-driven candidates for "
        "session ID not rotated after login (fixation), weak JWT handling "
        "(alg=none / weak alg / missing exp / kid confusion) decoded from "
        "fixture token strings only, and token-in-query/fragment leakage when "
        "fixtures show it. Evidence must cite fixture signals (same session "
        "cookie before+after login; decoded JWT header alg/kid/exp; token in "
        "query/fragment URL). Analyze fixture tokens only — do not mint attack "
        "payloads or hammer live IdPs. Hard request caps if any live mock used. "
        "Never auto-VERIFIED. Not a live token-theft toolkit. Authorized / lab only."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns candidates/notes/hints/caps."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
