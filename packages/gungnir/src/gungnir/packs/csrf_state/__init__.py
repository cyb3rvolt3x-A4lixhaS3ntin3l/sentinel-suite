"""CSRF / state-token hunt pack — fixture-driven anti-CSRF candidates (Phase C slice8)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.csrf_state.checks import run_checks
from gungnir.packs.manifest import PackManifest

MANIFEST = PackManifest(
    id="csrf_state",
    pack_class="csrf_state",
    needs_roles=0,
    consumes=("URL", "ENDPOINT", "SESSION"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "CSRF / state-token pack v0 — fixture-driven candidates for missing "
        "anti-CSRF on state-changing methods, unbound/reusable tokens, and "
        "weak cookie flags (SameSite=None without Secure). Double-submit vs "
        "synchronizer-token patterns are coach hints only. Evidence cites "
        "concrete fixture signals (missing token field, cookie flag string, "
        "unbound marker). Hard request caps if any live mock used. Never "
        "auto-VERIFIED. No cross-site CSRF farms / form flood. Authorized / lab only."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns candidates/notes/hints/caps."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
