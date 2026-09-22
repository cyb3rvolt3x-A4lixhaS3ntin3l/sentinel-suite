"""ATO / OAuth / OIDC hunt pack v0 — candidates + evidence stubs only."""

from __future__ import annotations

from typing import Any

from gungnir.packs.ato_oauth_oidc.checks import run_checks
from gungnir.packs.manifest import PackManifest

MANIFEST = PackManifest(
    id="ato_oauth_oidc",
    pack_class="ato_oauth",
    needs_roles=1,
    consumes=("URL", "ENDPOINT", "SESSION"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "Detect OAuth/OIDC/SAML/login/reset surface candidates and emit "
        "defensive finding candidates (redirect_uri/state/PKCE, token leakage "
        "patterns, password-reset enumeration). Lab fixtures + mocked HTTP only "
        "in tests; optional scoped_request for authorized targets."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns {candidates: [...], notes: [...]}."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
