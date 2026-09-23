"""SSRF collaborator hunt pack — owned collaborator stubs + local listener (Phase C slice15)."""

from __future__ import annotations

from typing import Any

from gungnir.packs.manifest import PackManifest
from gungnir.packs.ssrf_collaborator.checks import run_checks

MANIFEST = PackManifest(
    id="ssrf_collaborator",
    pack_class="ssrf_collaborator",
    needs_roles=0,
    consumes=("URL", "ENDPOINT", "SESSION"),
    emits=("FINDING", "EVIDENCE"),
    noise_class="med",
    description=(
        "SSRF collaborator pack v0 — fixture-driven URL-param / header-injection "
        "candidates with operator-owned collaborator callback markers. "
        "Default collaborator = local 127.0.0.1 fixture mock. "
        "Optional --listen starts a localhost-owned callback listener "
        "(bind 127.0.0.1 by default; COLLABORATOR_HIT events). "
        "Optional --collaborator must be operator-owned; refuses cloud metadata "
        "IPs (169.254.169.254 / metadata.google.internal / Azure IMDS) unless "
        "--i-understand-lab AND documented lab fixture mode. "
        "Open-internet SSRF probes require --scope + --i-own-this + "
        "--i-understand-lab. Hard request caps ≤10; listen caps duration≤120s "
        "default / hits≤50. Findings stay needs_human; never auto-VERIFIED. "
        "DNS rebinding = coach hints only. No interactsh; no outbound scan. "
        "NOT a cloud-metadata attack kit; NOT a random-internet SSRF scanner. "
        "Authorized / lab only."
    ),
    version="0",
)


def run(ctx: dict[str, Any]) -> dict[str, Any]:
    """Pack entrypoint — returns candidates/notes/hints/caps/observations."""
    return run_checks(ctx)


__all__ = ["MANIFEST", "run"]
