"""Vetted engine download allowlist — Sprint 0.

Only entries in ENGINE_ALLOWLIST may be fetched. Keep empty until a real
third-party release can be pinned with version + URL + sha256. Deferred
engine names are documented here and in docs/ENGINES.md; they are never
fetched until hashed and allowlisted.
"""

from __future__ import annotations

from typing import Any

# name → {version, url, sha256, filename}
# Empty by default: do not invent hashes for third-party releases.
ENGINE_ALLOWLIST: dict[str, dict[str, str]] = {}

# Known useful engines not yet hashed — never download; doctor reports deferred.
DEFERRED_ENGINES: tuple[str, ...] = (
    "subfinder",
    "httpx",
    "naabu",
    "nuclei",
    "dnsx",
    "katana",
    "ffuf",
)

# Names doctor also probes for "detected" (stdlib / common PATH tools).
COMMON_DETECT: tuple[str, ...] = (
    "python",
    "python3",
    "true",
    "curl",
    "wget",
    "nmap",  # optional; missing → doctor Naabu-class degrade (Phase F)
)


def get_allowlist_entry(name: str) -> dict[str, str] | None:
    """Return a copy of the allowlist entry or None."""
    entry = ENGINE_ALLOWLIST.get(name)
    if entry is None:
        return None
    return dict(entry)


def is_allowlisted(name: str) -> bool:
    return name in ENGINE_ALLOWLIST


def is_deferred(name: str) -> bool:
    return name in DEFERRED_ENGINES and name not in ENGINE_ALLOWLIST


def set_allowlist_for_tests(entries: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    """
    Replace ENGINE_ALLOWLIST in-process for tests. Returns previous mapping.

    Production code should not call this — tests only.
    """
    previous = dict(ENGINE_ALLOWLIST)
    ENGINE_ALLOWLIST.clear()
    ENGINE_ALLOWLIST.update(entries)
    return previous


def describe_allowlist() -> dict[str, Any]:
    """Snapshot for docs / doctor."""
    return {
        "allowlisted": sorted(ENGINE_ALLOWLIST.keys()),
        "deferred": list(DEFERRED_ENGINES),
        "common_detect": list(COMMON_DETECT),
    }
