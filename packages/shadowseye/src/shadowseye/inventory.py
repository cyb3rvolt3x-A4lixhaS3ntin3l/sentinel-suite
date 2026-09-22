"""Inventory JSON schema helpers — normalize / extend ShadowsEye inventory."""

from __future__ import annotations

from typing import Any


def empty_inventory() -> dict[str, Any]:
    """Canonical empty inventory (backward-compatible keys + Phase B fields)."""
    return {
        "domains": [],
        "dns_names": [],
        "ips": [],
        "ports": [],
        "http": [],
        "tech": [],
        "identity": [],
        "sources": [],
        "ranked": [],
        "notes": [],
    }


def normalize_inventory(raw: dict[str, Any] | None) -> dict[str, Any]:
    """
    Ensure inventory has Phase B keys without dropping existing data.

    Keeps backward compatibility with Sprint 0 shape (domains/dns_names/ips/ports).
    """
    base = empty_inventory()
    if not raw:
        return base
    out = dict(base)
    for key in (
        "domains",
        "dns_names",
        "ips",
        "ports",
        "http",
        "tech",
        "identity",
        "sources",
        "ranked",
        "notes",
    ):
        if key in raw and raw[key] is not None:
            out[key] = list(raw[key]) if isinstance(raw[key], (list, tuple)) else raw[key]
    # Preserve any extra keys callers may have added
    for key, val in raw.items():
        if key not in out:
            out[key] = val
    return out


def merge_sources(inventory: dict[str, Any], *sources: str) -> dict[str, Any]:
    """Append unique source labels to inventory['sources']."""
    inv = normalize_inventory(inventory)
    seen = {str(s).lower() for s in inv.get("sources") or []}
    for src in sources:
        s = str(src).strip()
        if not s:
            continue
        if s.lower() not in seen:
            inv["sources"].append(s)
            seen.add(s.lower())
    return inv


def dns_name_strings(inventory: dict[str, Any]) -> list[str]:
    """Flatten dns_names entries to hostname strings."""
    names: list[str] = []
    seen: set[str] = set()
    for raw in inventory.get("dns_names") or []:
        if isinstance(raw, str):
            name = raw.strip().lower().rstrip(".")
        else:
            name = str(raw.get("name") or raw.get("dns_name") or "").strip().lower().rstrip(".")
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names
