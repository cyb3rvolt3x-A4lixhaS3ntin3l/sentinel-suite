"""Thin correlate — honest dedupe + stubs. NOT the 26-chain enhanced library."""

from __future__ import annotations

from typing import Any


def _host_of(finding: dict[str, Any]) -> str:
    for key in ("host", "asset", "target", "url"):
        val = finding.get(key)
        if val:
            return str(val).strip().lower()
    return ""


def _title_of(finding: dict[str, Any]) -> str:
    return str(finding.get("title") or finding.get("name") or "").strip().lower()


def correlate_findings(
    findings: list[dict[str, Any]],
    *,
    default_verification: str = "unverified",
) -> list[dict[str, Any]]:
    """
    Accept list[dict] findings; return findings with honest fields.

    - Dedupes by (title + host)
    - Sets verification / verification_status default to ``unverified``
    - Adds optional simple ``chain_stubs`` list (empty unless trivial parent hint)

    This is **not** a port of gungnir-harden enhanced_correlate (26+ attack
    chains). See packages/gungnir/README.md for what is NOT ported yet.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    for raw in findings:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        title = _title_of(item)
        host = _host_of(item)
        key = f"{title}|{host}"
        if key in seen:
            item["deduped"] = True
            # Skip duplicate — keep first
            continue
        seen.add(key)

        status = (
            str(
                item.get("verification")
                or item.get("verification_status")
                or default_verification
            )
            .strip()
            .lower()
            or default_verification
        )
        item["verification"] = status
        item["verification_status"] = status
        item["verified"] = status in ("verified", "confirmed")
        if "title" not in item and title:
            item["title"] = title
        if host and "host" not in item:
            item["host"] = host
        # Honest: no fabricated multi-finding attack chains here
        item.setdefault("chain_stubs", [])
        out.append(item)

    return out
