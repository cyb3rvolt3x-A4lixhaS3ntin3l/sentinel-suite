"""Coach hints for cache / Host-header patterns — questions a hunter should ask.

Hints are NOT auto-confirmed vulnerabilities. Default pack output never
marks findings verified/confirmed; a human must confirm explicitly.
"""

from __future__ import annotations

from typing import Any

# Pattern kinds the coach recognizes.
PATTERN_KINDS = (
    "cache_control_weakness",
    "vary_weakness",
    "host_reflection",
    "x_forwarded_host",
    "x_forwarded_scheme",
    "path_confusion",
    "cache_key_mismatch",
    "generic_cache_host",
)

_HINTS: dict[str, list[str]] = {
    "cache_control_weakness": [
        "Is Cache-Control missing, public, or overly long max-age on sensitive responses?",
        "Does the response carry private / no-store when auth cookies are present?",
        "Could a shared cache store a response that reflected attacker Host headers?",
        "Are CDN cache policies aligned with origin Cache-Control intent?",
        "Needs human: Cache-Control strings are coach hints — confirm before VERIFIED.",
    ],
    "vary_weakness": [
        "Does Vary omit Host / Authorization / Cookie when those affect the body?",
        "Is Vary: User-Agent alone insufficient for Host-keyed content?",
        "Could a cache key that ignores X-Forwarded-Host poison a shared entry?",
        "Are normalized paths included in the cache key when path confusion exists?",
        "Needs human: Vary weakness is a hint — confirm keying with cache docs.",
    ],
    "host_reflection": [
        "Does the absolute URL / canonical link / Location reflect the request Host?",
        "Is the reflected Host value present in a cacheable body or header?",
        "Would an attacker-controlled Host land in a shared-cache entry?",
        "Is the reflection gated behind Cache-Control: private / no-store?",
        "Needs human: fixture header-in vs body/header-out diff required.",
    ],
    "x_forwarded_host": [
        "Does X-Forwarded-Host override Host for absolute URL generation?",
        "Is XFH trusted from the edge only, or from any client?",
        "Does the reflected XFH value appear in a cacheable response?",
        "Is Vary including X-Forwarded-Host when it affects the body?",
        "Needs human: cite fixture XFH-in vs reflected-out evidence.",
    ],
    "x_forwarded_scheme": [
        "Does X-Forwarded-Scheme / X-Forwarded-Proto flip https→http in links?",
        "Could scheme reflection create mixed-content or cookie-scope issues?",
        "Is the reflected scheme stored in a cacheable response body?",
        "Are scheme-dependent redirects keyed correctly in the cache?",
        "Needs human: fixture scheme-in vs body/header-out required.",
    ],
    "path_confusion": [
        "Do /foo and /foo/ (or encoded / %2e / semicolon) normalize differently?",
        "Does the origin treat path A equivalent while the cache keys them apart?",
        "Or the reverse: cache collapses keys while origin serves different content?",
        "Are path-normalization rules documented for the CDN / reverse proxy?",
        "Needs human: fixture must show cache_key_a != cache_key_b with content diff.",
    ],
    "cache_key_mismatch": [
        "Do two requests that should share a key actually get different keys (or vice versa)?",
        "Is Host / path / query / header inclusion inconsistent between origin and CDN?",
        "Could key mismatch enable cache deception against a victim path?",
        "Document key A vs key B strings from fixtures — never infer from theory alone.",
        "Needs human: concrete key-mismatch evidence before any VERIFIED claim.",
    ],
    "generic_cache_host": [
        "Staging/lab first — never treat this pack as a production CDN poison weapon.",
        "Evidence = header-in vs body/header-out diffs, or cache-key A vs B strings.",
        "Never emit on Host / X-Forwarded-* header name alone without reflection evidence.",
        "Cache-Control / Vary findings stay coach hints until a human confirms impact.",
        "Never auto-confirm — use sentinel hunt confirm-finding after review.",
    ],
}


def hints_for_pattern(kind: str) -> list[str]:
    """Return coach-hint questions for a cache_host pattern kind (never empty)."""
    key = (kind or "generic_cache_host").strip().lower()
    if key not in _HINTS:
        key = "generic_cache_host"
    return list(_HINTS[key])


def build_hint_record(
    *,
    pattern_kind: str,
    host: str | None = None,
    url: str | None = None,
    extra: list[str] | None = None,
) -> dict[str, Any]:
    """Structured coach-hint record (not a verified finding)."""
    questions = hints_for_pattern(pattern_kind)
    if extra:
        for q in extra:
            if q and q not in questions:
                questions.append(q)
    return {
        "kind": "coach_hints",
        "pattern_kind": pattern_kind,
        "host": host,
        "url": url,
        "questions": questions,
        "note": (
            "Coach hints only — not auto-confirmed vulns; "
            "human must confirm before VERIFIED/confirmed. "
            "Cannot: poison production CDN."
        ),
        "verification": "needs_human",
    }


__all__ = [
    "PATTERN_KINDS",
    "build_hint_record",
    "hints_for_pattern",
]
