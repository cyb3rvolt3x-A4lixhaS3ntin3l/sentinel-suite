"""Coach hints for open-redirect patterns — questions a hunter should ask.

Hints are NOT auto-confirmed vulnerabilities. Default pack output never
marks findings verified/confirmed; a human must confirm explicitly.
"""

from __future__ import annotations

from typing import Any

# Pattern kinds the coach recognizes.
PATTERN_KINDS = (
    "allowlist_validation",
    "denylist_validation",
    "protocol_relative",
    "encoded_bypass",
    "location_header",
    "param_redirect",
    "generic_open_redirect",
)

_HINTS: dict[str, list[str]] = {
    "allowlist_validation": [
        "Is the redirect target validated against a strict allowlist of hosts/paths?",
        "Does the allowlist compare parsed hostname (not substring of the raw URL)?",
        "Are relative-path only redirects preferred over absolute external URLs?",
        "Does validation reject protocol-relative (//evil) and userinfo tricks?",
        "Needs human: confirm allowlist covers all intended login/post-auth destinations.",
    ],
    "denylist_validation": [
        "Is denylist (block evil.com) used instead of allowlist? Denylists are brittle.",
        "Can encoding / case / alternate TLDs bypass the denylist?",
        "Does the denylist miss protocol-relative and data:/javascript: schemes?",
        "Would switching to an allowlist of known-good hosts be safer?",
        "Needs human: denylist hits are candidates — confirm real bypass before VERIFIED.",
    ],
    "protocol_relative": [
        "Does //evil.example pass validation that only strips http(s): prefixes?",
        "Is the Location header built by concatenating an untrusted // URL?",
        "Do browsers treat protocol-relative Location as same-scheme absolute?",
        "Are nested encodings (%2F%2Fevil) normalized before the allowlist check?",
        "Needs human: fixture //evil signal is a candidate, not a live exploit.",
    ],
    "encoded_bypass": [
        "Are URL-encoded slashes / dots / schemes decoded before host comparison?",
        "Does double-encoding (%252F%252F) survive a single decode pass?",
        "Are backslash (\\) or @ userinfo tricks accepted as path vs host?",
        "Is unicode / IDN homograph normalization applied?",
        "Needs human: encoded fixture markers need decode-path confirmation.",
    ],
    "location_header": [
        "Does the Location response header reflect an attacker-controlled query value?",
        "Is the reflected value an absolute URL to an external host?",
        "Are 3xx status codes paired with the reflected Location?",
        "Could meta-refresh / JS redirect equivalents mirror the same bug?",
        "Needs human: confirm Location reflection is not same-origin only.",
    ],
    "param_redirect": [
        "Do next/return/url/redirect/continue params drive a server-side redirect?",
        "Is there evidence (Location / redirect_to) — not merely a param name present?",
        "Is the destination host different from the request host (external)?",
        "Are open redirects chained into OAuth redirect_uri / login flows?",
        "Never emit on bare param presence without redirect evidence.",
    ],
    "generic_open_redirect": [
        "Prefer allowlist of destinations over denylist of evil hosts.",
        "Parse then validate hostname; never substring-match the raw URL string.",
        "Reject protocol-relative, data:, javascript:, and encoded bypass forms.",
        "For post-login returns, prefer signed relative paths over absolute URLs.",
        "Never auto-confirm — use sentinel hunt confirm-finding after review.",
    ],
}


def hints_for_pattern(kind: str) -> list[str]:
    """Return coach-hint questions for an open-redirect pattern kind (never empty)."""
    key = (kind or "generic_open_redirect").strip().lower()
    if key not in _HINTS:
        key = "generic_open_redirect"
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
            "human must confirm before VERIFIED/confirmed"
        ),
        "verification": "needs_human",
    }


__all__ = [
    "PATTERN_KINDS",
    "build_hint_record",
    "hints_for_pattern",
]
