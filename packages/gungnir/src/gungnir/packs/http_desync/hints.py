"""Coach hints for HTTP desync / smuggling patterns — questions only.

Hints are NOT auto-confirmed vulnerabilities. Default pack output never
marks findings verified/confirmed; a human must confirm explicitly.
desync is lab/staging; production needs written auth + careful coordination.
"""

from __future__ import annotations

from typing import Any

PATTERN_KINDS = (
    "cl_te",
    "te_cl",
    "header_smuggle",
    "generic_desync",
)

_HINTS: dict[str, list[str]] = {
    "cl_te": [
        "Do front-end and back-end disagree on Content-Length vs Transfer-Encoding?",
        "Does the fixture show different status/body/headers under CL vs TE interpretation?",
        "Is Transfer-Encoding: chunked accepted while Content-Length is also present?",
        "Would normalizing to a single framing method close the differential?",
        "Needs human: cite fixture differential markers — do not run live CDN smuggling.",
    ],
    "te_cl": [
        "Does the front-end prefer TE while the back-end prefers CL (TE.CL)?",
        "Are chunked bodies terminated consistently across hops in the fixture?",
        "Could a desynced second request land on a privileged path in lab only?",
        "Is HTTP/1.1 hop-by-hop TE stripped before the origin?",
        "Needs human: fixture TE vs CL response diffs only — no live WAF campaigns.",
    ],
    "header_smuggle": [
        "Do ambiguous / obfuscated headers (folded, duplicate, whitespace) parse differently across hops?",
        "Does the fixture show a header value accepted by one hop and ignored by another?",
        "Could header smuggling confuse Host / X-Forwarded-* trust boundaries?",
        "Prefer rejecting obsolete line folding and duplicate critical headers.",
        "Needs human: cite fixture header differential — not a live header-spray tool.",
    ],
    "generic_desync": [
        "desync is lab/staging; production needs written auth + careful coordination",
        "Evidence = differential response markers (status/body/header) across ambiguous interpretations.",
        "Fixture-driven only by default — never craft live desync campaigns against public CDNs/WAFs.",
        "Hard request caps ≤10 for any non-pure-fixture path; dual --i-own-this + --i-understand-lab.",
        "Never auto-confirm — use sentinel hunt confirm-finding after review.",
        "Cannot: production CDN/WAF smuggling, DoS/flood, open-internet without lab dual-flag.",
    ],
}


def hints_for_pattern(kind: str) -> list[str]:
    """Return coach-hint questions for a desync pattern kind (never empty)."""
    key = (kind or "generic_desync").strip().lower().replace("-", "_").replace(".", "_")
    if key in {"clte", "content_length_te"}:
        key = "cl_te"
    if key in {"tecl", "te_content_length"}:
        key = "te_cl"
    if key not in _HINTS:
        key = "generic_desync"
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
            "desync is lab/staging; production needs written auth + careful coordination. "
            "Cannot: production CDN/WAF smuggling, DoS, open-internet without lab dual-flag."
        ),
        "verification": "needs_human",
    }


__all__ = [
    "PATTERN_KINDS",
    "build_hint_record",
    "hints_for_pattern",
]
