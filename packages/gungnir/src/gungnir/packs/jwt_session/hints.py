"""Coach hints for JWT / session-fixation patterns — questions a hunter should ask.

Hints are NOT auto-confirmed vulnerabilities. Default pack output never
marks findings verified/confirmed; a human must confirm explicitly.
"""

from __future__ import annotations

from typing import Any

# Pattern kinds the coach recognizes.
PATTERN_KINDS = (
    "session_fixation",
    "jwt_alg_none",
    "jwt_weak_alg",
    "jwt_missing_exp",
    "jwt_kid_confusion",
    "token_query_leak",
    "generic_jwt_session",
)

_HINTS: dict[str, list[str]] = {
    "session_fixation": [
        "Is the session cookie value identical before and after successful login?",
        "Does the server issue a new Set-Cookie on auth success (rotation)?",
        "Could an attacker fixate a pre-auth session id and wait for the victim to log in?",
        "Are secondary session identifiers (CSRF, device) also rotated on auth?",
        "Needs human: cite fixture pre-login cookie == post-login cookie evidence.",
    ],
    "jwt_alg_none": [
        "Does the verifier accept alg=none (unsigned) tokens from fixtures?",
        "Is the algorithm allowlist explicit (deny-by-default) rather than trusting header.alg?",
        "Would rejecting alg=none break any legitimate client flows?",
        "Are unsigned tokens rejected even when the signature segment is empty?",
        "Needs human: decoded fixture JWT header must show alg=none — do not mint live tokens.",
    ],
    "jwt_weak_alg": [
        "Is a symmetric alg (HS*) accepted where fixtures expect asymmetric (RS*/ES*/PS*)?",
        "Could an attacker swap alg and sign with a known public key as HMAC secret?",
        "Is the expected algorithm pinned per issuer / key id rather than trusted from the token?",
        "Document fixture expected_alg vs observed header.alg — never invent live tokens.",
        "Needs human: weak-alg candidate is fixture-decoded only until confirmed.",
    ],
    "jwt_missing_exp": [
        "Does the fixture JWT payload omit exp (or set it far in the future without bound)?",
        "Are nbf / iat validated alongside exp?",
        "Could a missing-exp token live forever in browser storage or logs?",
        "Is clock skew tolerance documented and bounded?",
        "Needs human: cite decoded fixture payload missing exp field.",
    ],
    "jwt_kid_confusion": [
        "Does the fixture JWT header kid look like a path / URL / traversal (../, file:, http)?",
        "Is kid used to select keys from a closed allowlist only?",
        "Could a malicious kid force loading an attacker-controlled key material?",
        "Are JWKS lookups constrained to known hosts (no SSRF via kid/jku/x5u)?",
        "Needs human: cite fixture kid string — do not probe live JWKS with forged kids.",
    ],
    "token_query_leak": [
        "Does the fixture URL carry access_token / id_token / jwt in query or fragment?",
        "Would tokens in query leak via Referer, logs, browser history, or analytics?",
        "Prefer HttpOnly Secure cookies (or POST body) over query/fragment for tokens.",
        "Are fragments stripped before server-side logging?",
        "Needs human: cite fixture URL query/fragment evidence — no live token exfil.",
    ],
    "generic_jwt_session": [
        "Staging/lab first — never treat this pack as a live token-theft toolkit.",
        "Evidence = same session cookie before+after login; decoded JWT alg/kid/exp; token in query/fragment.",
        "Analyze fixture tokens only — do not mint attack payloads or hammer live IdPs.",
        "Rotate session on auth; reject alg=none; put tokens in cookies not query (coach).",
        "Never auto-confirm — use sentinel hunt confirm-finding after review.",
        "Cannot: live IdP hammering + token exfil modules.",
    ],
}


def hints_for_pattern(kind: str) -> list[str]:
    """Return coach-hint questions for a jwt_session pattern kind (never empty)."""
    key = (kind or "generic_jwt_session").strip().lower()
    if key not in _HINTS:
        key = "generic_jwt_session"
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
            "Cannot: live IdP hammering + token exfil."
        ),
        "verification": "needs_human",
    }


__all__ = [
    "PATTERN_KINDS",
    "build_hint_record",
    "hints_for_pattern",
]
