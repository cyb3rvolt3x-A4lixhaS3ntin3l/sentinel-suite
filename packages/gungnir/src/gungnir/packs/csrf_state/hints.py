"""Coach hints for CSRF / state-token patterns — questions a hunter should ask.

Hints are NOT auto-confirmed vulnerabilities. Default pack output never
marks findings verified/confirmed; a human must confirm explicitly.
"""

from __future__ import annotations

from typing import Any

# Pattern kinds the coach recognizes.
PATTERN_KINDS = (
    "synchronizer_token",
    "double_submit_cookie",
    "samesite_cookie",
    "missing_token",
    "unbound_token",
    "generic_csrf",
)

_HINTS: dict[str, list[str]] = {
    "synchronizer_token": [
        "Is the CSRF token cryptographically random and rotated per session?",
        "Is the token bound to the user session (not a global/static value)?",
        "Does the server reject requests with a missing or mismatched token?",
        "Is the token single-use or at least rotated after sensitive actions?",
        "Is the token transmitted only via POST body / custom header (not in URL)?",
    ],
    "double_submit_cookie": [
        "Is the CSRF cookie marked Secure + HttpOnly (or intentionally not HttpOnly)?",
        "Does the server compare cookie value to a matching form/header field?",
        "Can an attacker set the cookie via subdomain / XSS and forge the twin field?",
        "Is SameSite=Strict or Lax set on the CSRF cookie?",
        "Is the cookie value unpredictable and not derived from a known session id?",
    ],
    "samesite_cookie": [
        "Is SameSite=None paired with Secure (required by modern browsers)?",
        "Would SameSite=Lax or Strict be sufficient for this cookie's role?",
        "Are session cookies missing SameSite entirely (legacy defaults vary)?",
        "Does a cross-site top-level GET still carry Lax cookies unintendedly?",
        "Needs human: confirm cookie role (session vs CSRF vs preference).",
    ],
    "missing_token": [
        "Does this state-changing endpoint accept POST/PUT/PATCH/DELETE with no CSRF defense?",
        "Is Origin / Referer checked as a secondary defense?",
        "Are custom headers (e.g. X-Requested-With) required and CORS-restricted?",
        "Can the action be triggered via a simple HTML form from another origin?",
        "Needs human: confirm impact of the state change before VERIFIED.",
    ],
    "unbound_token": [
        "Is the same CSRF token accepted across different sessions/users?",
        "Can a token harvested from one account be replayed on another?",
        "Is the token bound to a specific form action / resource id?",
        "Does token validation fail closed when the binding claim is absent?",
        "Needs human: fixture unbound marker is a candidate, not proof of exploit.",
    ],
    "generic_csrf": [
        "Which anti-CSRF pattern is intended (synchronizer vs double-submit)?",
        "Are SameSite cookie flags correct for the auth/session cookies?",
        "Are state-changing GETs present (should be POST+token instead)?",
        "Is CORS overly permissive for credentialed cross-origin requests?",
        "Never auto-confirm — use sentinel hunt confirm-finding after review.",
    ],
}


def hints_for_pattern(kind: str) -> list[str]:
    """Return coach-hint questions for a CSRF pattern kind (never empty)."""
    key = (kind or "generic_csrf").strip().lower()
    if key not in _HINTS:
        key = "generic_csrf"
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
