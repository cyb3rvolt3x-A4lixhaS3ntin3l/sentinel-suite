"""Coach hints for SSRF collaborator patterns — questions only.

Hints are NOT auto-confirmed vulnerabilities. Default pack output never
marks findings verified/confirmed; a human must confirm explicitly.
"""

from __future__ import annotations

from typing import Any

PATTERN_KINDS = (
    "url_param",
    "header_injection",
    "dns_rebind",
    "generic_ssrf",
)

_HINTS: dict[str, list[str]] = {
    "url_param": [
        "Does a URL/query parameter cause the app to fetch an operator-owned collaborator?",
        "Do fixtures show a collaborator callback marker or outbound URL to the collaborator?",
        "Is the fetch allowlisted / blocked for link-local and cloud metadata addresses?",
        "Would requiring an allowlist of outbound hosts close the candidate?",
        "Needs human: cite collaborator hit markers — do not probe 169.254.169.254 live.",
    ],
    "header_injection": [
        "Do Host / X-Forwarded-Host / Forwarded headers influence the outbound fetch URL?",
        "Does the fixture show the collaborator receiving a request after header injection?",
        "Is the outbound URL built from untrusted header values?",
        "Prefer ignoring untrusted Host/XFH for server-side fetches.",
        "Needs human: fixture header→outbound evidence only — not a live header spray.",
    ],
    "dns_rebind": [
        "Could DNS rebinding confuse a time-of-check allowlist (coach question only)?",
        "Does the app re-resolve DNS between check and fetch?",
        "Would pinning resolved IPs for the request lifetime mitigate rebind?",
        "No live rebind tooling ships here — document the question for humans.",
        "Needs human: DNS rebinding coach hints only; never auto-confirm.",
    ],
    "generic_ssrf": [
        "ssrf packs are lab-first with an operator-owned collaborator; never spray cloud metadata or random internet hosts",
        "Evidence = collaborator callback markers / outbound URL resolved to collaborator in fixtures.",
        "Default collaborator = 127.0.0.1 fixture mock; --collaborator must be operator-owned.",
        "Refuse 169.254.169.254 / metadata.google.internal / Azure IMDS unless lab fixture mode + --i-understand-lab.",
        "Open-internet SSRF probes need --scope AND --i-own-this AND --i-understand-lab.",
        "Hard request caps ≤10; findings never auto-VERIFIED — use confirm-finding.",
        "Cannot: live cloud metadata campaigns, random internet SSRF scan.",
    ],
}


def hints_for_pattern(kind: str) -> list[str]:
    key = (kind or "generic_ssrf").strip().lower().replace("-", "_").replace(".", "_")
    if key in {"param_fetch", "outbound_url", "ssrf_url"}:
        key = "url_param"
    if key in {"host_header", "x_forwarded_host", "header_outbound"}:
        key = "header_injection"
    if key in {"dns_rebinding", "rebinding"}:
        key = "dns_rebind"
    if key not in _HINTS:
        key = "generic_ssrf"
    return list(_HINTS[key])


def build_hint_record(
    *,
    pattern_kind: str,
    host: str | None = None,
    url: str | None = None,
    extra: list[str] | None = None,
) -> dict[str, Any]:
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
            "Operator-owned collaborator only; no cloud-metadata campaigns; "
            "DNS rebinding = coach only. "
            "Cannot: live cloud metadata campaigns, random internet SSRF scan."
        ),
        "verification": "needs_human",
    }


__all__ = ["PATTERN_KINDS", "build_hint_record", "hints_for_pattern"]
