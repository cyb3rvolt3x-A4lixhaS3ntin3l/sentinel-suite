"""Coach hints for business-logic flows — questions a hunter should ask.

Hints are NOT auto-confirmed vulnerabilities. Default pack output never
marks findings verified/confirmed; a human must confirm explicitly.
"""

from __future__ import annotations

from typing import Any

# Canonical multi-step flow kinds the mapper recognizes.
FLOW_KINDS = (
    "cart_checkout",
    "invite_accept",
    "transfer_confirm",
    "apply_approve",
    "generic_multi_step",
)

# Per-kind coach questions (defensive hunter checklist).
_HINTS: dict[str, list[str]] = {
    "cart_checkout": [
        "Can cart/line item price be tampered client-side before checkout?",
        "Can a checkout step be skipped (e.g. payment → confirm without cart)?",
        "Does replaying a checkout/payment request create duplicate orders?",
        "Does quantity overflow / negative qty change totals incorrectly?",
        "Are coupon / discount codes reusable beyond intended limits?",
    ],
    "invite_accept": [
        "Can an invite token be replayed after accept?",
        "Can invite acceptance be forced for another user (IDOR on invite id)?",
        "Does skipping verify/email step still grant membership?",
        "Are expired / revoked invites still accepted?",
        "Can role/privilege in the invite payload be escalated?",
    ],
    "transfer_confirm": [
        "Can transfer amount / destination be tampered between draft and confirm?",
        "Can the confirm step be replayed for double-spend?",
        "Can confirm be called without a prior authorized draft?",
        "Does skipping MFA/confirm still move funds in fixtures?",
        "Are beneficiary identifiers swapped across sessions?",
    ],
    "apply_approve": [
        "Can approval be performed by a low-priv role (BFLA)?",
        "Can apply→approve skip review / status gates?",
        "Does replaying approve double-grant entitlements?",
        "Can application payload be mutated after submit but before approve?",
        "Are approval tokens bound to the specific application id?",
    ],
    "generic_multi_step": [
        "Can any required step be skipped while still completing the flow?",
        "Can request bodies (price, qty, role, amount) be tampered mid-flow?",
        "Does replaying a terminal step duplicate the side effect?",
        "Are step tokens / CSRF / state nonces bound and single-use?",
        "Do out-of-order step calls still succeed?",
    ],
}


def hints_for_flow_kind(kind: str) -> list[str]:
    """Return coach-hint questions for a flow kind (never empty)."""
    key = (kind or "generic_multi_step").strip().lower()
    if key not in _HINTS:
        key = "generic_multi_step"
    return list(_HINTS[key])


def build_hint_record(
    *,
    flow_kind: str,
    flow_id: str | None = None,
    flow_name: str | None = None,
    host: str | None = None,
    extra: list[str] | None = None,
) -> dict[str, Any]:
    """Structured coach-hint record (not a verified finding)."""
    questions = hints_for_flow_kind(flow_kind)
    if extra:
        for q in extra:
            if q and q not in questions:
                questions.append(q)
    return {
        "kind": "coach_hints",
        "flow_kind": flow_kind,
        "flow_id": flow_id,
        "flow_name": flow_name,
        "host": host,
        "questions": questions,
        "note": (
            "Coach hints only — not auto-confirmed vulns; "
            "human must confirm before VERIFIED/confirmed"
        ),
    }


__all__ = [
    "FLOW_KINDS",
    "build_hint_record",
    "hints_for_flow_kind",
]
