"""In-process fixture analyzer for HTTP desync / smuggling *evidence*.

Lab-only scaffolding: compares pre-recorded differential responses across
ambiguous request interpretations (CL.TE / TE.CL / header-smuggle).
NO live HTTP I/O. NO crafting of production CDN/WAF smuggling campaigns.
Hard request caps for any non-pure-fixture path are enforced by the caller.
"""

from __future__ import annotations

from typing import Any

from gungnir.packs.http_desync.caps import DesyncCaps, RequestBudget

# Kind aliases accepted in fixtures.
_KIND_CL_TE = frozenset({"cl_te", "cl.te", "clte", "content-length-te"})
_KIND_TE_CL = frozenset({"te_cl", "te.cl", "tecl", "te-content-length"})
_KIND_HEADER = frozenset(
    {"header_smuggle", "header-smuggle", "hdr_smuggle", "header_obfuscation"}
)


def _norm_kind(raw: str) -> str:
    k = (raw or "").strip().lower().replace(" ", "_")
    if k in _KIND_CL_TE:
        return "cl_te"
    if k in _KIND_TE_CL:
        return "te_cl"
    if k in _KIND_HEADER:
        return "header_smuggle"
    return k or "desync"


def _as_resp(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        return {}
    status = obj.get("status")
    try:
        status_i = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_i = None
    headers = obj.get("headers") if isinstance(obj.get("headers"), dict) else {}
    body = obj.get("body")
    body_s = "" if body is None else str(body)
    return {
        "status": status_i,
        "headers": {str(k).lower(): str(v) for k, v in headers.items()},
        "body": body_s,
        "marker": str(obj.get("marker") or ""),
    }


def _diff_markers(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Return structured differential evidence between two interpretations."""
    status_diff = a.get("status") != b.get("status")
    body_diff = (a.get("body") or "") != (b.get("body") or "")
    hdr_a = a.get("headers") or {}
    hdr_b = b.get("headers") or {}
    header_keys = sorted(set(hdr_a) | set(hdr_b))
    header_diffs = {
        k: {"a": hdr_a.get(k), "b": hdr_b.get(k)}
        for k in header_keys
        if hdr_a.get(k) != hdr_b.get(k)
    }
    marker_a = (a.get("marker") or "").strip()
    marker_b = (b.get("marker") or "").strip()
    marker_diff = bool(marker_a or marker_b) and marker_a != marker_b
    has_diff = bool(status_diff or body_diff or header_diffs or marker_diff)
    return {
        "status_diff": status_diff,
        "body_diff": body_diff,
        "header_diffs": header_diffs,
        "marker_diff": marker_diff,
        "has_differential": has_diff,
        "marker_a": marker_a or None,
        "marker_b": marker_b or None,
    }


def analyze_fixture_scenario(
    scenario: dict[str, Any],
    caps: DesyncCaps,
    *,
    budget: RequestBudget | None = None,
) -> dict[str, Any]:
    """
    Analyze one fixture scenario for desync differential evidence.

    Expects interpretation_a / interpretation_b (or front/back, cl_view/te_view)
    response dicts with status/body/headers/marker. Never opens a network
    socket. Optional budget is only touched when scenario.request_cost > 0
    (live-mock accounting) — pure fixtures leave budget unused.
    """
    kind = _norm_kind(str(scenario.get("kind") or "cl_te"))
    name = str(scenario.get("name") or kind)
    url = str(scenario.get("url") or "http://127.0.0.1/lab/desync")
    host = str(scenario.get("host") or "127.0.0.1")

    interp_a = _as_resp(
        scenario.get("interpretation_a")
        or scenario.get("front")
        or scenario.get("cl_view")
        or scenario.get("response_a")
        or {}
    )
    interp_b = _as_resp(
        scenario.get("interpretation_b")
        or scenario.get("back")
        or scenario.get("te_view")
        or scenario.get("response_b")
        or {}
    )
    diff = _diff_markers(interp_a, interp_b)

    # Optional live-mock cost accounting (never crafts payloads).
    cost = int(scenario.get("request_cost") or 0)
    requests_used = 0
    requests_rejected = 0
    if budget is not None and cost > 0:
        for _ in range(cost):
            if budget.try_acquire():
                requests_used += 1
            else:
                requests_rejected += 1
                break

    force = bool(scenario.get("force_candidate_signal"))
    expect = scenario.get("expect") if isinstance(scenario.get("expect"), dict) else {}
    expect_diff = bool(expect.get("differential") or expect.get("desync"))

    candidate_signal = False
    signal_reason = None
    if diff["has_differential"]:
        candidate_signal = True
        if kind == "cl_te":
            signal_reason = "cl_te_differential"
        elif kind == "te_cl":
            signal_reason = "te_cl_differential"
        elif kind == "header_smuggle":
            signal_reason = "header_smuggle_differential"
        else:
            signal_reason = "desync_differential"
    elif force or expect_diff:
        # Deterministic fixture override for tests — still needs_human only.
        candidate_signal = True
        signal_reason = signal_reason or "fixture_forced"
        diff = {**diff, "has_differential": True, "forced": True}

    observation: dict[str, Any] = {
        "kind": kind,
        "name": name,
        "url": url,
        "host": host,
        "interpretation_a": interp_a,
        "interpretation_b": interp_b,
        "diff": diff,
        "candidate_signal": candidate_signal,
        "signal_reason": signal_reason,
        "max_requests": caps.max_requests,
        "requests_used": requests_used,
        "requests_rejected_by_cap": requests_rejected,
        "note": (
            "Fixture differential evidence only — not a live smuggle. "
            "Needs human review; never auto-VERIFIED."
        ),
    }
    if budget is not None:
        assert budget.used <= caps.max_requests
    return observation


def default_lab_scenarios() -> list[dict[str, Any]]:
    """Built-in 127.0.0.1 fixture differentials (no network)."""
    return [
        {
            "name": "lab-cl-te-diff",
            "kind": "cl_te",
            "url": "http://127.0.0.1/lab/desync/cl-te",
            "host": "127.0.0.1",
            "interpretation_a": {
                "status": 200,
                "body": "OK front-CL",
                "headers": {"x-lab-view": "content-length"},
                "marker": "CL_VIEW",
            },
            "interpretation_b": {
                "status": 404,
                "body": "smuggled-path TE",
                "headers": {"x-lab-view": "transfer-encoding"},
                "marker": "TE_VIEW",
            },
            "expect": {"differential": True},
        },
        {
            "name": "lab-te-cl-diff",
            "kind": "te_cl",
            "url": "http://127.0.0.1/lab/desync/te-cl",
            "host": "127.0.0.1",
            "interpretation_a": {
                "status": 200,
                "body": "OK front-TE",
                "headers": {"x-lab-view": "transfer-encoding"},
                "marker": "TE_VIEW",
            },
            "interpretation_b": {
                "status": 403,
                "body": "blocked-by-CL-backend",
                "headers": {"x-lab-view": "content-length"},
                "marker": "CL_VIEW",
            },
            "expect": {"differential": True},
        },
        {
            "name": "lab-header-smuggle-diff",
            "kind": "header_smuggle",
            "url": "http://127.0.0.1/lab/desync/hdr",
            "host": "127.0.0.1",
            "interpretation_a": {
                "status": 200,
                "body": "normal",
                "headers": {"x-forwarded-host": "127.0.0.1"},
                "marker": "NORM",
            },
            "interpretation_b": {
                "status": 200,
                "body": "confused-host",
                "headers": {"x-forwarded-host": "evil.lab"},
                "marker": "SMUGGLED_HDR",
            },
            "expect": {"differential": True},
        },
    ]


__all__ = [
    "analyze_fixture_scenario",
    "default_lab_scenarios",
    "RequestBudget",
]
