"""In-process fixture analyzer for SSRF collaborator evidence.

Lab scaffolding: fixture markers that an operator-owned collaborator received
a callback, or that an outbound URL resolved to the collaborator.
NO live cloud-metadata fetches. NO random-internet spray.
DNS rebinding = coach hints only (no live rebind tooling).
"""

from __future__ import annotations

from urllib.parse import urlparse

from typing import Any

from gungnir.packs.ssrf_collaborator.caps import (
    DEFAULT_COLLABORATOR,
    RequestBudget,
    SsrfCaps,
    host_of,
    is_cloud_metadata_target,
)

_KIND_URL_PARAM = frozenset(
    {"url_param", "url-param", "param_fetch", "outbound_url", "ssrf_url"}
)
_KIND_HEADER = frozenset(
    {
        "header_injection",
        "header-injection",
        "host_header",
        "x_forwarded_host",
        "xff_host",
        "header_outbound",
    }
)
_KIND_DNS_REBIND = frozenset(
    {"dns_rebind", "dns-rebind", "dns_rebinding", "rebinding"}
)


def _norm_kind(raw: str) -> str:
    k = (raw or "").strip().lower().replace(" ", "_").replace("-", "_")
    if k in _KIND_URL_PARAM:
        return "url_param"
    if k in _KIND_HEADER:
        return "header_injection"
    if k in _KIND_DNS_REBIND:
        return "dns_rebind"
    return k or "ssrf"


def _as_callback(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        return {}
    return {
        "received": bool(obj.get("received") or obj.get("hit") or obj.get("callback")),
        "marker": str(obj.get("marker") or obj.get("token") or "").strip(),
        "outbound_url": str(obj.get("outbound_url") or obj.get("url") or "").strip(),
        "method": str(obj.get("method") or "GET").upper(),
        "headers": (
            {str(k).lower(): str(v) for k, v in obj["headers"].items()}
            if isinstance(obj.get("headers"), dict)
            else {}
        ),
        "note": str(obj.get("note") or ""),
    }


def _collaborator_hit(callback: dict[str, Any], collaborator: str) -> dict[str, Any]:
    marker = callback.get("marker") or ""
    outbound = callback.get("outbound_url") or ""
    collab_host = host_of(collaborator)
    outbound_host = host_of(outbound) if outbound else ""
    received = bool(callback.get("received"))
    # Require collaborator URL affinity (not mere shared host — 127.0.0.1
    # lab targets would otherwise false-positive every loopback outbound).
    collab_norm = collaborator.rstrip("/")
    outbound_norm = outbound.rstrip("/")
    url_to_collab = bool(
        outbound
        and collab_norm
        and (
            collab_norm in outbound_norm
            or outbound_norm in collab_norm
            or (
                collab_host
                and outbound_host
                and collab_host == outbound_host
                and (
                    # path/port affinity when hosts match
                    (urlparse(collaborator).path or "/") in (urlparse(outbound).path or "/")
                    or (urlparse(outbound).port == urlparse(collaborator).port)
                )
            )
        )
    )
    return {
        "hit": bool(received or url_to_collab),
        "received": received,
        "url_resolved_to_collaborator": url_to_collab,
        "marker": marker or None,
        "outbound_url": outbound or None,
        "collaborator": collaborator,
        "collaborator_host": collab_host or None,
    }


def analyze_fixture_scenario(
    scenario: dict[str, Any],
    caps: SsrfCaps,
    *,
    budget: RequestBudget | None = None,
) -> dict[str, Any]:
    """Analyze one fixture scenario. Never opens a network socket."""
    kind = _norm_kind(str(scenario.get("kind") or "url_param"))
    name = str(scenario.get("name") or kind)
    url = str(scenario.get("url") or "http://127.0.0.1/lab/ssrf")
    host = str(scenario.get("host") or "127.0.0.1")
    collaborator = str(
        scenario.get("collaborator") or caps.collaborator or DEFAULT_COLLABORATOR
    )

    callback = _as_callback(
        scenario.get("collaborator_callback")
        or scenario.get("callback")
        or scenario.get("evidence")
        or {}
    )
    hit_info = _collaborator_hit(callback, collaborator)

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
    expect_hit = bool(
        expect.get("collaborator_hit") or expect.get("ssrf") or expect.get("callback")
    )

    header_influence = False
    inj = scenario.get("header_injection") or scenario.get("injected_headers")
    if isinstance(inj, dict) and inj:
        header_influence = True
        inj_host = str(
            inj.get("host")
            or inj.get("Host")
            or inj.get("x-forwarded-host")
            or inj.get("X-Forwarded-Host")
            or ""
        )
        if inj_host and host_of(inj_host) == host_of(collaborator):
            hit_info = {
                **hit_info,
                "hit": True,
                "url_resolved_to_collaborator": True,
                "header_influenced_outbound": True,
            }

    candidate_signal = False
    signal_reason = None
    dns_rebind_coach_only = False

    if kind == "dns_rebind":
        if hit_info["hit"] or force or expect_hit:
            candidate_signal = True
            signal_reason = "dns_rebind_fixture_stub"
        else:
            signal_reason = "dns_rebind_coach_only"
            dns_rebind_coach_only = True
    elif hit_info["hit"]:
        candidate_signal = True
        if kind == "url_param":
            signal_reason = "url_param_collaborator_hit"
        elif kind == "header_injection" or header_influence:
            signal_reason = "header_injection_collaborator_hit"
        else:
            signal_reason = "collaborator_hit"
    elif force or expect_hit:
        candidate_signal = True
        signal_reason = "fixture_forced"
        hit_info = {**hit_info, "hit": True, "forced": True}

    outbound = hit_info.get("outbound_url") or ""
    metadata_outbound = is_cloud_metadata_target(outbound) or is_cloud_metadata_target(
        collaborator
    )

    observation: dict[str, Any] = {
        "kind": kind,
        "name": name,
        "url": url,
        "host": host,
        "collaborator": collaborator,
        "callback": callback,
        "hit": hit_info,
        "header_injection": inj if isinstance(inj, dict) else None,
        "header_influence": header_influence,
        "candidate_signal": candidate_signal,
        "signal_reason": signal_reason,
        "dns_rebind_coach_only": dns_rebind_coach_only,
        "metadata_outbound_flagged": metadata_outbound,
        "max_requests": caps.max_requests,
        "requests_used": requests_used,
        "requests_rejected_by_cap": requests_rejected,
        "note": (
            "Fixture collaborator evidence only — not a live cloud-metadata "
            "fetch or random-internet SSRF spray. Needs human review; "
            "never auto-VERIFIED. DNS rebinding = coach hints only."
        ),
    }
    if budget is not None:
        assert budget.used <= caps.max_requests
    return observation


def default_lab_scenarios(collaborator: str | None = None) -> list[dict[str, Any]]:
    """Built-in 127.0.0.1 fixture collaborator scenarios (no network)."""
    collab = (collaborator or DEFAULT_COLLABORATOR).strip() or DEFAULT_COLLABORATOR
    return [
        {
            "name": "lab-url-param-callback",
            "kind": "url_param",
            "url": "http://127.0.0.1/lab/ssrf?url=" + collab,
            "host": "127.0.0.1",
            "collaborator": collab,
            "collaborator_callback": {
                "received": True,
                "marker": "SSRF_COLLAB_HIT",
                "outbound_url": collab,
                "method": "GET",
            },
            "expect": {"collaborator_hit": True},
        },
        {
            "name": "lab-header-host-outbound",
            "kind": "header_injection",
            "url": "http://127.0.0.1/lab/ssrf/fetch",
            "host": "127.0.0.1",
            "collaborator": collab,
            "header_injection": {
                "Host": host_of(collab) or "127.0.0.1",
                "X-Forwarded-Host": host_of(collab) or "127.0.0.1",
            },
            "collaborator_callback": {
                "received": True,
                "marker": "SSRF_HDR_HIT",
                "outbound_url": collab,
                "method": "GET",
            },
            "expect": {"collaborator_hit": True},
        },
        {
            "name": "lab-dns-rebind-coach",
            "kind": "dns_rebind",
            "url": "http://127.0.0.1/lab/ssrf/rebind",
            "host": "127.0.0.1",
            "collaborator": collab,
            "collaborator_callback": {},
            "expect": {},
        },
    ]


__all__ = [
    "analyze_fixture_scenario",
    "default_lab_scenarios",
    "RequestBudget",
]
