"""Flow mapper v0 — fixture + optional HTML/form crawl stubs (scope-gated).

Detects multi-step flow candidates (cart→checkout, invite→accept,
transfer→confirm, apply→approve). Emits FLOW / STEP shaped dicts with
low confidence until a human marks them. No live abuse.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from sentinel_core import Scope, ScopeDenied, assert_url_in_scope

from gungnir.packs.business_logic.hints import FLOW_KINDS, build_hint_record

_DEFAULT_FLOW_CONFIDENCE = 0.25  # low until human marks

# Path / label tokens that suggest each flow kind.
_KIND_PATTERNS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "cart_checkout": (
        ("cart", "basket", "bag", "line-item", "add-to-cart"),
        ("checkout", "payment", "place-order", "pay", "confirm-order"),
    ),
    "invite_accept": (
        ("invite", "invitation", "invite-link"),
        ("accept", "join", "redeem-invite"),
    ),
    "transfer_confirm": (
        ("transfer", "wire", "send-money", "draft-transfer"),
        ("confirm", "authorize-transfer", "approve-transfer"),
    ),
    "apply_approve": (
        ("apply", "application", "submit-application"),
        ("approve", "review", "decision"),
    ),
}


def _host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower().rstrip(".")


def _scope_gate(scope: Scope | None, url: str, *, i_own_this: bool) -> str | None:
    host = _host(url)
    if not host:
        return None
    if scope is not None:
        try:
            assert_url_in_scope(scope, url)
            return host
        except ScopeDenied:
            return None
    if i_own_this:
        return host
    return None


def _norm_token(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")


def infer_flow_kind(name: str = "", steps: list[dict[str, Any]] | None = None) -> str:
    """Infer flow kind from name + step labels/paths."""
    blob_parts = [name or ""]
    for s in steps or []:
        blob_parts.append(str(s.get("name") or ""))
        blob_parts.append(str(s.get("path") or s.get("url") or ""))
        blob_parts.append(str(s.get("label") or ""))
    blob = _norm_token(" ".join(blob_parts))

    for kind, (a_toks, b_toks) in _KIND_PATTERNS.items():
        has_a = any(t in blob for t in a_toks)
        has_b = any(t in blob for t in b_toks)
        if has_a and has_b:
            return kind
    for kind, (a_toks, b_toks) in _KIND_PATTERNS.items():
        if any(t in blob for t in a_toks + b_toks) and len(steps or []) >= 2:
            return kind
    return "generic_multi_step"


class _FormLinkParser(HTMLParser):
    """Collect form actions + anchor hrefs from fixture HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.actions: list[str] = []
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k: (v or "") for k, v in attrs}
        if tag.lower() == "form" and ad.get("action"):
            self.actions.append(ad["action"])
        if tag.lower() == "a" and ad.get("href"):
            self.hrefs.append(ad["href"])


def parse_html_flow_stubs(
    html: str,
    *,
    base_url: str,
    scope: Scope | None,
    i_own_this: bool,
) -> list[dict[str, Any]]:
    """
    Optional HTML/form crawl stub — fixture HTML only, scope-gated.

    Builds a candidate flow when ≥2 in-scope form actions / links look
    like a multi-step pair. No network fetch.
    """
    if not html or not base_url:
        return []
    host = _scope_gate(scope, base_url, i_own_this=i_own_this)
    if host is None:
        return []

    parser = _FormLinkParser()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001 — malformed fixture HTML is soft-fail
        return []

    urls: list[str] = []
    for raw in [*parser.actions, *parser.hrefs]:
        abs_url = urljoin(base_url, raw)
        if _scope_gate(scope, abs_url, i_own_this=i_own_this) is None:
            continue
        urls.append(abs_url)

    if len(urls) < 2:
        return []

    seen: set[str] = set()
    ordered: list[str] = []
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        ordered.append(u)

    steps = [
        {
            "name": f"step_{i + 1}",
            "url": u,
            "path": urlparse(u).path,
            "index": i,
        }
        for i, u in enumerate(ordered[:6])
    ]
    kind = infer_flow_kind(name="html_stub", steps=steps)
    return [
        {
            "name": f"html_stub:{kind}",
            "kind": kind,
            "source": "html_stub",
            "base_url": base_url,
            "host": host,
            "steps": steps,
            "confidence": _DEFAULT_FLOW_CONFIDENCE,
        }
    ]


def map_flows_from_fixtures(ctx: dict[str, Any]) -> dict[str, Any]:
    """
    Map multi-step flow candidates from fixtures (+ optional HTML stubs).

    Returns ``{flows: [...], steps: [...], hints: [...], notes: [...]}``.
    FLOW confidence stays low until human marks.
    """
    fixtures = ctx.get("fixtures") or {}
    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))
    notes = [
        "business_logic flow_mapper v0: fixture + optional HTML stubs",
        "FLOW/STEP confidence low until human marks",
        "no live crawl abuse; scope hard-kill enforced",
    ]

    raw_flows: list[dict[str, Any]] = []
    for row in fixtures.get("flows") or fixtures.get("multi_step_flows") or []:
        if isinstance(row, dict):
            raw_flows.append(row)

    for row in fixtures.get("html_pages") or fixtures.get("html_stubs") or []:
        if not isinstance(row, dict):
            continue
        html = str(row.get("html") or row.get("body") or "")
        base = str(row.get("url") or row.get("base_url") or "")
        raw_flows.extend(
            parse_html_flow_stubs(
                html, base_url=base, scope=scope, i_own_this=i_own
            )
        )

    flows_out: list[dict[str, Any]] = []
    steps_out: list[dict[str, Any]] = []
    hints_out: list[dict[str, Any]] = []

    for idx, row in enumerate(raw_flows):
        steps_in = list(row.get("steps") or [])
        if len(steps_in) < 2:
            continue

        rep_url = str(
            row.get("url")
            or row.get("base_url")
            or (steps_in[0].get("url") if steps_in else "")
            or ""
        )
        host = row.get("host")
        if not host and rep_url:
            host = _scope_gate(scope, rep_url, i_own_this=i_own)
        elif host and scope is not None:
            try:
                scope.hard_kill(str(host))
            except ScopeDenied:
                host = None
        if not host and not i_own:
            continue
        if not host and i_own and rep_url:
            host = _host(rep_url) or "lab.local"
        if not host:
            continue

        gated_steps: list[dict[str, Any]] = []
        for i, s in enumerate(steps_in):
            if not isinstance(s, dict):
                continue
            su = str(s.get("url") or "")
            if su:
                sh = _scope_gate(scope, su, i_own_this=i_own)
                if sh is None:
                    continue
            gated_steps.append(
                {
                    "name": str(s.get("name") or s.get("label") or f"step_{i + 1}"),
                    "url": su or None,
                    "path": str(s.get("path") or (urlparse(su).path if su else "")),
                    "method": str(s.get("method") or "GET").upper(),
                    "index": int(s.get("index") if s.get("index") is not None else i),
                }
            )

        if len(gated_steps) < 2:
            continue

        kind = str(row.get("kind") or row.get("flow_kind") or "").strip().lower()
        if kind not in FLOW_KINDS:
            kind = infer_flow_kind(
                name=str(row.get("name") or ""), steps=gated_steps
            )

        flow_key = str(row.get("id") or f"flow-{idx}-{kind}")
        name = str(row.get("name") or kind)
        confidence = float(row.get("confidence") or _DEFAULT_FLOW_CONFIDENCE)
        if confidence > 0.45:
            confidence = 0.45

        flow_rec = {
            "local_id": flow_key,
            "name": name,
            "kind": kind,
            "host": host,
            "url": rep_url or None,
            "source": str(row.get("source") or "fixture"),
            "confidence": confidence,
            "human_marked": False,
            "step_count": len(gated_steps),
            "step_names": [s["name"] for s in gated_steps],
        }
        flows_out.append(flow_rec)

        for s in gated_steps:
            steps_out.append(
                {
                    "flow_local_id": flow_key,
                    "name": s["name"],
                    "url": s.get("url"),
                    "path": s.get("path"),
                    "method": s.get("method"),
                    "index": s["index"],
                    "host": host,
                    "confidence": confidence,
                    "human_marked": False,
                }
            )

        hints_out.append(
            build_hint_record(
                flow_kind=kind,
                flow_id=flow_key,
                flow_name=name,
                host=str(host),
            )
        )

    if not flows_out:
        notes.append(
            "no multi-step flows mapped — provide fixtures.flows "
            "(≥2 steps) or fixtures.html_pages under lab fixtures"
        )

    return {
        "flows": flows_out,
        "steps": steps_out,
        "hints": hints_out,
        "notes": notes,
    }


__all__ = [
    "infer_flow_kind",
    "map_flows_from_fixtures",
    "parse_html_flow_stubs",
]
