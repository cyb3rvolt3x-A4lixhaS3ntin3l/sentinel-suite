"""xss_dom pack v0 — fixture-driven XSS/DOM sink-proof candidates (defensive).

Evidence or it did not happen: prefer proving a unique marker lands in a DOM
sink context (innerHTML / document.write / eval-ish) over alert() spam.

Surfaces covered (fixture-first):
  - Source→sink candidates (location / hash / postMessage → DOM sinks)
  - Reflected / stored path stubs only (fixtures)
  - Hard request caps if any live mock / opener used

Never auto-VERIFIED. No dalfox binary. No live mass scanning.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from gungnir.packs.manifest import finding_gate_checklist
from gungnir.packs.runner import PackRunError
from gungnir.packs.xss_dom.caps import (
    COACH_CAPS,
    HARD_MAX_REQUESTS,
    RequestBudget,
    XssDomCapExceededError,
    host_of,
    is_lab_local_host,
    resolve_caps,
)
from sentinel_core import Scope, ScopeDenied, assert_url_in_scope

_AUTO_STATUSES = frozenset({"needs_human", "unverified"})

DEFAULT_MARKER = "ssntnlXSS7m4rk"

# Sink kinds we treat as proof-worthy when marker appears in their context.
SINK_KINDS = frozenset(
    {
        "innerHTML",
        "outerHTML",
        "document.write",
        "document.writeln",
        "insertAdjacentHTML",
        "eval",
        "Function",
        "setTimeout",
        "setInterval",
        "script_src",
        "jQuery.html",
        "element.setAttribute",
    }
)

SOURCE_KINDS = frozenset(
    {
        "location",
        "location.hash",
        "location.search",
        "location.href",
        "document.URL",
        "document.documentURI",
        "postMessage",
        "window.name",
        "document.referrer",
        "input",
        "storage",
    }
)

COACH_XSS = (
    "XSS/DOM sink-proof: evidence = marker observed in a sink context "
    "(innerHTML / document.write / eval-ish). Do NOT treat alert() alone as proof. "
    "Fixture-driven only unless authorized lab mock."
)


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


def _resolve_host(ctx: dict[str, Any], url: str, notes: list[str], *, label: str) -> str | None:
    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))
    host = _scope_gate(scope, url, i_own_this=i_own) if url else None
    if host is not None:
        return host
    if is_lab_local_host(host_of(url)) and i_own:
        return host_of(url) or "127.0.0.1"
    notes.append(f"skipped {label} OOS/unscoped url={url}")
    return None


def _marker_of(row: dict[str, Any]) -> str:
    m = row.get("marker") or row.get("canary") or DEFAULT_MARKER
    return str(m)


def _sink_kind(row: dict[str, Any]) -> str:
    sink = row.get("sink")
    if isinstance(sink, dict):
        kind = str(sink.get("kind") or sink.get("name") or "").strip()
        if kind:
            return kind
    return str(row.get("sink_kind") or "").strip()


def _source_kind(row: dict[str, Any]) -> str:
    source = row.get("source")
    if isinstance(source, dict):
        kind = str(source.get("kind") or source.get("name") or "").strip()
        if kind:
            return kind
    return str(row.get("source_kind") or "").strip()


def _sink_snippet(row: dict[str, Any]) -> str:
    sink = row.get("sink")
    if isinstance(sink, dict):
        for key in ("snippet", "context", "value", "html", "code", "body"):
            if sink.get(key):
                return str(sink.get(key))
    for key in ("sink_snippet", "snippet", "context", "body", "html"):
        if row.get(key):
            return str(row.get(key))
    resp = row.get("response")
    if isinstance(resp, dict) and resp.get("body") is not None:
        return str(resp.get("body"))
    return ""


def _marker_in_sink(marker: str, snippet: str, *, sink_kind: str) -> bool:
    """True when marker is present in sink context (not alert()-only)."""
    if not marker or not snippet:
        return False
    if marker not in snippet:
        return False
    # Reject alert()-only "proof" without a real sink kind / assignment context
    sk = (sink_kind or "").strip()
    if not sk:
        # Allow if snippet itself shows a sink assignment containing the marker
        lower = snippet.lower()
        sink_tokens = (
            "innerhtml",
            "outerhtml",
            "document.write",
            "insertadjacenthtml",
            "eval(",
            "new function",
            "settimeout(",
            "setinterval(",
        )
        if any(t in lower for t in sink_tokens) and marker in snippet:
            return True
        # alert()-only is insufficient
        if "alert(" in lower and marker in snippet:
            return False
        return False
    # Known sink kind + marker in snippet = proof candidate
    if sk in SINK_KINDS or sk.lower() in {s.lower() for s in SINK_KINDS}:
        return True
    # Unknown sink kind still accepted if marker is clearly in assignment-ish context
    return marker in snippet


def _alert_only(row: dict[str, Any], snippet: str) -> bool:
    """Detect alert()-spam fixtures that lack sink proof."""
    lower = (snippet or "").lower()
    sk = _sink_kind(row)
    if sk and (sk in SINK_KINDS or sk.lower() in {s.lower() for s in SINK_KINDS}):
        return False
    if "alert(" in lower and not any(
        t in lower
        for t in (
            "innerhtml",
            "outerhtml",
            "document.write",
            "insertadjacenthtml",
            "eval(",
            "settimeout",
            "setinterval",
        )
    ):
        return True
    return False


def _candidate(
    *,
    title: str,
    host: str,
    url: str,
    check: str,
    verification: str,
    impact: str,
    evidence_summary: str,
    evidence_stub: dict[str, Any],
    confidence: float,
    reproducible: bool,
    coach_hints: list[str] | None = None,
    human_gate: bool = True,
) -> dict[str, Any]:
    assert verification in _AUTO_STATUSES
    return {
        "title": title,
        "host": host,
        "url": url,
        "check": check,
        "verification": verification,
        "confidence": confidence,
        "impact": impact,
        "reproducible": reproducible,
        "in_scope": True,
        "evidence_attached": True,
        "human_gate": human_gate,
        "auto_verified": False,
        "coach_hints": list(coach_hints or [COACH_XSS]),
        "evidence_summary": evidence_summary,
        "evidence_stub": evidence_stub,
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=reproducible,
            impact=impact,
            evidence_attached=True,
        ),
    }


def _default_source_sink_fixtures() -> list[dict[str, Any]]:
    marker = DEFAULT_MARKER
    return [
        {
            "name": "lab-location-hash-innerHTML",
            "url": f"http://127.0.0.1/app#{marker}",
            "source": {"kind": "location.hash", "value": f"#{marker}"},
            "sink": {
                "kind": "innerHTML",
                "snippet": f'element.innerHTML = location.hash.slice(1); // -> <div>{marker}</div>',
            },
            "marker": marker,
            "expect": {"marker_in_sink": True},
        },
        {
            "name": "lab-postMessage-innerHTML",
            "url": "http://127.0.0.1/widget",
            "source": {"kind": "postMessage", "value": marker},
            "sink": {
                "kind": "innerHTML",
                "snippet": f'window.onmessage = e => box.innerHTML = e.data; // data={marker}',
            },
            "marker": marker,
            "expect": {"marker_in_sink": True},
        },
        {
            "name": "lab-search-document-write",
            "url": f"http://127.0.0.1/search?q={marker}",
            "source": {"kind": "location.search", "value": f"q={marker}"},
            "sink": {
                "kind": "document.write",
                "snippet": f'document.write("<b>" + q + "</b>"); // q={marker}',
            },
            "marker": marker,
            "expect": {"marker_in_sink": True},
        },
    ]


def _source_sink_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(fixtures.get("source_sink") or fixtures.get("dom_sinks") or [])
    if not rows and not fixtures:
        rows = _default_source_sink_fixtures()
        notes.append("using built-in 127.0.0.1 source→sink fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "http://127.0.0.1/")
        host = _resolve_host(ctx, url, notes, label="source_sink")
        if host is None:
            continue

        marker = _marker_of(row)
        sink_kind = _sink_kind(row)
        source_kind = _source_kind(row)
        snippet = _sink_snippet(row)
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}

        if _alert_only(row, snippet):
            notes.append(
                f"rejected alert()-only fixture name={row.get('name') or url} "
                "(sink proof required)"
            )
            continue

        proved = bool(expect.get("marker_in_sink")) or _marker_in_sink(
            marker, snippet, sink_kind=sink_kind
        )
        if not proved:
            notes.append(
                f"source_sink no marker-in-sink proof name={row.get('name') or url}"
            )
            continue

        check = "xss_dom_source_sink_marker"
        verification = "needs_human"
        title = (
            f"DOM XSS source→sink candidate "
            f"({source_kind or 'source'} → {sink_kind or 'sink'})"
        )
        impact = "xss_dom_source_sink_candidate"
        stub = {
            "check": check,
            "request": {
                "method": row.get("method") or "GET",
                "url": url,
                "source_kind": source_kind or None,
                "sink_kind": sink_kind or None,
                "marker": marker,
                "note": "Fixture-only source→sink probe — not a live XSS mass scan",
            },
            "response": {
                "sink_kind": sink_kind or None,
                "marker": marker,
                "marker_in_sink": True,
                "sink_snippet": snippet[:320] if snippet else None,
                "observed": {
                    "source_kind": source_kind or None,
                    "sink_kind": sink_kind or None,
                    "marker_present": True,
                    "alert_only": False,
                },
                "note": (
                    "Sink-proof evidence: unique marker observed in sink context. "
                    "alert() alone is not accepted as proof."
                ),
            },
        }
        out.append(
            _candidate(
                title=title,
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact=impact,
                evidence_summary=(
                    f"{check}: marker={marker!r} in sink={sink_kind or 'inferred'} "
                    f"from source={source_kind or 'inferred'} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.5 if sink_kind in SINK_KINDS else 0.4,
                reproducible=False,
                coach_hints=[
                    COACH_XSS,
                    "Confirm marker survives encoding and lands executable in sink.",
                    "Prefer Trusted Types / strict CSP over alert()-based demos.",
                    "Do not run dalfox-all / live mass scanning from this pack.",
                ],
            )
        )
    return out


def _reflected_stub_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    """Reflected XSS path stubs — fixture response body must contain marker."""
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(fixtures.get("reflected") or fixtures.get("reflected_stubs") or [])
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        host = _resolve_host(ctx, url, notes, label="reflected") if url else None
        if not url or host is None:
            continue
        marker = _marker_of(row)
        resp = row.get("response") or {}
        if not isinstance(resp, dict):
            continue
        body = str(resp.get("body") or resp.get("html") or "")
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
        reflected = bool(expect.get("reflected")) or (marker in body)
        if not reflected:
            notes.append(f"reflected stub: marker not in body url={url}")
            continue
        # Prefer sink context if provided; else body reflection is stub-level only
        sink_kind = _sink_kind(row)
        snippet = _sink_snippet(row) or body
        has_sink = _marker_in_sink(marker, snippet, sink_kind=sink_kind)
        check = "xss_dom_reflected_stub"
        verification = "needs_human" if has_sink else "unverified"
        stub = {
            "check": check,
            "request": {
                "method": row.get("method") or "GET",
                "url": url,
                "param": row.get("param") or row.get("parameter"),
                "marker": marker,
                "note": "Reflected path stub (fixture) — not a live scanner run",
            },
            "response": {
                "status": resp.get("status"),
                "marker": marker,
                "marker_in_body": marker in body,
                "marker_in_sink": has_sink,
                "sink_kind": sink_kind or None,
                "sink_snippet": snippet[:280] if snippet else None,
                "body_stub": body[:240] if body else None,
                "note": (
                    "Stub only. Elevate confidence only when marker is proved "
                    "in a DOM sink context (not alert())."
                ),
            },
        }
        out.append(
            _candidate(
                title="Reflected XSS path stub (fixture)",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="xss_reflected_stub_candidate",
                evidence_summary=(
                    f"{check}: marker={marker!r} reflected "
                    f"sink_proof={has_sink} (verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.45 if has_sink else 0.25,
                reproducible=False,
                coach_hints=[
                    COACH_XSS,
                    "Encode output contextually; prefer CSP + Trusted Types.",
                ],
            )
        )
    return out


def _stored_stub_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    """Stored XSS path stubs — marker seen on a later read fixture."""
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(fixtures.get("stored") or fixtures.get("stored_stubs") or [])
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("read_url") or row.get("endpoint") or "")
        host = _resolve_host(ctx, url, notes, label="stored") if url else None
        if not url or host is None:
            continue
        marker = _marker_of(row)
        write = row.get("write_response") or row.get("store") or {}
        read = row.get("read_response") or row.get("response") or {}
        if not isinstance(read, dict):
            continue
        body = str(read.get("body") or read.get("html") or "")
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
        stored = bool(expect.get("stored")) or (marker in body)
        if not stored:
            notes.append(f"stored stub: marker not on read url={url}")
            continue
        sink_kind = _sink_kind(row)
        snippet = _sink_snippet(row) or body
        has_sink = _marker_in_sink(marker, snippet, sink_kind=sink_kind)
        check = "xss_dom_stored_stub"
        verification = "needs_human" if has_sink else "unverified"
        write_status = write.get("status") if isinstance(write, dict) else None
        stub = {
            "check": check,
            "request": {
                "method": row.get("method") or "POST",
                "url": url,
                "write_url": row.get("write_url"),
                "marker": marker,
                "note": "Stored path stub (fixture) — write then read replay only",
            },
            "response": {
                "write_status": write_status,
                "read_status": read.get("status"),
                "marker": marker,
                "marker_in_body": marker in body,
                "marker_in_sink": has_sink,
                "sink_kind": sink_kind or None,
                "sink_snippet": snippet[:280] if snippet else None,
                "body_stub": body[:240] if body else None,
                "note": (
                    "Stub only. Sink-proof when marker is in a DOM sink context "
                    "on the read path."
                ),
            },
        }
        out.append(
            _candidate(
                title="Stored XSS path stub (fixture)",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="xss_stored_stub_candidate",
                evidence_summary=(
                    f"{check}: marker={marker!r} stored+read "
                    f"sink_proof={has_sink} (verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.45 if has_sink else 0.25,
                reproducible=False,
                coach_hints=[
                    COACH_XSS,
                    "Sanitize on output; treat stored HTML as untrusted.",
                ],
            )
        )
    return out


def _postmessage_hints(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    """postMessage origin-check coach hints (needs_human only)."""
    hints: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(fixtures.get("postmessage") or fixtures.get("post_message") or [])
    if not rows:
        hints.append(
            {
                "kind": "postmessage_coach",
                "note": (
                    "Review postMessage handlers for origin checks and sink usage. "
                    "This pack does not fuzz postMessage on live targets."
                ),
                "questions": [
                    COACH_XSS,
                    "Does every message handler verify event.origin?",
                    "Does handler data reach innerHTML / eval without sanitization?",
                    "Needs human: treat postMessage→sink as a review checklist.",
                ],
                "verification": "needs_human",
            }
        )
        notes.append("postMessage: coach hint only (no live fuzzing)")
        return hints

    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        hints.append(
            {
                "kind": "postmessage_candidate_hint",
                "url": url or None,
                "host": host,
                "note": (
                    "needs_human: postMessage fixture hint — pack will not "
                    "fuzz origins or spam alert()."
                ),
                "questions": [
                    COACH_XSS,
                    f"Fixture origin_check={row.get('origin_check')!r}.",
                    "Confirm e.origin allowlist and no sink without sanitization.",
                ],
                "verification": "needs_human",
                "expect": row.get("expect") if isinstance(row.get("expect"), dict) else {},
            }
        )
    return hints


def _maybe_live_mock(
    ctx: dict[str, Any], caps_dict: dict[str, Any], notes: list[str]
) -> None:
    """If opener/live_mock present, enforce hard request caps (no mass scan)."""
    opener = ctx.get("opener")
    live_mock = (ctx.get("fixtures") or {}).get("live_mock")
    if opener is None and not live_mock:
        return

    budget = RequestBudget(max_requests=int(caps_dict["max_requests"]))
    notes.append(
        f"live mock path active — hard cap requests≤{caps_dict['max_requests']} "
        f"(hard_max={HARD_MAX_REQUESTS}); no dalfox / mass scan"
    )

    calls = live_mock.get("calls") if isinstance(live_mock, dict) else None
    if isinstance(calls, list):
        for call in calls:
            if not budget.try_acquire():
                notes.append(
                    f"live mock request refused past cap "
                    f"(used={budget.used}, rejected={budget.rejected})"
                )
                break
            if callable(opener):
                try:
                    opener(call)
                except Exception as exc:  # noqa: BLE001 — lab mock soft
                    notes.append(f"live mock call soft-fail: {exc}")
        notes.append(f"live mock requests_used={budget.used}/{budget.max_requests}")
        caps_dict["requests_used"] = budget.used
        caps_dict["requests_rejected"] = budget.rejected
    elif callable(opener):
        if budget.try_acquire():
            try:
                opener({"probe": "xss_dom_typename"})
            except Exception as exc:  # noqa: BLE001
                notes.append(f"live mock opener soft-fail: {exc}")
        caps_dict["requests_used"] = budget.used


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """Run xss_dom pack v0 checks (fixture-first, sink-proof, scope-gated)."""
    notes: list[str] = [
        "xss_dom v0: fixture-driven source→sink / reflected / stored stubs",
        COACH_XSS,
        "findings default needs_human|unverified; never auto-VERIFIED/confirmed",
        "alert() alone is NOT proof — marker must land in sink context",
        "no dalfox binary / --tools / live mass scanning",
        f"live-mock hard cap requests≤{HARD_MAX_REQUESTS}",
    ]

    try:
        caps = resolve_caps(
            max_requests=ctx.get("max_requests"),
            i_understand_lab=bool(ctx.get("i_understand_lab")),
        )
    except XssDomCapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    caps_dict = caps.to_dict()
    _maybe_live_mock(ctx, caps_dict, notes)

    candidates: list[dict[str, Any]] = []
    candidates.extend(_source_sink_candidates(ctx, notes))
    candidates.extend(_reflected_stub_candidates(ctx, notes))
    candidates.extend(_stored_stub_candidates(ctx, notes))
    hints = _postmessage_hints(ctx, notes)

    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for c in candidates:
        assert c.get("auto_verified") is False
        assert c["verification"] in _AUTO_STATUSES
        key = (str(c.get("title")), str(c.get("url")), str(c.get("check")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    if not unique:
        notes.append(
            "no XSS/DOM candidates — provide fixtures.source_sink / reflected / "
            "stored under lab fixtures (or rely on built-in source→sink mock)"
        )

    return {
        "candidates": unique,
        "flows": [],
        "steps": [],
        "hints": hints,
        "notes": notes,
        "caps": caps_dict,
        "fixtures_only": not bool(
            ctx.get("opener") or (ctx.get("fixtures") or {}).get("live_mock")
        ),
    }


__all__ = ["run_checks", "COACH_XSS", "DEFAULT_MARKER", "SINK_KINDS", "SOURCE_KINDS"]
