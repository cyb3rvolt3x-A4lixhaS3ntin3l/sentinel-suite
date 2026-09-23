"""open_redirect pack v0 — fixture-driven unvalidated redirect candidates (defensive).

Evidence or it did not happen: cite concrete fixture signals (Location header
value, external host in redirect target, //evil or encoded bypass) — never
emit on bare query-param name alone.

Surfaces covered (fixture-first):
  - next/return/url/redirect/continue (and similar) → external host redirect
  - Protocol-relative //evil and encoded bypass candidates
  - Header Location reflection of attacker-controlled values

Never auto-VERIFIED. No blind param spray / redirect farms / browser automation.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlparse

from gungnir.packs.manifest import finding_gate_checklist
from gungnir.packs.open_redirect.caps import (
    COACH_CAPS,
    HARD_MAX_REQUESTS,
    RequestBudget,
    OpenRedirectCapExceededError,
    host_of,
    is_lab_local_host,
    resolve_caps,
)
from gungnir.packs.open_redirect.hints import build_hint_record, hints_for_pattern
from gungnir.packs.runner import PackRunError
from sentinel_core import Scope, ScopeDenied, assert_url_in_scope

_AUTO_STATUSES = frozenset({"needs_human", "unverified"})

# Common redirect query / body param names (candidates only WITH evidence).
REDIRECT_PARAM_NAMES = frozenset(
    {
        "next",
        "return",
        "return_to",
        "returnto",
        "return_url",
        "returnurl",
        "url",
        "redirect",
        "redirect_uri",
        "redirect_url",
        "redirecturi",
        "redirecturl",
        "continue",
        "continue_url",
        "dest",
        "destination",
        "goto",
        "target",
        "rurl",
        "redir",
        "callback",
        "callback_url",
        "success_url",
        "failure_url",
        "RelayState",
        "relaystate",
    }
)

COACH_OPEN_REDIRECT = (
    "Open redirect: evidence = concrete fixture signal "
    "(Location header value, external host in redirect target, "
    "//evil or encoded bypass). Do NOT emit on bare param name alone. "
    "Fixture-driven only unless authorized lab mock."
)

_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})

# Encoded / protocol-relative evil markers we recognize in fixtures.
_PROTO_REL_RE = re.compile(r"(?:^|[=\"'\s])//[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_ENCODED_SLASH_RE = re.compile(
    r"(?:%2[fF]){2}[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"  # %2F%2Fevil.example
    r"|%252[fF]%252[fF][a-zA-Z0-9.-]+"  # double-encoded
    r"|\\/\\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"  # \/\/evil
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
        "coach_hints": list(coach_hints or [COACH_OPEN_REDIRECT]),
        "evidence_summary": evidence_summary,
        "evidence_stub": evidence_stub,
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=reproducible,
            impact=impact,
            evidence_attached=True,
        ),
    }


def _params_of(row: dict[str, Any]) -> dict[str, Any]:
    params = row.get("params") or row.get("query") or row.get("query_params") or {}
    if isinstance(params, dict):
        return params
    return {}


def _headers_of(row: dict[str, Any]) -> dict[str, Any]:
    headers = row.get("headers") or {}
    if isinstance(headers, dict):
        return {str(k).lower(): v for k, v in headers.items()}
    return {}


def _response_of(row: dict[str, Any]) -> dict[str, Any]:
    resp = row.get("response") or {}
    if isinstance(resp, dict):
        return resp
    return {}


def _location_from(row: dict[str, Any]) -> str:
    """Extract Location / redirect target from fixture (response or top-level)."""
    resp = _response_of(row)
    headers = {}
    if isinstance(resp.get("headers"), dict):
        headers = {str(k).lower(): v for k, v in resp["headers"].items()}
    # Also merge top-level headers under response.headers preference
    top_h = _headers_of(row)
    loc = (
        resp.get("location")
        or headers.get("location")
        or row.get("location")
        or top_h.get("location")
        or row.get("redirect_to")
        or row.get("redirect_target")
        or resp.get("redirect_to")
        or ""
    )
    return str(loc).strip()


def _status_of(row: dict[str, Any]) -> int | None:
    resp = _response_of(row)
    for src in (resp.get("status"), resp.get("status_code"), row.get("status"), row.get("status_code")):
        if src is None:
            continue
        try:
            return int(src)
        except (TypeError, ValueError):
            continue
    return None


def _target_host(target: str) -> str:
    """Hostname of a redirect target (supports protocol-relative)."""
    t = (target or "").strip()
    if not t:
        return ""
    return host_of(t)


def _is_external_target(request_host: str, target: str) -> bool:
    """True when redirect target host differs from request host (and is absolute-ish)."""
    th = _target_host(target)
    if not th:
        # Relative path-only — not an open redirect to external host
        return False
    rh = (request_host or "").strip().lower().rstrip(".")
    return th != rh


def _is_protocol_relative(target: str) -> bool:
    t = (target or "").strip()
    if t.startswith("//") and not t.startswith("///"):
        return bool(_target_host(t))
    return bool(_PROTO_REL_RE.search(t))


def _is_encoded_bypass(target: str) -> bool:
    t = (target or "").strip()
    if not t:
        return False
    if _ENCODED_SLASH_RE.search(t):
        return True
    # Single decode reveals protocol-relative or absolute external
    try:
        once = unquote(t)
    except Exception:  # noqa: BLE001
        once = t
    if once != t and (_is_protocol_relative(once) or once.lower().startswith("http")):
        return True
    try:
        twice = unquote(once)
    except Exception:  # noqa: BLE001
        twice = once
    if twice != once and (_is_protocol_relative(twice) or twice.lower().startswith("http")):
        return True
    # javascript: / data: schemes as bypass-ish
    lower = t.lower()
    if lower.startswith("javascript:") or lower.startswith("data:"):
        return True
    return False


def _redirect_param_hit(row: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return (param_name, param_value) for first known redirect param, else (None, None)."""
    params = _params_of(row)
    # Also accept explicit param/value fields
    if row.get("param") and row.get("value") is not None:
        pname = str(row.get("param")).strip()
        if pname.lower() in {n.lower() for n in REDIRECT_PARAM_NAMES} or pname:
            return pname, str(row.get("value"))
    for key, val in params.items():
        kn = str(key).strip()
        if kn.lower() in {n.lower() for n in REDIRECT_PARAM_NAMES}:
            return kn, None if val is None else str(val)
    return None, None


def _has_redirect_evidence(row: dict[str, Any], request_host: str) -> dict[str, Any] | None:
    """
    Require concrete redirect evidence — not mere param presence.

    Evidence forms:
      - Location / redirect_to pointing at external host
      - expect.open_redirect / expect.external_redirect True with location
      - status in 3xx + location external
      - protocol-relative or encoded bypass markers in location/value
    """
    expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
    location = _location_from(row)
    status = _status_of(row)
    param_name, param_value = _redirect_param_hit(row)

    # Candidate value that may itself be the redirect target (when Location absent
    # but fixture explicitly marks open_redirect + provides the value as evidence)
    value_as_target = location or (param_value if expect.get("open_redirect") or expect.get("external_redirect") or expect.get("location_reflects") else "")

    signals: dict[str, Any] = {
        "location": location or None,
        "status": status,
        "param_name": param_name,
        "param_value": (param_value[:200] if param_value else None),
    }

    if not location and not (
        expect.get("open_redirect")
        or expect.get("external_redirect")
        or expect.get("location_reflects")
        or expect.get("protocol_relative")
        or expect.get("encoded_bypass")
        or row.get("open_redirect") is True
    ):
        return None  # no evidence markers at all

    target = location or str(value_as_target or "")
    if not target:
        # Explicit expect without any target string — insufficient
        return None

    external = _is_external_target(request_host, target)
    proto_rel = _is_protocol_relative(target) or bool(expect.get("protocol_relative"))
    encoded = _is_encoded_bypass(target) or bool(expect.get("encoded_bypass"))
    reflects = bool(
        expect.get("location_reflects")
        or row.get("location_reflects") is True
        or (
            param_value
            and location
            and (
                param_value in location
                or unquote(param_value) in location
                or location in (param_value, unquote(param_value))
            )
        )
    )
    status_redirect = status in _REDIRECT_STATUS if status is not None else False

    # Must have at least one concrete signal beyond "param present"
    # Open-redirect evidence requires external / protocol-relative / encoded
    # bypass — same-origin relative Location reflection alone is NOT enough.
    if not (external or proto_rel or encoded):
        if (expect.get("open_redirect") or expect.get("external_redirect")) and target:
            if target.lower().startswith("http") or _is_protocol_relative(target) or _is_encoded_bypass(target):
                external = external or _is_external_target(request_host, target) or target.lower().startswith("http")
                proto_rel = proto_rel or _is_protocol_relative(target)
                encoded = encoded or _is_encoded_bypass(target)
            else:
                return None
        else:
            return None

    if not (external or proto_rel or encoded):
        return None

    signals.update(
        {
            "external_host": external,
            "target_host": _target_host(target) or None,
            "protocol_relative": proto_rel,
            "encoded_bypass": encoded,
            "location_reflects": reflects,
            "status_redirect": status_redirect,
            "target": target[:320],
        }
    )
    return signals


def _default_param_redirect_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-next-external",
            "url": "http://127.0.0.1/login",
            "params": {"next": "https://evil.example/phish"},
            "response": {
                "status": 302,
                "headers": {"Location": "https://evil.example/phish"},
            },
            "expect": {"open_redirect": True, "external_redirect": True, "location_reflects": True},
        },
        {
            "name": "lab-return-continue",
            "url": "http://127.0.0.1/auth/callback",
            "params": {"return": "https://attacker.example/"},
            "location": "https://attacker.example/",
            "status": 302,
            "expect": {"open_redirect": True, "location_reflects": True},
        },
    ]


def _default_proto_rel_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-protocol-relative",
            "url": "http://127.0.0.1/out",
            "params": {"url": "//evil.example/path"},
            "response": {"status": 302, "headers": {"Location": "//evil.example/path"}},
            "expect": {"protocol_relative": True, "open_redirect": True, "location_reflects": True},
        }
    ]


def _default_encoded_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-encoded-bypass",
            "url": "http://127.0.0.1/go",
            "params": {"redirect": "%2F%2Fevil.example%2F"},
            "response": {
                "status": 302,
                "headers": {"Location": "%2F%2Fevil.example%2F"},
            },
            "expect": {"encoded_bypass": True, "open_redirect": True, "location_reflects": True},
        }
    ]


def _default_location_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-location-reflect",
            "url": "http://127.0.0.1/redirect",
            "params": {"continue": "https://evil.example/x"},
            "response": {
                "status": 302,
                "headers": {"Location": "https://evil.example/x"},
            },
            "expect": {"location_reflects": True, "external_redirect": True},
        }
    ]


def _param_redirect_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("param_redirect")
        or fixtures.get("redirect_params")
        or fixtures.get("open_redirect")
        or []
    )
    if not rows and not fixtures:
        rows = _default_param_redirect_fixtures()
        notes.append("using built-in 127.0.0.1 param-redirect fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        if not url:
            continue
        host = _resolve_host(ctx, url, notes, label="param_redirect")
        if host is None:
            continue

        param_name, param_value = _redirect_param_hit(row)
        # Reject bare param presence without redirect evidence
        evidence = _has_redirect_evidence(row, host)
        if evidence is None:
            if param_name:
                notes.append(
                    f"param_redirect skipped — param={param_name!r} present but no "
                    f"redirect evidence (Location/external/encoded) name={row.get('name') or url}"
                )
            else:
                notes.append(
                    f"param_redirect skipped — no redirect evidence "
                    f"name={row.get('name') or url}"
                )
            continue

        check = "open_redirect_param_external"
        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": str(row.get("method") or "GET").upper(),
                "url": url,
                "param": evidence.get("param_name") or param_name,
                "param_value_stub": (evidence.get("param_value") or (param_value or ""))[:120],
                "note": (
                    "Fixture-only open-redirect candidate — not a live "
                    "blind param spray"
                ),
            },
            "response": {
                "status": evidence.get("status"),
                "location": evidence.get("location"),
                "observed": {
                    "external_host": evidence.get("external_host"),
                    "target_host": evidence.get("target_host"),
                    "location_reflects": evidence.get("location_reflects"),
                    "status_redirect": evidence.get("status_redirect"),
                    "fixture_name": row.get("name"),
                },
                "evidence_signal": (
                    f"Location/redirect target={evidence.get('target')!r} "
                    f"target_host={evidence.get('target_host')!r} "
                    f"external={evidence.get('external_host')} "
                    f"param={(evidence.get('param_name') or param_name)!r}"
                ),
                "note": (
                    "Evidence = fixture Location/external-host signal. "
                    "Confirm allowlist failure before VERIFIED."
                ),
            },
        }
        out.append(
            _candidate(
                title=(
                    f"Open redirect via param "
                    f"{evidence.get('param_name') or param_name or 'redirect'}"
                ),
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="open_redirect_param_external_candidate",
                evidence_summary=(
                    f"{check}: target_host={evidence.get('target_host')!r} "
                    f"external={evidence.get('external_host')} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.5,
                reproducible=False,
                coach_hints=[COACH_OPEN_REDIRECT] + hints_for_pattern("param_redirect")[:3],
            )
        )
    return out


def _protocol_relative_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("protocol_relative")
        or fixtures.get("proto_relative")
        or fixtures.get("slash_slash")
        or []
    )
    if not rows and not fixtures:
        rows = _default_proto_rel_fixtures()
        notes.append("using built-in 127.0.0.1 protocol-relative //evil fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        if not url:
            continue
        host = _resolve_host(ctx, url, notes, label="protocol_relative")
        if host is None:
            continue

        evidence = _has_redirect_evidence(row, host)
        location = _location_from(row)
        _, param_value = _redirect_param_hit(row)
        target = (evidence or {}).get("target") or location or param_value or ""
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
        proto = (
            (evidence and evidence.get("protocol_relative"))
            or _is_protocol_relative(str(target))
            or bool(expect.get("protocol_relative"))
            or row.get("protocol_relative") is True
        )
        if not proto or not target:
            notes.append(
                f"protocol_relative fixture lacks //evil signal "
                f"name={row.get('name') or url}"
            )
            continue
        # Still require some redirect evidence (Location or explicit expect)
        if evidence is None and not (
            expect.get("protocol_relative") or expect.get("open_redirect")
        ):
            notes.append(
                f"protocol_relative skipped — no redirect evidence "
                f"name={row.get('name') or url}"
            )
            continue

        check = "open_redirect_protocol_relative"
        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": str(row.get("method") or "GET").upper(),
                "url": url,
                "param": (evidence or {}).get("param_name"),
                "note": "Fixture protocol-relative //evil candidate — not a live farm",
            },
            "response": {
                "location": location or None,
                "observed": {
                    "protocol_relative": True,
                    "target": str(target)[:320],
                    "target_host": _target_host(str(target)) or None,
                    "fixture_name": row.get("name"),
                },
                "evidence_signal": (
                    f"protocol-relative target={str(target)[:200]!r} "
                    f"host={_target_host(str(target))!r}"
                ),
                "note": (
                    "Evidence = fixture //evil (or equivalent) signal. "
                    "Confirm parser/allowlist treats protocol-relative as absolute."
                ),
            },
        }
        out.append(
            _candidate(
                title="Protocol-relative open redirect (//evil) candidate",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="open_redirect_protocol_relative_candidate",
                evidence_summary=(
                    f"{check}: target={str(target)[:64]!r} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.5,
                reproducible=False,
                coach_hints=[COACH_OPEN_REDIRECT] + hints_for_pattern("protocol_relative")[:3],
            )
        )
    return out


def _encoded_bypass_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("encoded_bypass")
        or fixtures.get("encoding_bypass")
        or fixtures.get("encoded_redirect")
        or []
    )
    if not rows and not fixtures:
        rows = _default_encoded_fixtures()
        notes.append("using built-in 127.0.0.1 encoded-bypass fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        if not url:
            continue
        host = _resolve_host(ctx, url, notes, label="encoded_bypass")
        if host is None:
            continue

        evidence = _has_redirect_evidence(row, host)
        location = _location_from(row)
        _, param_value = _redirect_param_hit(row)
        target = (evidence or {}).get("target") or location or param_value or ""
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
        encoded = (
            (evidence and evidence.get("encoded_bypass"))
            or _is_encoded_bypass(str(target))
            or bool(expect.get("encoded_bypass"))
            or row.get("encoded_bypass") is True
        )
        if not encoded or not target:
            notes.append(
                f"encoded_bypass fixture lacks encoded // or scheme bypass "
                f"name={row.get('name') or url}"
            )
            continue
        if evidence is None and not (
            expect.get("encoded_bypass") or expect.get("open_redirect")
        ):
            notes.append(
                f"encoded_bypass skipped — no redirect evidence "
                f"name={row.get('name') or url}"
            )
            continue

        check = "open_redirect_encoded_bypass"
        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": str(row.get("method") or "GET").upper(),
                "url": url,
                "param": (evidence or {}).get("param_name"),
                "note": "Fixture encoded-bypass candidate — not a live spray",
            },
            "response": {
                "location": location or None,
                "observed": {
                    "encoded_bypass": True,
                    "target": str(target)[:320],
                    "decoded_stub": unquote(str(target))[:200],
                    "fixture_name": row.get("name"),
                },
                "evidence_signal": (
                    f"encoded bypass target={str(target)[:200]!r} "
                    f"decoded={unquote(str(target))[:120]!r}"
                ),
                "note": (
                    "Evidence = fixture encoded bypass marker. "
                    "Confirm decode-then-validate order before VERIFIED."
                ),
            },
        }
        out.append(
            _candidate(
                title="Encoded open-redirect bypass candidate",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="open_redirect_encoded_bypass_candidate",
                evidence_summary=(
                    f"{check}: target={str(target)[:64]!r} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.45,
                reproducible=False,
                coach_hints=[COACH_OPEN_REDIRECT] + hints_for_pattern("encoded_bypass")[:3],
            )
        )
    return out


def _location_reflect_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("location_reflect")
        or fixtures.get("location_header")
        or fixtures.get("location_reflection")
        or []
    )
    if not rows and not fixtures:
        rows = _default_location_fixtures()
        notes.append("using built-in 127.0.0.1 Location-reflection fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        if not url:
            continue
        host = _resolve_host(ctx, url, notes, label="location_reflect")
        if host is None:
            continue

        evidence = _has_redirect_evidence(row, host)
        location = _location_from(row)
        param_name, param_value = _redirect_param_hit(row)
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}

        reflects = bool(
            (evidence and evidence.get("location_reflects"))
            or expect.get("location_reflects")
            or row.get("location_reflects") is True
        )
        if not location:
            notes.append(
                f"location_reflect fixture missing Location value "
                f"name={row.get('name') or url}"
            )
            continue
        if not reflects:
            # Infer: param value appears in Location and Location is external
            if param_value and (
                param_value in location
                or unquote(param_value) in location
                or location == param_value
            ):
                reflects = True
        if not reflects:
            notes.append(
                f"location_reflect skipped — Location present but no reflection "
                f"signal name={row.get('name') or url}"
            )
            continue
        if not (
            _is_external_target(host, location)
            or _is_protocol_relative(location)
            or _is_encoded_bypass(location)
            or expect.get("external_redirect")
            or expect.get("open_redirect")
        ):
            notes.append(
                f"location_reflect skipped — Location not external/bypass "
                f"name={row.get('name') or url}"
            )
            continue

        check = "open_redirect_location_reflect"
        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": str(row.get("method") or "GET").upper(),
                "url": url,
                "param": param_name,
                "param_value_stub": (param_value or "")[:120],
                "note": "Fixture Location-reflection candidate — not a live spray",
            },
            "response": {
                "status": _status_of(row),
                "location": location[:320],
                "observed": {
                    "location_reflects": True,
                    "target_host": _target_host(location) or None,
                    "external_host": _is_external_target(host, location),
                    "fixture_name": row.get("name"),
                },
                "evidence_signal": (
                    f"Location={location[:200]!r} reflects attacker-controlled "
                    f"value param={param_name!r} target_host={_target_host(location)!r}"
                ),
                "note": (
                    "Evidence = Location header reflecting attacker-controlled "
                    "external value from fixture. Human must confirm."
                ),
            },
        }
        out.append(
            _candidate(
                title="Location header reflects attacker-controlled redirect",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="open_redirect_location_reflect_candidate",
                evidence_summary=(
                    f"{check}: Location host={_target_host(location)!r} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.55,
                reproducible=False,
                coach_hints=[COACH_OPEN_REDIRECT] + hints_for_pattern("location_header")[:3],
            )
        )
    return out


def _validation_coach_hints(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    """Allowlist vs denylist redirect validation coach hints (hints only)."""
    hints: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("redirect_validation")
        or fixtures.get("validation_patterns")
        or fixtures.get("patterns")
        or []
    )

    if not rows:
        for kind in ("allowlist_validation", "denylist_validation"):
            hints.append(build_hint_record(pattern_kind=kind))
        notes.append(
            "open_redirect validation coach: allowlist_validation + "
            "denylist_validation hints only (not auto-confirmed)"
        )
        return hints

    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))
    for row in rows:
        if not isinstance(row, dict):
            continue
        kind = str(
            row.get("pattern") or row.get("kind") or row.get("pattern_kind") or ""
        ).strip().lower()
        if not kind:
            kind = "generic_open_redirect"
        if kind in {"allowlist", "allow"}:
            kind = "allowlist_validation"
        if kind in {"denylist", "blocklist", "deny"}:
            kind = "denylist_validation"
        url = str(row.get("url") or row.get("endpoint") or "") or None
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        extra = []
        if row.get("note"):
            extra.append(str(row.get("note")))
        hints.append(
            build_hint_record(
                pattern_kind=kind,
                host=host,
                url=url,
                extra=extra or None,
            )
        )
    notes.append(f"open_redirect validation coach hints from fixtures: {len(hints)}")
    return hints


def _maybe_live_mock(
    ctx: dict[str, Any], caps_dict: dict[str, Any], notes: list[str]
) -> None:
    """If opener/live_mock present, enforce hard request caps (no mass spray)."""
    opener = ctx.get("opener")
    live_mock = (ctx.get("fixtures") or {}).get("live_mock")
    if opener is None and not live_mock:
        return

    budget = RequestBudget(max_requests=int(caps_dict["max_requests"]))
    notes.append(
        f"live mock path active — hard cap requests≤{caps_dict['max_requests']} "
        f"(hard_max={HARD_MAX_REQUESTS}); no redirect farm / param spray"
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
                opener({"probe": "open_redirect_typename"})
            except Exception as exc:  # noqa: BLE001
                notes.append(f"live mock opener soft-fail: {exc}")
        caps_dict["requests_used"] = budget.used


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """Run open_redirect pack v0 checks (fixture-first, evidence-backed, scope-gated)."""
    notes: list[str] = [
        "open_redirect v0: fixture-driven param / //evil / encoded / Location candidates",
        COACH_OPEN_REDIRECT,
        "findings default needs_human|unverified; never auto-VERIFIED/confirmed",
        "evidence must cite concrete redirect signals — no bare param-name noise",
        "no blind param spray / browser automation / live redirect farms",
        f"live-mock hard cap requests≤{HARD_MAX_REQUESTS}",
    ]

    try:
        caps = resolve_caps(
            max_requests=ctx.get("max_requests"),
            i_understand_lab=bool(ctx.get("i_understand_lab")),
        )
    except OpenRedirectCapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    caps_dict = caps.to_dict()
    _maybe_live_mock(ctx, caps_dict, notes)

    candidates: list[dict[str, Any]] = []
    candidates.extend(_param_redirect_candidates(ctx, notes))
    candidates.extend(_protocol_relative_candidates(ctx, notes))
    candidates.extend(_encoded_bypass_candidates(ctx, notes))
    candidates.extend(_location_reflect_candidates(ctx, notes))
    hints = _validation_coach_hints(ctx, notes)

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
            "no open-redirect candidates — provide fixtures param_redirect / "
            "protocol_relative / encoded_bypass / location_reflect under lab "
            "fixtures (or rely on built-in mocks when fixtures={})"
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


__all__ = [
    "run_checks",
    "COACH_OPEN_REDIRECT",
    "REDIRECT_PARAM_NAMES",
]
