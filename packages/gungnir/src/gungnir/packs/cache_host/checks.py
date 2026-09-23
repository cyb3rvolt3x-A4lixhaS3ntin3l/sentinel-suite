"""cache_host pack v0 — fixture-driven cache deception / Host-header evidence.

Evidence or it did not happen: cite concrete fixture diffs
(header-in vs body/header-out; cache-key A vs B; Cache-Control/Vary strings) —
never emit on Host / X-Forwarded-* header name alone.

Surfaces covered (fixture-first):
  - Host / X-Forwarded-Host / X-Forwarded-Scheme reflection into cacheable
    body or response headers
  - Path confusion / URL normalization cache-key mismatch (key A vs B)
  - Cache-Control / Vary weakness coach hints only

Cannot: poison production CDN / mass Host-header spray / live CDN poison
weapon. Staging/lab first. Never auto-VERIFIED.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from gungnir.packs.cache_host.caps import (
    COACH_CAPS,
    HARD_MAX_REQUESTS,
    RequestBudget,
    CacheHostCapExceededError,
    host_of,
    is_lab_local_host,
    resolve_caps,
)
from gungnir.packs.cache_host.hints import build_hint_record, hints_for_pattern
from gungnir.packs.manifest import finding_gate_checklist
from gungnir.packs.runner import PackRunError
from sentinel_core import Scope, ScopeDenied, assert_url_in_scope

_AUTO_STATUSES = frozenset({"needs_human", "unverified"})

# Request headers we look for reflection of (only WITH evidence diffs).
REFLECTED_HEADER_NAMES = frozenset(
    {
        "host",
        "x-forwarded-host",
        "x-forwarded-scheme",
        "x-forwarded-proto",
        "forwarded",
    }
)

COACH_CACHE_HOST = (
    "cache_host: evidence = concrete fixture diff "
    "(header-in vs body/header-out; cache-key A vs B). "
    "Do NOT emit on Host / X-Forwarded-* name alone. "
    "Staging/lab first — Cannot: poison production CDN. "
    "Fixture-driven only unless authorized lab mock."
)

CANNOT_PRODUCTION_CDN = (
    "Cannot: poison production CDN / live CDN purge-poison tooling / "
    "mass Host-header spray / browser farms. Staging/lab fixture evidence only."
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
        "coach_hints": list(coach_hints or [COACH_CACHE_HOST]),
        "evidence_summary": evidence_summary,
        "evidence_stub": evidence_stub,
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=reproducible,
            impact=impact,
            evidence_attached=True,
        ),
    }


def _req_headers(row: dict[str, Any]) -> dict[str, str]:
    headers = row.get("request_headers") or row.get("headers") or {}
    if isinstance(headers, dict):
        return {str(k).lower(): str(v) for k, v in headers.items() if v is not None}
    return {}


def _response_of(row: dict[str, Any]) -> dict[str, Any]:
    resp = row.get("response") or {}
    return resp if isinstance(resp, dict) else {}


def _resp_headers(row: dict[str, Any]) -> dict[str, str]:
    resp = _response_of(row)
    headers: dict[str, str] = {}
    if isinstance(resp.get("headers"), dict):
        headers = {str(k).lower(): str(v) for k, v in resp["headers"].items() if v is not None}
    # Top-level response_* convenience
    for key in ("location", "cache_control", "vary", "content_type"):
        if row.get(key) is not None and key.replace("_", "-") not in headers:
            headers[key.replace("_", "-")] = str(row.get(key))
    return headers


def _resp_body(row: dict[str, Any]) -> str:
    resp = _response_of(row)
    body = resp.get("body")
    if body is None:
        body = row.get("body") or row.get("response_body") or ""
    return str(body)


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


def _is_cacheable_signal(row: dict[str, Any], resp_headers: dict[str, str]) -> bool:
    """True when fixture indicates the response is (or could be) cacheable."""
    expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
    if expect.get("cacheable") is True or row.get("cacheable") is True:
        return True
    cc = (resp_headers.get("cache-control") or "").lower()
    if not cc:
        # Missing Cache-Control on a reflected response is itself a weakness signal
        # when fixture explicitly marks reflection into a shared context.
        if expect.get("reflected") or expect.get("host_reflects") or expect.get("xfh_reflects"):
            return True
        return False
    if "no-store" in cc or "private" in cc:
        # Still allow if fixture explicitly says cacheable (CDN may ignore)
        return bool(expect.get("cacheable") or expect.get("cdn_caches") or row.get("cdn_caches"))
    if "public" in cc or "max-age=" in cc or "s-maxage=" in cc:
        return True
    return False


def _find_reflection(
    injected: str, body: str, resp_headers: dict[str, str]
) -> dict[str, Any] | None:
    """Locate injected value in body or response headers; return where it landed."""
    inj = (injected or "").strip()
    if not inj:
        return None
    lands: list[str] = []
    if inj in body:
        lands.append("body")
    for hk, hv in resp_headers.items():
        if inj in hv:
            lands.append(f"header:{hk}")
    if not lands:
        # Case-insensitive fallback for hostnames
        inj_l = inj.lower()
        if inj_l and inj_l in body.lower():
            lands.append("body")
        for hk, hv in resp_headers.items():
            if inj_l in hv.lower():
                lands.append(f"header:{hk}")
    if not lands:
        return None
    return {"value": inj[:200], "lands_in": lands}


def _host_header_value(row: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return (header_name, injected_value) for Host / XFH / XFS from fixture."""
    req = _req_headers(row)
    # Explicit fields take precedence
    for field, name in (
        ("x_forwarded_host", "x-forwarded-host"),
        ("x_forwarded_scheme", "x-forwarded-scheme"),
        ("x_forwarded_proto", "x-forwarded-proto"),
        ("host_header", "host"),
        ("injected_host", "host"),
    ):
        if row.get(field):
            return name, str(row.get(field)).strip()
    for name in (
        "x-forwarded-host",
        "x-forwarded-scheme",
        "x-forwarded-proto",
        "host",
    ):
        if name in req and str(req[name]).strip():
            return name, str(req[name]).strip()
    # params-style injection
    params = row.get("params") or {}
    if isinstance(params, dict):
        for key in ("host", "x_forwarded_host", "xfh", "x_forwarded_scheme"):
            if params.get(key):
                mapped = {
                    "host": "host",
                    "x_forwarded_host": "x-forwarded-host",
                    "xfh": "x-forwarded-host",
                    "x_forwarded_scheme": "x-forwarded-scheme",
                }[key]
                return mapped, str(params[key]).strip()
    return None, None


def _has_host_reflection_evidence(row: dict[str, Any]) -> dict[str, Any] | None:
    """
    Require concrete reflection evidence: injected header value lands in
    cacheable body/headers. Never emit on header name alone.
    """
    expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
    header_name, injected = _host_header_value(row)
    body = _resp_body(row)
    resp_headers = _resp_headers(row)

    if not injected:
        return None

    reflection = _find_reflection(injected, body, resp_headers)
    # Explicit expect can supply reflected_in / reflected_value
    if reflection is None:
        reflected_value = (
            expect.get("reflected_value")
            or row.get("reflected_value")
            or expect.get("reflected")
        )
        if isinstance(reflected_value, str) and injected in reflected_value:
            reflection = {
                "value": injected[:200],
                "lands_in": [str(expect.get("reflected_in") or row.get("reflected_in") or "body")],
            }
        elif expect.get("host_reflects") or expect.get("xfh_reflects") or expect.get("scheme_reflects"):
            # Expect flags without locating the value — still need the value in body/headers
            return None

    if reflection is None:
        return None

    cacheable = _is_cacheable_signal(row, resp_headers)
    # Require cacheable signal OR explicit expect that reflection is cache-relevant
    if not cacheable and not (
        expect.get("cacheable")
        or expect.get("cache_poison")
        or expect.get("host_reflects")
        or expect.get("xfh_reflects")
        or expect.get("scheme_reflects")
        or row.get("cacheable") is True
    ):
        # Reflection into a clearly non-cacheable private response is still
        # interesting as Host-header evidence, but we require an explicit expect
        # or Cache-Control string present for honesty — skip bare reflection
        # without cache context unless expect says reflected.
        if not (expect.get("reflected") or expect.get("host_reflects")):
            return None

    # Diff strings for evidence
    header_in = f"{header_name or 'host'}: {injected}"
    out_parts = []
    for land in reflection["lands_in"]:
        if land == "body":
            # cite a short body snippet around the value
            idx = body.lower().find(injected.lower())
            if idx >= 0:
                snippet = body[max(0, idx - 20) : idx + len(injected) + 20]
                out_parts.append(f"body≈{snippet!r}")
            else:
                out_parts.append("body (value present)")
        elif land.startswith("header:"):
            hk = land.split(":", 1)[1]
            out_parts.append(f"{hk}: {resp_headers.get(hk, '')[:160]}")
    header_out = "; ".join(out_parts) if out_parts else str(reflection["lands_in"])

    return {
        "header_name": header_name or "host",
        "injected": injected[:200],
        "lands_in": reflection["lands_in"],
        "cacheable": cacheable or bool(expect.get("cacheable") or expect.get("cache_poison")),
        "cache_control": resp_headers.get("cache-control"),
        "vary": resp_headers.get("vary"),
        "status": _status_of(row),
        "diff_header_in": header_in[:240],
        "diff_header_out": header_out[:320],
        "fixture_name": row.get("name"),
    }


def _has_key_mismatch_evidence(row: dict[str, Any]) -> dict[str, Any] | None:
    """
    Require concrete cache-key A vs B mismatch with a content/header diff.
    """
    expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
    keys_map = row.get("keys") if isinstance(row.get("keys"), dict) else {}
    key_a = row.get("cache_key_a") or row.get("key_a") or keys_map.get("a")
    key_b = row.get("cache_key_b") or row.get("key_b") or keys_map.get("b")
    # Nested request_a / request_b style
    req_a = row.get("request_a") if isinstance(row.get("request_a"), dict) else {}
    req_b = row.get("request_b") if isinstance(row.get("request_b"), dict) else {}
    if key_a is None:
        key_a = req_a.get("cache_key") or req_a.get("key")
    if key_b is None:
        key_b = req_b.get("cache_key") or req_b.get("key")

    if key_a is None or key_b is None:
        return None
    key_a_s = str(key_a).strip()
    key_b_s = str(key_b).strip()
    if not key_a_s or not key_b_s:
        return None
    if key_a_s == key_b_s and not (
        expect.get("key_mismatch") is True
        or expect.get("normalization_mismatch") is True
        or row.get("key_mismatch") is True
    ):
        # Same key string — only emit if fixture claims mismatch via normalization
        # of equivalent paths that SHOULD differ or vice versa; without a content
        # diff this is insufficient.
        return None

    # Content / header diff between A and B
    body_a = str(
        row.get("body_a")
        or (row.get("response_a") or {}).get("body")
        or req_a.get("body")
        or ""
    )
    body_b = str(
        row.get("body_b")
        or (row.get("response_b") or {}).get("body")
        or req_b.get("body")
        or ""
    )
    headers_a = {}
    headers_b = {}
    if isinstance(row.get("response_a"), dict) and isinstance(row["response_a"].get("headers"), dict):
        headers_a = {str(k).lower(): str(v) for k, v in row["response_a"]["headers"].items()}
    if isinstance(row.get("response_b"), dict) and isinstance(row["response_b"].get("headers"), dict):
        headers_b = {str(k).lower(): str(v) for k, v in row["response_b"]["headers"].items()}
    if isinstance(req_a.get("response_headers"), dict):
        headers_a = {str(k).lower(): str(v) for k, v in req_a["response_headers"].items()}
    if isinstance(req_b.get("response_headers"), dict):
        headers_b = {str(k).lower(): str(v) for k, v in req_b["response_headers"].items()}

    content_diff = body_a != body_b and (body_a != "" or body_b != "")
    header_diff = headers_a != headers_b and (headers_a or headers_b)
    path_a = str(row.get("path_a") or req_a.get("path") or req_a.get("url") or "")
    path_b = str(row.get("path_b") or req_b.get("path") or req_b.get("url") or "")
    keys_differ = key_a_s != key_b_s

    # Need keys differing OR explicit mismatch expect, PLUS a content/header/path signal
    if not keys_differ and not (
        expect.get("key_mismatch") or expect.get("normalization_mismatch")
    ):
        return None
    if not (content_diff or header_diff or (path_a and path_b and path_a != path_b) or expect.get("key_mismatch")):
        # If keys differ but no content/path evidence, still allow when expect says so
        if not (expect.get("key_mismatch") or expect.get("path_confusion") or expect.get("normalization_mismatch")):
            return None

    return {
        "cache_key_a": key_a_s[:240],
        "cache_key_b": key_b_s[:240],
        "keys_differ": keys_differ,
        "content_diff": content_diff,
        "header_diff": bool(header_diff),
        "path_a": path_a[:200] or None,
        "path_b": path_b[:200] or None,
        "body_a_stub": body_a[:120] or None,
        "body_b_stub": body_b[:120] or None,
        "fixture_name": row.get("name"),
        "diff_summary": (
            f"cache_key_a={key_a_s[:120]!r} vs cache_key_b={key_b_s[:120]!r}; "
            f"content_diff={content_diff}; header_diff={bool(header_diff)}; "
            f"path_a={path_a[:80]!r} path_b={path_b[:80]!r}"
        ),
    }


def _default_host_reflect_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-host-reflect-cacheable",
            "url": "http://127.0.0.1/app",
            "request_headers": {"Host": "evil.example"},
            "response": {
                "status": 200,
                "headers": {
                    "Cache-Control": "public, max-age=3600",
                    "Content-Type": "text/html",
                },
                "body": '<html><link rel="canonical" href="https://evil.example/app"/></html>',
            },
            "expect": {"host_reflects": True, "cacheable": True},
        },
        {
            "name": "lab-xfh-reflect-cacheable",
            "url": "http://127.0.0.1/page",
            "request_headers": {
                "Host": "127.0.0.1",
                "X-Forwarded-Host": "attacker.example",
            },
            "response": {
                "status": 200,
                "headers": {
                    "Cache-Control": "public, max-age=600",
                    "Location": "https://attacker.example/page",
                },
                "body": "Welcome to attacker.example",
            },
            "expect": {"xfh_reflects": True, "cacheable": True},
        },
    ]


def _default_scheme_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-xfs-reflect-cacheable",
            "url": "http://127.0.0.1/login",
            "request_headers": {
                "Host": "127.0.0.1",
                "X-Forwarded-Scheme": "http",
            },
            "response": {
                "status": 200,
                "headers": {"Cache-Control": "public, max-age=120"},
                "body": '<a href="http://127.0.0.1/login">continue</a>',
            },
            "expect": {"scheme_reflects": True, "cacheable": True},
        }
    ]


def _default_key_mismatch_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-path-confusion-keys",
            "url": "http://127.0.0.1/static",
            "path_a": "/static/../admin",
            "path_b": "/admin",
            "cache_key_a": "GET|/static/../admin|host=127.0.0.1",
            "cache_key_b": "GET|/admin|host=127.0.0.1",
            "body_a": "cached-static-poison",
            "body_b": "real-admin",
            "expect": {"key_mismatch": True, "path_confusion": True},
        }
    ]


def _host_reflect_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("host_reflect")
        or fixtures.get("host_reflection")
        or fixtures.get("xfh_reflect")
        or fixtures.get("header_reflect")
        or []
    )
    if not rows and not fixtures:
        rows = _default_host_reflect_fixtures()
        notes.append("using built-in 127.0.0.1 Host/XFH reflection fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        if not url:
            continue
        host = _resolve_host(ctx, url, notes, label="host_reflect")
        if host is None:
            continue

        header_name, injected = _host_header_value(row)
        evidence = _has_host_reflection_evidence(row)
        if evidence is None:
            if header_name:
                notes.append(
                    f"host_reflect skipped — header={header_name!r} present but no "
                    f"reflection/cacheable evidence diff name={row.get('name') or url}"
                )
            else:
                notes.append(
                    f"host_reflect skipped — no Host/XFH injection+reflection evidence "
                    f"name={row.get('name') or url}"
                )
            continue

        # Pick check id by which header reflected
        hname = evidence["header_name"]
        if hname in {"x-forwarded-host"}:
            check = "cache_host_xfh_reflect"
            title = "X-Forwarded-Host reflection into cacheable response"
            pattern = "x_forwarded_host"
        elif hname in {"x-forwarded-scheme", "x-forwarded-proto"}:
            check = "cache_host_xfs_reflect"
            title = "X-Forwarded-Scheme reflection into cacheable response"
            pattern = "x_forwarded_scheme"
        else:
            check = "cache_host_host_reflect"
            title = "Host header reflection into cacheable response"
            pattern = "host_reflection"

        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": str(row.get("method") or "GET").upper(),
                "url": url,
                "header": evidence["header_name"],
                "injected_value_stub": evidence["injected"][:120],
                "note": (
                    "Fixture-only cache/Host reflection candidate — not a live "
                    "CDN poison / Host-header spray"
                ),
            },
            "response": {
                "status": evidence.get("status"),
                "cache_control": evidence.get("cache_control"),
                "vary": evidence.get("vary"),
                "observed": {
                    "lands_in": evidence.get("lands_in"),
                    "cacheable": evidence.get("cacheable"),
                    "fixture_name": evidence.get("fixture_name"),
                },
                "evidence_signal": (
                    f"diff header_in={evidence['diff_header_in']!r} → "
                    f"header_out/body={evidence['diff_header_out']!r}; "
                    f"cacheable={evidence.get('cacheable')}"
                ),
                "note": (
                    "Evidence = fixture header-in vs body/header-out diff. "
                    "Confirm shared-cache impact before VERIFIED. "
                    + CANNOT_PRODUCTION_CDN
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
                impact=f"{check}_candidate",
                evidence_summary=(
                    f"{check}: injected={evidence['injected']!r} "
                    f"lands_in={evidence.get('lands_in')} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.5,
                reproducible=False,
                coach_hints=[COACH_CACHE_HOST] + hints_for_pattern(pattern)[:3],
            )
        )
    return out


def _scheme_reflect_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("scheme_reflect")
        or fixtures.get("x_forwarded_scheme")
        or fixtures.get("xfs_reflect")
        or []
    )
    if not rows and not fixtures:
        rows = _default_scheme_fixtures()
        notes.append("using built-in 127.0.0.1 X-Forwarded-Scheme fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        if not url:
            continue
        host = _resolve_host(ctx, url, notes, label="scheme_reflect")
        if host is None:
            continue

        evidence = _has_host_reflection_evidence(row)
        header_name, _injected = _host_header_value(row)
        if evidence is None or (
            evidence["header_name"] not in {"x-forwarded-scheme", "x-forwarded-proto"}
            and not (
                isinstance(row.get("expect"), dict)
                and row["expect"].get("scheme_reflects")
            )
        ):
            # If default host_reflect already covered XFS under host_reflect key,
            # scheme-specific bucket still needs scheme header evidence.
            if header_name and header_name not in {"x-forwarded-scheme", "x-forwarded-proto"}:
                notes.append(
                    f"scheme_reflect skipped — expected X-Forwarded-Scheme/Proto "
                    f"name={row.get('name') or url}"
                )
                continue
            if evidence is None:
                notes.append(
                    f"scheme_reflect skipped — no scheme reflection evidence "
                    f"name={row.get('name') or url}"
                )
                continue

        check = "cache_host_xfs_reflect"
        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": str(row.get("method") or "GET").upper(),
                "url": url,
                "header": evidence["header_name"],
                "injected_value_stub": evidence["injected"][:120],
                "note": "Fixture X-Forwarded-Scheme candidate — not production CDN poison",
            },
            "response": {
                "status": evidence.get("status"),
                "cache_control": evidence.get("cache_control"),
                "observed": {
                    "lands_in": evidence.get("lands_in"),
                    "cacheable": evidence.get("cacheable"),
                    "fixture_name": evidence.get("fixture_name"),
                },
                "evidence_signal": (
                    f"diff header_in={evidence['diff_header_in']!r} → "
                    f"out={evidence['diff_header_out']!r}"
                ),
                "note": CANNOT_PRODUCTION_CDN,
            },
        }
        out.append(
            _candidate(
                title="X-Forwarded-Scheme reflection into cacheable response",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="cache_host_xfs_reflect_candidate",
                evidence_summary=(
                    f"{check}: injected={evidence['injected']!r} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.5,
                reproducible=False,
                coach_hints=[COACH_CACHE_HOST] + hints_for_pattern("x_forwarded_scheme")[:3],
            )
        )
    return out


def _key_mismatch_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("path_confusion")
        or fixtures.get("cache_key_mismatch")
        or fixtures.get("key_mismatch")
        or fixtures.get("normalization")
        or []
    )
    if not rows and not fixtures:
        rows = _default_key_mismatch_fixtures()
        notes.append("using built-in 127.0.0.1 path-confusion cache-key fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(
            row.get("url")
            or row.get("endpoint")
            or (row.get("request_a") or {}).get("url")
            or ""
        )
        if not url:
            continue
        host = _resolve_host(ctx, url, notes, label="path_confusion")
        if host is None:
            continue

        evidence = _has_key_mismatch_evidence(row)
        if evidence is None:
            notes.append(
                f"path_confusion/key_mismatch skipped — need cache_key_a vs "
                f"cache_key_b (+ content/path diff) name={row.get('name') or url}"
            )
            continue

        check = "cache_host_key_mismatch"
        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": str(row.get("method") or "GET").upper(),
                "url": url,
                "path_a": evidence.get("path_a"),
                "path_b": evidence.get("path_b"),
                "note": (
                    "Fixture path-confusion / cache-key mismatch — not a live "
                    "CDN poison tool"
                ),
            },
            "response": {
                "observed": {
                    "cache_key_a": evidence.get("cache_key_a"),
                    "cache_key_b": evidence.get("cache_key_b"),
                    "keys_differ": evidence.get("keys_differ"),
                    "content_diff": evidence.get("content_diff"),
                    "header_diff": evidence.get("header_diff"),
                    "fixture_name": evidence.get("fixture_name"),
                },
                "evidence_signal": evidence.get("diff_summary"),
                "note": (
                    "Evidence = fixture cache-key A vs B (+ content/header/path diff). "
                    + CANNOT_PRODUCTION_CDN
                ),
            },
        }
        out.append(
            _candidate(
                title="Cache-key mismatch / path-confusion candidate",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="cache_host_key_mismatch_candidate",
                evidence_summary=(
                    f"{check}: key_a={evidence['cache_key_a'][:64]!r} "
                    f"key_b={evidence['cache_key_b'][:64]!r} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.5,
                reproducible=False,
                coach_hints=[COACH_CACHE_HOST]
                + hints_for_pattern("path_confusion")[:2]
                + hints_for_pattern("cache_key_mismatch")[:2],
            )
        )
    return out


def _cache_vary_coach_hints(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    """Cache-Control / Vary weakness coach hints (hints only — not auto-confirm)."""
    hints: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("cache_control_vary")
        or fixtures.get("cache_vary")
        or fixtures.get("vary_weakness")
        or fixtures.get("patterns")
        or []
    )

    if not rows:
        for kind in ("cache_control_weakness", "vary_weakness"):
            hints.append(build_hint_record(pattern_kind=kind))
        notes.append(
            "cache_host coach: cache_control_weakness + vary_weakness hints only "
            "(not auto-confirmed); " + CANNOT_PRODUCTION_CDN
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
            # Infer from fixture strings
            cc = str(row.get("cache_control") or row.get("Cache-Control") or "")
            vary = str(row.get("vary") or row.get("Vary") or "")
            if cc:
                kind = "cache_control_weakness"
            elif vary:
                kind = "vary_weakness"
            else:
                kind = "generic_cache_host"
        if kind in {"cache-control", "cache_control", "cc"}:
            kind = "cache_control_weakness"
        if kind in {"vary", "vary_header"}:
            kind = "vary_weakness"
        url = str(row.get("url") or row.get("endpoint") or "") or None
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        extra = []
        if row.get("note"):
            extra.append(str(row.get("note")))
        cc = row.get("cache_control") or row.get("Cache-Control")
        vary = row.get("vary") or row.get("Vary")
        if cc:
            extra.append(f"observed Cache-Control={cc!r} (hint only)")
        if vary:
            extra.append(f"observed Vary={vary!r} (hint only)")
        hints.append(
            build_hint_record(
                pattern_kind=kind,
                host=host,
                url=url,
                extra=extra or None,
            )
        )
    notes.append(f"cache_host Cache-Control/Vary coach hints from fixtures: {len(hints)}")
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
        f"(hard_max={HARD_MAX_REQUESTS}); no Host-header spray / CDN poison"
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
                opener({"probe": "cache_host_typename"})
            except Exception as exc:  # noqa: BLE001
                notes.append(f"live mock opener soft-fail: {exc}")
        caps_dict["requests_used"] = budget.used


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """Run cache_host pack v0 checks (fixture-first, evidence-backed, scope-gated)."""
    notes: list[str] = [
        "cache_host v0: fixture-driven Host/XFH/XFS reflection + cache-key mismatch",
        COACH_CACHE_HOST,
        CANNOT_PRODUCTION_CDN,
        "findings default needs_human|unverified; never auto-VERIFIED/confirmed",
        "evidence must cite fixture diffs — no bare Host/X-Forwarded-* name noise",
        f"live-mock hard cap requests≤{HARD_MAX_REQUESTS}",
    ]

    try:
        caps = resolve_caps(
            max_requests=ctx.get("max_requests"),
            i_understand_lab=bool(ctx.get("i_understand_lab")),
        )
    except CacheHostCapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    caps_dict = caps.to_dict()
    _maybe_live_mock(ctx, caps_dict, notes)

    candidates: list[dict[str, Any]] = []
    candidates.extend(_host_reflect_candidates(ctx, notes))
    candidates.extend(_scheme_reflect_candidates(ctx, notes))
    candidates.extend(_key_mismatch_candidates(ctx, notes))
    hints = _cache_vary_coach_hints(ctx, notes)

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
            "no cache_host candidates — provide fixtures host_reflect / "
            "scheme_reflect / path_confusion under lab fixtures "
            "(or rely on built-in mocks when fixtures={})"
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
        "cannot": [CANNOT_PRODUCTION_CDN],
    }


__all__ = [
    "run_checks",
    "COACH_CACHE_HOST",
    "CANNOT_PRODUCTION_CDN",
    "REFLECTED_HEADER_NAMES",
]
