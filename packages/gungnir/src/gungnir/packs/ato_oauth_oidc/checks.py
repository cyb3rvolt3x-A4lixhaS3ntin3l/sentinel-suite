"""ATO/OAuth/OIDC v0 checks — candidates + replayable evidence stubs.

No exploit payloads, no lockout loops, no live IdP abuse automation.
Optional HTTP only via sentinel_core.scoped_request (tests inject opener).
"""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from gungnir.packs.manifest import finding_gate_checklist
from sentinel_core import Scope, ScopeDenied, assert_url_in_scope, scoped_request

_TOKEN_LEAK_RE = re.compile(
    r"(?i)(?:^|[?#&])(access_token|id_token|code|refresh_token)=([^&\s#]+)"
)
_OPEN_REDIRECT_URI_RE = re.compile(
    r"(?i)redirect_uri=(https?://(?![^&]*example\.com)[^&]+|https?%3A%2F%2F[^&]+)"
)
# Weak open-redirect patterns often used in labs / misconfig candidates
_REDIRECT_PARAM_HOST_RE = re.compile(
    r"(?i)(?:redirect_uri|redirect_url|return_to|next|continue)=([^&]+)"
)


def _host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower().rstrip(".")


def _scope_gate(scope: Scope | None, url: str, *, i_own_this: bool) -> str | None:
    """Return host if allowed; None if hard-killed / unscoped without lab flag."""
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


def _oauth_param_candidates(surface: list[dict[str, Any]], ctx: dict[str, Any]) -> list[dict]:
    """redirect_uri / state / PKCE presence & misuse candidates (heuristic)."""
    out: list[dict[str, Any]] = []
    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))

    for surf in surface:
        url = surf.get("url") or ""
        host = _scope_gate(scope, url, i_own_this=i_own)
        if not host:
            continue
        kinds = set(surf.get("kinds") or [])
        qkeys = {k.lower() for k in (surf.get("query_keys") or [])}
        oauthish = kinds & {
            "oauth_authorize",
            "oidc",
            "callback",
            "oauth_param",
            "login",
        }
        if not oauthish and not (
            qkeys & {"client_id", "response_type", "redirect_uri", "code_challenge"}
        ):
            continue

        issues: list[str] = []
        if "client_id" in qkeys or "response_type" in qkeys or "oauth_authorize" in kinds:
            if "state" not in qkeys:
                issues.append("missing_state_candidate")
            # Public-client PKCE hint: response_type=code without code_challenge
            parsed = urlparse(url)
            qs = {k.lower(): v for k, v in parse_qs(parsed.query).items()}
            rt = (qs.get("response_type") or [""])[0].lower()
            if rt == "code" and "code_challenge" not in qkeys:
                issues.append("missing_pkce_public_client_hint")
            if "redirect_uri" in qkeys:
                raw_ru = (qs.get("redirect_uri") or qs.get("redirect_url") or [""])[0]
                if raw_ru and (
                    "*" in raw_ru
                    or raw_ru.startswith("//")
                    or "redirect_uri=" in raw_ru.lower()
                ):
                    issues.append("open_redirect_uri_pattern_candidate")
                # Loose external redirect_uri host vs request host
                try:
                    ru_host = _host(raw_ru) if raw_ru else ""
                    if ru_host and ru_host != host and not ru_host.endswith("." + host):
                        issues.append("redirect_uri_host_mismatch_candidate")
                except Exception:  # noqa: BLE001
                    pass

        for issue in issues:
            stub = {
                "check": issue,
                "request": {"method": "GET", "url": url},
                "response": {"status": None, "note": "heuristic_only_no_fetch"},
            }
            out.append(
                {
                    "title": f"OAuth/OIDC {issue.replace('_', ' ')}",
                    "host": host,
                    "url": url,
                    "check": issue,
                    "verification": "unverified",
                    "confidence": 0.35,
                    "impact": "auth_misconfig_candidate",
                    "reproducible": False,
                    "in_scope": True,
                    "evidence_attached": True,
                    "evidence_summary": f"Heuristic candidate: {issue} on {url}",
                    "evidence_stub": stub,
                    "checklist": finding_gate_checklist(
                        in_scope=True,
                        reproducible=False,
                        impact="auth_misconfig_candidate",
                        evidence_attached=True,
                    ),
                }
            )
    return out


def _token_leakage_candidates(ctx: dict[str, Any]) -> list[dict]:
    """Look for access_token|id_token|code in Location/fragment patterns on fixtures."""
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))

    # Fixture shape: {"token_leak_responses": [{"url", "location", "body", "status"}]}
    for row in fixtures.get("token_leak_responses") or []:
        url = str(row.get("url") or "")
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        if url and host is None:
            continue
        location = str(row.get("location") or "")
        body = str(row.get("body") or "")
        blob = f"{location}\n{body}"
        matches = _TOKEN_LEAK_RE.findall(blob)
        # Also fragment-style Location: https://app/#access_token=...
        if "#" in location:
            frag = location.split("#", 1)[1]
            matches.extend(_TOKEN_LEAK_RE.findall("#" + frag))
        if not matches and "access_token=" not in blob.lower() and "id_token=" not in blob.lower():
            # code= in query of Location is a soft candidate only with oauth callback context
            if "code=" in location.lower() and (
                "oauth" in (url + location).lower() or "callback" in (url + location).lower()
            ):
                matches = [("code", "(redacted)")]
            else:
                continue
        token_types = sorted({m[0].lower() for m in matches})
        host = host or (_host(url) if url else "unknown")
        stub = {
            "check": "oauth_token_leakage_candidate",
            "request": {"method": "GET", "url": url},
            "response": {
                "status": row.get("status"),
                "location_stub": location[:200] if location else None,
                "token_types_observed": token_types,
                "note": "values redacted — pattern match only",
            },
        }
        out.append(
            {
                "title": "OAuth token leakage candidate in redirect/fragment/query",
                "host": host,
                "url": url,
                "check": "oauth_token_leakage_candidate",
                "token_types": token_types,
                "verification": "unverified",
                "confidence": 0.45,
                "impact": "token_exposure_candidate",
                "reproducible": bool(row.get("reproducible")),
                "in_scope": True,
                "evidence_attached": True,
                "evidence_summary": (
                    f"Pattern candidate for {', '.join(token_types)} in Location/body stub"
                ),
                "evidence_stub": stub,
                "checklist": finding_gate_checklist(
                    in_scope=True,
                    reproducible=bool(row.get("reproducible")),
                    impact="token_exposure_candidate",
                    evidence_attached=True,
                ),
            }
        )

    # Also scan surface URLs themselves for fragment/query token patterns (no fetch)
    for surf in ctx.get("surface") or []:
        url = surf.get("url") or ""
        host = _scope_gate(scope, url, i_own_this=i_own)
        if not host:
            continue
        matches = _TOKEN_LEAK_RE.findall(url)
        if not matches:
            continue
        token_types = sorted({m[0].lower() for m in matches})
        stub = {
            "check": "oauth_token_leakage_candidate",
            "request": {"method": "GET", "url": url.split("#")[0] + "#<redacted>"},
            "response": {
                "status": None,
                "token_types_observed": token_types,
                "note": "URL/fragment heuristic — no live fetch",
            },
        }
        out.append(
            {
                "title": "OAuth token leakage candidate in URL/fragment",
                "host": host,
                "url": url.split("#")[0],
                "check": "oauth_token_leakage_candidate",
                "token_types": token_types,
                "verification": "unverified",
                "confidence": 0.4,
                "impact": "token_exposure_candidate",
                "reproducible": False,
                "in_scope": True,
                "evidence_attached": True,
                "evidence_summary": "URL/fragment pattern candidate (values not stored)",
                "evidence_stub": stub,
                "checklist": finding_gate_checklist(
                    in_scope=True,
                    reproducible=False,
                    impact="token_exposure_candidate",
                    evidence_attached=True,
                ),
            }
        )
    return out


def _reset_enumeration_candidates(ctx: dict[str, Any]) -> list[dict]:
    """
    Password reset / account enumeration candidates — fixture-driven.

    Compares known vs unknown responses from fixtures. Rate-aware messaging;
    does not loop / lockout-abuse.
    """
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))
    opener: Callable[..., Any] | None = ctx.get("opener")

    rows = fixtures.get("reset_enumeration") or []
    # Optional single live compare via scoped_request when opener provided (tests)
    live = fixtures.get("reset_live")
    if live and opener is not None and scope is not None:
        url = str(live.get("url") or "")
        try:
            assert_url_in_scope(scope, url)
        except ScopeDenied:
            url = ""
        if url:
            # One known + one unknown only — no loops
            for label, body in (
                ("known", live.get("known_body") or b"email=known@lab.example"),
                ("unknown", live.get("unknown_body") or b"email=nosuch@lab.example"),
            ):
                data = body if isinstance(body, (bytes, bytearray)) else str(body).encode()
                try:
                    resp = scoped_request(
                        scope,
                        str(live.get("method") or "POST"),
                        url,
                        data=data,
                        headers=dict(live.get("headers") or {}),
                        opener=opener,
                        timeout=float(live.get("timeout") or 5),
                    )
                    status = getattr(resp, "status", None) or getattr(resp, "code", None)
                    raw = getattr(resp, "read", lambda: b"")()
                    if isinstance(raw, bytes):
                        text = raw.decode("utf-8", errors="replace")
                    else:
                        text = str(raw)
                    rows.append(
                        {
                            "url": url,
                            "label": label,
                            "status": status,
                            "body": text[:500],
                            "headers": dict(getattr(resp, "headers", {}) or {}),
                        }
                    )
                except ScopeDenied:
                    break

    # Group fixture rows by url
    by_url: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        u = str(row.get("url") or "")
        by_url.setdefault(u, []).append(row)

    for url, group in by_url.items():
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        if url and host is None:
            continue
        host = host or "unknown"
        known = next((r for r in group if str(r.get("label", "")).lower() == "known"), None)
        unknown = next(
            (r for r in group if str(r.get("label", "")).lower() == "unknown"), None
        )
        if not known or not unknown:
            continue
        diff_bits: list[str] = []
        if known.get("status") != unknown.get("status"):
            diff_bits.append(
                f"status {known.get('status')} vs {unknown.get('status')}"
            )
        kb = str(known.get("body") or "")
        ub = str(unknown.get("body") or "")
        if kb.strip() != ub.strip():
            diff_bits.append("body_diff")
        kh = str((known.get("headers") or {}).get("set-cookie", ""))
        uh = str((unknown.get("headers") or {}).get("set-cookie", ""))
        if kh != uh:
            diff_bits.append("set_cookie_diff")
        if not diff_bits:
            continue
        stub = {
            "check": "password_reset_enumeration_candidate",
            "request": {"method": "POST", "url": url},
            "response": {
                "known_status": known.get("status"),
                "unknown_status": unknown.get("status"),
                "diff": diff_bits,
                "note": (
                    "Fixture/compare only — do not loop; back off on 429; "
                    "no lockout abuse"
                ),
            },
        }
        out.append(
            {
                "title": "Password reset / account enumeration candidate",
                "host": host,
                "url": url,
                "check": "password_reset_enumeration_candidate",
                "diff": diff_bits,
                "verification": "unverified",
                "confidence": 0.4,
                "impact": "account_enumeration_candidate",
                "reproducible": True,
                "in_scope": True,
                "evidence_attached": True,
                "evidence_summary": (
                    "Different responses for known vs unknown account "
                    f"({', '.join(diff_bits)}). Rate-aware: stop on 429; no lockout loops."
                ),
                "evidence_stub": stub,
                "checklist": finding_gate_checklist(
                    in_scope=True,
                    reproducible=True,
                    impact="account_enumeration_candidate",
                    evidence_attached=True,
                ),
            }
        )

    # Surface-only note when reset paths exist but no fixtures — skipped honesty
    if not out:
        reset_surfaces = [
            s
            for s in (ctx.get("surface") or [])
            if "password_reset" in set(s.get("kinds") or [])
            or any(
                t in (s.get("path") or "").lower()
                for t in ("reset", "forgot")
            )
        ]
        for surf in reset_surfaces[:3]:
            url = surf.get("url") or ""
            host = _scope_gate(scope, url, i_own_this=i_own)
            if not host:
                continue
            out.append(
                {
                    "title": "Password reset surface candidate (no enumeration compare)",
                    "host": host,
                    "url": url,
                    "check": "password_reset_surface_candidate",
                    "verification": "skipped",
                    "confidence": 0.25,
                    "impact": "informational",
                    "reproducible": False,
                    "in_scope": True,
                    "evidence_attached": False,
                    "evidence_summary": (
                        "Reset/forgot path detected; enumeration compare skipped "
                        "(provide fixtures.reset_enumeration). No lockout loops."
                    ),
                    "checklist": finding_gate_checklist(
                        in_scope=True,
                        reproducible=False,
                        impact="informational",
                        evidence_attached=False,
                    ),
                }
            )
    return out


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """Run all v0 checks; filter OOS before returning candidates."""
    notes = [
        "ato_oauth_oidc v0: candidates + evidence stubs only",
        "no full ATO chain automation; no live IdP attack playbooks",
        "no BOLA; no report factory; nuclei-all not used",
    ]
    surface = list(ctx.get("surface") or [])
    # Also fold explicit --url list through surface if pack runner already did
    candidates: list[dict[str, Any]] = []
    candidates.extend(_oauth_param_candidates(surface, ctx))
    candidates.extend(_token_leakage_candidates(ctx))
    candidates.extend(_reset_enumeration_candidates(ctx))

    # Deduplicate by title+url+check
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for c in candidates:
        key = (str(c.get("title")), str(c.get("url")), str(c.get("check")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    if not surface and not unique:
        notes.append(
            "no auth/oauth surface URLs found — pass --url or run Eye inventory first"
        )

    return {"candidates": unique, "notes": notes}
