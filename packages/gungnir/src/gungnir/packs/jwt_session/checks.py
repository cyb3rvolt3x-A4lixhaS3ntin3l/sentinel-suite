"""jwt_session pack v0 — fixture-driven session fixation + JWT handling evidence.

Evidence or it did not happen: cite concrete fixture signals
(same session cookie before+after login; decoded JWT header alg/kid/exp from
fixture strings; token appearing in query/fragment in fixture URL) —
never invent live tokens or spray IdPs.

Surfaces covered (fixture-first):
  - Session ID not rotated after login (fixation)
  - JWT alg=none / weak alg / missing exp / kid confusion (fixture tokens only)
  - Token in query/fragment leakage

Cannot: live IdP hammering / token exfil modules / mint attack payloads for
unauthorized use / forge sessions against live targets. Staging/lab first.
Never auto-VERIFIED. Not a live token-theft toolkit.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from gungnir.packs.jwt_session.caps import (
    COACH_CAPS,
    HARD_MAX_REQUESTS,
    RequestBudget,
    JwtSessionCapExceededError,
    host_of,
    is_lab_local_host,
    resolve_caps,
)
from gungnir.packs.jwt_session.hints import build_hint_record, hints_for_pattern
from gungnir.packs.manifest import finding_gate_checklist
from gungnir.packs.runner import PackRunError
from sentinel_core import Scope, ScopeDenied, assert_url_in_scope

_AUTO_STATUSES = frozenset({"needs_human", "unverified"})

# Symmetric algs often abused when verifier expects asymmetric.
_WEAK_SYMMETRIC = frozenset({"HS256", "HS384", "HS512", "HS1"})
_ASYMMETRIC = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    }
)

# kid shapes that suggest confusion / traversal (fixture-string heuristics only).
_KID_CONFUSION_RE = re.compile(
    r"(?:\.\./|\.\.\\|file:|https?://|/etc/|\\\\|/keys/|hmac\.pem|private\.pem)",
    re.IGNORECASE,
)

_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)

COACH_JWT_SESSION = (
    "jwt_session: evidence = fixture signals "
    "(same session cookie before+after login; decoded JWT alg/kid/exp; "
    "token in query/fragment). Analyze fixture tokens only — do not mint "
    "attack payloads. Staging/lab first — Cannot: live IdP hammering + token exfil. "
    "Fixture-driven only unless authorized lab mock."
)

CANNOT_LIVE_IDP_EXFIL = (
    "Cannot: live IdP hammering / credential stuffing / session-hijack "
    "runbooks against real IdPs / token exfiltration modules / mint attack "
    "payloads for unauthorized use / forge live sessions. "
    "Staging/lab fixture evidence only — not a live token-theft toolkit."
)

# Built-in lab fixture token strings (unsigned / demo signatures — not live secrets).
_LAB_ALG_NONE = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJzdWIiOiJsYWItdXNlciIsImlhdCI6MX0."
)
_LAB_NO_EXP = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJsYWItdXNlciIsImlhdCI6MX0."
    "lab-sig"
)
_LAB_KID = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uL2tleXMvaG1hYy5wZW0ifQ."
    "eyJzdWIiOiJsYWItdXNlciIsImV4cCI6OTk5OTk5OTk5OX0."
    "lab-sig"
)
_LAB_WEAK = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJsYWItdXNlciIsImV4cCI6OTk5OTk5OTk5OX0."
    "lab-sig"
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
        "coach_hints": list(coach_hints or [COACH_JWT_SESSION]),
        "evidence_summary": evidence_summary,
        "evidence_stub": evidence_stub,
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=reproducible,
            impact=impact,
            evidence_attached=True,
        ),
    }


def _b64url_json(segment: str) -> dict[str, Any] | None:
    """Decode one JWT base64url segment to a dict; None on failure."""
    raw = (segment or "").strip()
    if not raw:
        return None
    pad = "=" * ((4 - len(raw) % 4) % 4)
    try:
        data = base64.urlsafe_b64decode(raw + pad)
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def _decode_jwt_fixture(token: str) -> dict[str, Any] | None:
    """
    Decode header (+ payload when present) from a fixture JWT string.
    Never verifies signatures; never mints tokens; analysis only.
    """
    tok = (token or "").strip()
    if not tok or tok.count(".") < 2:
        return None
    parts = tok.split(".")
    header = _b64url_json(parts[0])
    if header is None:
        return None
    payload = _b64url_json(parts[1]) if len(parts) > 1 else None
    return {
        "header": header,
        "payload": payload if isinstance(payload, dict) else {},
        "alg": str(header.get("alg") or "").strip(),
        "kid": header.get("kid"),
        "typ": header.get("typ"),
        "has_exp": isinstance(payload, dict) and "exp" in payload,
        "exp": (payload or {}).get("exp") if isinstance(payload, dict) else None,
        "token_stub": tok[:80] + ("…" if len(tok) > 80 else ""),
        "parts": len(parts),
    }


def _extract_token(row: dict[str, Any]) -> str | None:
    """Pull a fixture JWT string from common fields (never invent one)."""
    for key in ("token", "jwt", "access_token", "id_token", "bearer", "fixture_token"):
        val = row.get(key)
        if isinstance(val, str) and val.count(".") >= 2:
            return val.strip()
    headers = row.get("request_headers") or row.get("headers") or {}
    if isinstance(headers, dict):
        for hk, hv in headers.items():
            if str(hk).lower() == "authorization" and isinstance(hv, str):
                m = re.match(r"(?i)bearer\s+(\S+)", hv.strip())
                if m and m.group(1).count(".") >= 2:
                    return m.group(1)
    # URL-embedded
    url = str(row.get("url") or row.get("endpoint") or "")
    if url:
        found = _token_in_url(url)
        if found:
            return found["token"]
    return None


def _token_in_url(url: str) -> dict[str, Any] | None:
    """Locate a JWT-shaped token in query or fragment of a fixture URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    # Query params
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for key in (
        "access_token",
        "id_token",
        "token",
        "jwt",
        "auth",
        "bearer",
        "session_token",
    ):
        vals = qs.get(key) or []
        for v in vals:
            if isinstance(v, str) and v.count(".") >= 2 and v.startswith("eyJ"):
                return {
                    "token": v,
                    "location": "query",
                    "param": key,
                    "url_stub": url[:200],
                }
    # Any JWT-shaped value in query
    for key, vals in qs.items():
        for v in vals:
            if isinstance(v, str) and _JWT_RE.search(v):
                m = _JWT_RE.search(v)
                return {
                    "token": m.group(0) if m else v,
                    "location": "query",
                    "param": key,
                    "url_stub": url[:200],
                }
    # Fragment
    frag = parsed.fragment or ""
    if frag:
        frag_qs = parse_qs(frag, keep_blank_values=True)
        for key, vals in frag_qs.items():
            for v in vals:
                if isinstance(v, str) and v.count(".") >= 2 and ("eyJ" in v):
                    m = _JWT_RE.search(v) or type("M", (), {"group": lambda *_: v})()
                    return {
                        "token": m.group(0) if hasattr(m, "group") else v,
                        "location": "fragment",
                        "param": key,
                        "url_stub": url[:200],
                    }
        m = _JWT_RE.search(frag)
        if m:
            return {
                "token": m.group(0),
                "location": "fragment",
                "param": None,
                "url_stub": url[:200],
            }
    return None


def _session_cookie_value(cookies: Any, *, names: tuple[str, ...] | None = None) -> tuple[str | None, str | None]:
    """Return (cookie_name, value) for a session-ish cookie from a fixture map."""
    if not isinstance(cookies, dict):
        return None, None
    preferred = names or (
        "session",
        "sessionid",
        "session_id",
        "sid",
        "jsessionid",
        "phpsessid",
        "connect.sid",
        "auth_session",
    )
    lower_map = {str(k).lower(): (str(k), str(v)) for k, v in cookies.items() if v is not None}
    for name in preferred:
        if name in lower_map:
            return lower_map[name]
    # Fall back to first cookie if only one present
    if len(lower_map) == 1:
        return next(iter(lower_map.values()))
    return None, None


def _has_fixation_evidence(row: dict[str, Any]) -> dict[str, Any] | None:
    """
    Require concrete evidence: same session cookie value before and after login.
    """
    expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
    pre = row.get("pre_login") or row.get("before_login") or row.get("pre_auth") or {}
    post = row.get("post_login") or row.get("after_login") or row.get("post_auth") or {}
    if not isinstance(pre, dict):
        pre = {}
    if not isinstance(post, dict):
        post = {}

    pre_cookies = pre.get("cookies") or row.get("pre_cookies") or row.get("session_before")
    post_cookies = post.get("cookies") or row.get("post_cookies") or row.get("session_after")

    # Flat cookie fields
    if pre_cookies is None and row.get("pre_session") is not None:
        pre_cookies = {"session": row.get("pre_session")}
    if post_cookies is None and row.get("post_session") is not None:
        post_cookies = {"session": row.get("post_session")}

    # Also accept set-cookie echoes
    if pre_cookies is None and isinstance(pre.get("set_cookie"), str):
        pre_cookies = {"session": pre["set_cookie"].split(";", 1)[0].split("=", 1)[-1]}
    if post_cookies is None and isinstance(post.get("set_cookie"), str):
        post_cookies = {"session": post["set_cookie"].split(";", 1)[0].split("=", 1)[-1]}

    pre_name, pre_val = _session_cookie_value(pre_cookies)
    post_name, post_val = _session_cookie_value(post_cookies)

    if not pre_val or not post_val:
        return None

    same = pre_val == post_val
    rotated = bool(expect.get("rotated") or row.get("rotated"))
    fixation_flag = bool(
        expect.get("fixation")
        or expect.get("session_fixation")
        or expect.get("not_rotated")
        or row.get("fixation")
    )

    if not same and not fixation_flag:
        return None
    if same is False and fixation_flag and not expect.get("same_cookie"):
        # Fixture claims fixation but cookies differ — insufficient evidence
        return None
    if not same:
        return None
    if rotated and same:
        # Explicitly marked rotated but values match — still a candidate
        pass

    return {
        "cookie_name": post_name or pre_name or "session",
        "pre_value_stub": pre_val[:64],
        "post_value_stub": post_val[:64],
        "same_cookie": True,
        "fixture_name": row.get("name"),
        "diff_summary": (
            f"session cookie {post_name or pre_name or 'session'!r} "
            f"pre_login={pre_val[:48]!r} == post_login={post_val[:48]!r} (not rotated)"
        ),
    }


def _jwt_issue_kind(decoded: dict[str, Any], row: dict[str, Any]) -> str | None:
    """
    Classify a fixture-decoded JWT into an issue kind, or None if clean.
    Never mints tokens; only reads decoded fixture fields + expect flags.
    """
    expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
    alg = (decoded.get("alg") or "").strip()
    alg_u = alg.upper()
    kid = decoded.get("kid")

    if alg_u == "NONE" or alg == "none" or expect.get("alg_none"):
        if alg_u == "NONE" or alg == "none" or str(alg).lower() == "none":
            return "jwt_alg_none"

    expected_alg = str(
        expect.get("expected_alg")
        or row.get("expected_alg")
        or expect.get("expect_alg")
        or ""
    ).strip().upper()
    if expected_alg in _ASYMMETRIC and alg_u in _WEAK_SYMMETRIC:
        return "jwt_weak_alg"
    if expect.get("weak_alg") and alg_u in _WEAK_SYMMETRIC:
        return "jwt_weak_alg"

    if not decoded.get("has_exp") or expect.get("missing_exp"):
        # Only emit missing-exp when payload decoded and exp absent (or expect says so)
        if not decoded.get("has_exp"):
            return "jwt_missing_exp"

    kid_s = str(kid) if kid is not None else ""
    if kid_s and (_KID_CONFUSION_RE.search(kid_s) or expect.get("kid_confusion")):
        return "jwt_kid_confusion"

    return None


def _default_fixation_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-session-not-rotated",
            "url": "http://127.0.0.1/login",
            "pre_login": {"cookies": {"session": "FIXATED-SESSION-ID-LAB"}},
            "post_login": {
                "cookies": {"session": "FIXATED-SESSION-ID-LAB"},
                "status": 200,
                "body": "welcome",
            },
            "expect": {"fixation": True, "not_rotated": True},
        }
    ]


def _default_jwt_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-jwt-alg-none",
            "url": "http://127.0.0.1/api/me",
            "token": _LAB_ALG_NONE,
            "expect": {"alg_none": True},
        },
        {
            "name": "lab-jwt-missing-exp",
            "url": "http://127.0.0.1/api/me",
            "token": _LAB_NO_EXP,
            "expect": {"missing_exp": True},
        },
        {
            "name": "lab-jwt-kid-confusion",
            "url": "http://127.0.0.1/api/me",
            "token": _LAB_KID,
            "expect": {"kid_confusion": True},
        },
        {
            "name": "lab-jwt-weak-alg",
            "url": "http://127.0.0.1/api/me",
            "token": _LAB_WEAK,
            "expected_alg": "RS256",
            "expect": {"weak_alg": True, "expected_alg": "RS256"},
        },
    ]


def _default_query_leak_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-token-in-query",
            "url": (
                "http://127.0.0.1/callback?access_token="
                + _LAB_NO_EXP
                + "&token_type=bearer"
            ),
            "expect": {"token_in_query": True},
        }
    ]


def _fixation_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("session_fixation")
        or fixtures.get("fixation")
        or fixtures.get("session_rotate")
        or []
    )
    if not rows and not fixtures:
        rows = _default_fixation_fixtures()
        notes.append("using built-in 127.0.0.1 session-fixation fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "http://127.0.0.1/login")
        host = _resolve_host(ctx, url, notes, label="session_fixation")
        if host is None:
            continue

        evidence = _has_fixation_evidence(row)
        if evidence is None:
            notes.append(
                f"session_fixation skipped — need same session cookie "
                f"before+after login name={row.get('name') or url}"
            )
            continue

        check = "jwt_session_fixation"
        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": str(row.get("method") or "POST").upper(),
                "url": url,
                "cookie_name": evidence["cookie_name"],
                "note": (
                    "Fixture session-fixation candidate — not a live "
                    "session-hijack runbook / IdP hammer"
                ),
            },
            "response": {
                "observed": {
                    "pre_value_stub": evidence["pre_value_stub"],
                    "post_value_stub": evidence["post_value_stub"],
                    "same_cookie": True,
                    "fixture_name": evidence.get("fixture_name"),
                },
                "evidence_signal": evidence["diff_summary"],
                "note": (
                    "Evidence = fixture pre-login cookie == post-login cookie. "
                    "Confirm rotation policy before VERIFIED. "
                    + CANNOT_LIVE_IDP_EXFIL
                ),
            },
        }
        out.append(
            _candidate(
                title="Session ID not rotated after login (fixation candidate)",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="jwt_session_fixation_candidate",
                evidence_summary=(
                    f"{check}: cookie={evidence['cookie_name']!r} "
                    f"pre==post (verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.5,
                reproducible=False,
                coach_hints=[COACH_JWT_SESSION] + hints_for_pattern("session_fixation")[:3],
            )
        )
    return out


_CHECK_BY_KIND = {
    "jwt_alg_none": ("jwt_session_alg_none", "JWT alg=none accepted (fixture-decoded)"),
    "jwt_weak_alg": ("jwt_session_weak_alg", "JWT weak/symmetric alg vs expected asymmetric"),
    "jwt_missing_exp": ("jwt_session_missing_exp", "JWT missing exp claim (fixture-decoded)"),
    "jwt_kid_confusion": ("jwt_session_kid_confusion", "JWT kid confusion candidate (fixture kid)"),
}


def _jwt_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("jwt")
        or fixtures.get("jwt_tokens")
        or fixtures.get("tokens")
        or fixtures.get("weak_jwt")
        or []
    )
    if not rows and not fixtures:
        rows = _default_jwt_fixtures()
        notes.append("using built-in 127.0.0.1 JWT fixture tokens (analyze only)")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "http://127.0.0.1/api/me")
        host = _resolve_host(ctx, url, notes, label="jwt")
        if host is None:
            continue

        token = _extract_token(row)
        if not token:
            notes.append(
                f"jwt skipped — no fixture token string "
                f"name={row.get('name') or url}"
            )
            continue

        decoded = _decode_jwt_fixture(token)
        if decoded is None:
            notes.append(
                f"jwt skipped — could not decode fixture token header "
                f"name={row.get('name') or url}"
            )
            continue

        kind = _jwt_issue_kind(decoded, row)
        if kind is None:
            notes.append(
                f"jwt skipped — no alg/none/weak/exp/kid evidence in fixture "
                f"name={row.get('name') or url} alg={decoded.get('alg')!r}"
            )
            continue

        check, title = _CHECK_BY_KIND[kind]
        verification = "needs_human"
        kid_stub = decoded.get("kid")
        if isinstance(kid_stub, str) and len(kid_stub) > 80:
            kid_stub = kid_stub[:80] + "…"
        stub = {
            "check": check,
            "request": {
                "method": str(row.get("method") or "GET").upper(),
                "url": url,
                "token_stub": decoded["token_stub"],
                "note": (
                    "Fixture JWT analysis only — do not mint attack payloads; "
                    "not live IdP hammering / token exfil"
                ),
            },
            "response": {
                "observed": {
                    "alg": decoded.get("alg"),
                    "kid": kid_stub,
                    "has_exp": decoded.get("has_exp"),
                    "exp": decoded.get("exp"),
                    "typ": decoded.get("typ"),
                    "fixture_name": row.get("name"),
                    "expected_alg": (row.get("expect") or {}).get("expected_alg")
                    or row.get("expected_alg"),
                },
                "evidence_signal": (
                    f"decoded fixture JWT header alg={decoded.get('alg')!r} "
                    f"kid={kid_stub!r} has_exp={decoded.get('has_exp')} "
                    f"issue={kind}"
                ),
                "note": (
                    "Evidence = decoded fixture JWT header/payload fields. "
                    "Never auto-VERIFIED. " + CANNOT_LIVE_IDP_EXFIL
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
                    f"{check}: alg={decoded.get('alg')!r} "
                    f"has_exp={decoded.get('has_exp')} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.5,
                reproducible=False,
                coach_hints=[COACH_JWT_SESSION] + hints_for_pattern(kind)[:3],
            )
        )
    return out


def _query_leak_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("token_query")
        or fixtures.get("token_leak")
        or fixtures.get("query_fragment")
        or fixtures.get("token_in_url")
        or []
    )
    if not rows and not fixtures:
        rows = _default_query_leak_fixtures()
        notes.append("using built-in 127.0.0.1 token-in-query fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        if not url:
            continue
        host = _resolve_host(ctx, url, notes, label="token_query")
        if host is None:
            continue

        found = _token_in_url(url)
        # Also allow explicit fields
        if found is None and row.get("token") and row.get("location") in {"query", "fragment"}:
            found = {
                "token": str(row.get("token")),
                "location": str(row.get("location")),
                "param": row.get("param"),
                "url_stub": url[:200],
            }
        if found is None:
            notes.append(
                f"token_query skipped — no JWT in fixture query/fragment "
                f"name={row.get('name') or url}"
            )
            continue

        # Decode for richer evidence when possible (still fixture-only)
        decoded = _decode_jwt_fixture(found["token"])
        check = "jwt_session_token_query"
        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": str(row.get("method") or "GET").upper(),
                "url": url[:240],
                "location": found["location"],
                "param": found.get("param"),
                "note": (
                    "Fixture token-in-query/fragment candidate — "
                    "not a live token-exfil module"
                ),
            },
            "response": {
                "observed": {
                    "location": found["location"],
                    "param": found.get("param"),
                    "token_stub": (found["token"][:64] + "…")
                    if len(found["token"]) > 64
                    else found["token"],
                    "alg": (decoded or {}).get("alg"),
                    "fixture_name": row.get("name"),
                },
                "evidence_signal": (
                    f"fixture URL carries JWT in {found['location']}"
                    + (f" param={found.get('param')!r}" if found.get("param") else "")
                    + (
                        f"; decoded alg={(decoded or {}).get('alg')!r}"
                        if decoded
                        else ""
                    )
                ),
                "note": (
                    "Evidence = token appearing in fixture URL query/fragment. "
                    "Prefer cookies over query. " + CANNOT_LIVE_IDP_EXFIL
                ),
            },
        }
        out.append(
            _candidate(
                title="JWT / token leaked via query or fragment (fixture)",
                host=host,
                url=url[:240],
                check=check,
                verification=verification,
                impact="jwt_session_token_query_candidate",
                evidence_summary=(
                    f"{check}: location={found['location']} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.5,
                reproducible=False,
                coach_hints=[COACH_JWT_SESSION] + hints_for_pattern("token_query_leak")[:3],
            )
        )
    return out


def _coach_hints(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    """Optional coach hints (hints only — not auto-confirm)."""
    hints: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("patterns")
        or fixtures.get("coach")
        or fixtures.get("hints")
        or []
    )

    if not rows:
        for kind in (
            "session_fixation",
            "jwt_alg_none",
            "token_query_leak",
            "generic_jwt_session",
        ):
            hints.append(build_hint_record(pattern_kind=kind))
        notes.append(
            "jwt_session coach: rotate session on auth; reject alg=none; "
            "put tokens in cookies not query (hints only, not auto-confirmed); "
            + CANNOT_LIVE_IDP_EXFIL
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
            kind = "generic_jwt_session"
        if kind in {"fixation", "session"}:
            kind = "session_fixation"
        if kind in {"alg_none", "none"}:
            kind = "jwt_alg_none"
        if kind in {"query", "fragment", "leak"}:
            kind = "token_query_leak"
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
    notes.append(f"jwt_session coach hints from fixtures: {len(hints)}")
    return hints


def _maybe_live_mock(
    ctx: dict[str, Any], caps_dict: dict[str, Any], notes: list[str]
) -> None:
    """If opener/live_mock present, enforce hard request caps (no IdP hammer)."""
    opener = ctx.get("opener")
    live_mock = (ctx.get("fixtures") or {}).get("live_mock")
    if opener is None and not live_mock:
        return

    budget = RequestBudget(max_requests=int(caps_dict["max_requests"]))
    notes.append(
        f"live mock path active — hard cap requests≤{caps_dict['max_requests']} "
        f"(hard_max={HARD_MAX_REQUESTS}); no live IdP hammering / token exfil"
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
                opener({"probe": "jwt_session_basename"})
            except Exception as exc:  # noqa: BLE001
                notes.append(f"live mock opener soft-fail: {exc}")
        caps_dict["requests_used"] = budget.used


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """Run jwt_session pack v0 checks (fixture-first, evidence-backed, scope-gated)."""
    notes: list[str] = [
        "jwt_session v0: fixture-driven session fixation + JWT handling + query leak",
        COACH_JWT_SESSION,
        CANNOT_LIVE_IDP_EXFIL,
        "findings default needs_human|unverified; never auto-VERIFIED/confirmed",
        "analyze fixture tokens only — do not mint attack payloads",
        f"live-mock hard cap requests≤{HARD_MAX_REQUESTS}",
        "ato_oauth_oidc pack stays as-is (OAuth/OIDC); this pack is session+JWT crypto/handling",
    ]

    try:
        caps = resolve_caps(
            max_requests=ctx.get("max_requests"),
            i_understand_lab=bool(ctx.get("i_understand_lab")),
        )
    except JwtSessionCapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    caps_dict = caps.to_dict()
    _maybe_live_mock(ctx, caps_dict, notes)

    candidates: list[dict[str, Any]] = []
    candidates.extend(_fixation_candidates(ctx, notes))
    candidates.extend(_jwt_candidates(ctx, notes))
    candidates.extend(_query_leak_candidates(ctx, notes))
    hints = _coach_hints(ctx, notes)

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
            "no jwt_session candidates — provide fixtures session_fixation / "
            "jwt / token_query under lab fixtures "
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
        "cannot": [CANNOT_LIVE_IDP_EXFIL],
    }


__all__ = [
    "run_checks",
    "COACH_JWT_SESSION",
    "CANNOT_LIVE_IDP_EXFIL",
    "_decode_jwt_fixture",
]
