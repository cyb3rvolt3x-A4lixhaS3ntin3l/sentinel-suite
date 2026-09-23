"""csrf_state pack v0 — fixture-driven CSRF / state-token candidates (defensive).

Evidence or it did not happen: cite concrete fixture signals (missing token
field, cookie flag string, unbound token marker) — not blind form POSTs.

Surfaces covered (fixture-first):
  - Missing CSRF token on state-changing POST/PUT/DELETE/PATCH candidates
  - Token not bound to session / reusable-token candidates
  - SameSite=None without Secure / weak cookie flag hints
  - Double-submit vs synchronizer-token pattern coach hints

Never auto-VERIFIED. No cross-site CSRF farms / form flood.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from gungnir.packs.csrf_state.caps import (
    COACH_CAPS,
    HARD_MAX_REQUESTS,
    RequestBudget,
    CsrfStateCapExceededError,
    host_of,
    is_lab_local_host,
    resolve_caps,
)
from gungnir.packs.csrf_state.hints import build_hint_record, hints_for_pattern
from gungnir.packs.manifest import finding_gate_checklist
from gungnir.packs.runner import PackRunError
from sentinel_core import Scope, ScopeDenied, assert_url_in_scope

_AUTO_STATUSES = frozenset({"needs_human", "unverified"})

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# Common CSRF field / header names observed in fixtures.
CSRF_FIELD_NAMES = frozenset(
    {
        "csrf",
        "csrf_token",
        "csrftoken",
        "csrfmiddlewaretoken",
        "_csrf",
        "_token",
        "authenticity_token",
        "xsrf",
        "xsrf_token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-requested-with",
        "__requestverificationtoken",
    }
)

COACH_CSRF = (
    "CSRF/state-token: evidence = concrete fixture signal "
    "(missing token field, unbound/reusable marker, or cookie flag string). "
    "Do NOT spray cross-site form POSTs. Fixture-driven only unless authorized lab mock."
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


def _method_of(row: dict[str, Any]) -> str:
    m = str(row.get("method") or row.get("http_method") or "POST").strip().upper()
    return m or "POST"


def _body_fields(row: dict[str, Any]) -> dict[str, Any]:
    body = row.get("body") or row.get("form") or row.get("fields") or {}
    if isinstance(body, dict):
        return body
    return {}


def _headers_of(row: dict[str, Any]) -> dict[str, Any]:
    headers = row.get("headers") or {}
    if isinstance(headers, dict):
        return {str(k).lower(): v for k, v in headers.items()}
    return {}


def _has_csrf_signal(row: dict[str, Any]) -> bool:
    """True when fixture body/headers already carry a CSRF token field/header."""
    fields = _body_fields(row)
    for key in fields:
        if str(key).strip().lower().replace("-", "_") in {
            n.replace("-", "_") for n in CSRF_FIELD_NAMES
        }:
            val = fields.get(key)
            if val is not None and str(val).strip() != "":
                return True
    headers = _headers_of(row)
    for name in CSRF_FIELD_NAMES:
        if name in headers and str(headers.get(name) or "").strip():
            return True
        # also check dash/underscore variants already normalized
        dashed = name.replace("_", "-")
        if dashed in headers and str(headers.get(dashed) or "").strip():
            return True
    # Explicit fixture markers
    if row.get("csrf_token") or row.get("token"):
        tok = row.get("csrf_token") or row.get("token")
        if str(tok).strip():
            return True
    if row.get("has_csrf_token") is True:
        return True
    return False


def _missing_token_explicit(row: dict[str, Any]) -> bool:
    """Fixture declares missing CSRF (honest signal, not spray inference alone)."""
    expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
    if expect.get("missing_csrf") is True or expect.get("missing_token") is True:
        return True
    if row.get("missing_csrf") is True or row.get("csrf_present") is False:
        return True
    if row.get("has_csrf_token") is False:
        return True
    # Empty token field named as CSRF is an explicit missing signal
    fields = _body_fields(row)
    for key, val in fields.items():
        kn = str(key).strip().lower().replace("-", "_")
        if kn in {n.replace("-", "_") for n in CSRF_FIELD_NAMES}:
            if val is None or str(val).strip() == "":
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
        "coach_hints": list(coach_hints or [COACH_CSRF]),
        "evidence_summary": evidence_summary,
        "evidence_stub": evidence_stub,
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=reproducible,
            impact=impact,
            evidence_attached=True,
        ),
    }


def _default_state_change_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-missing-csrf-post",
            "url": "http://127.0.0.1/account/email",
            "method": "POST",
            "body": {"email": "new@lab.example"},
            "csrf_present": False,
            "expect": {"missing_csrf": True},
        },
        {
            "name": "lab-missing-csrf-delete",
            "url": "http://127.0.0.1/api/widgets/1",
            "method": "DELETE",
            "headers": {},
            "body": {},
            "has_csrf_token": False,
            "expect": {"missing_token": True},
        },
    ]


def _default_cookie_flag_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-samesite-none-no-secure",
            "url": "http://127.0.0.1/",
            "set_cookie": "session=abc; Path=/; SameSite=None",
            "expect": {"samesite_none_without_secure": True},
        }
    ]


def _default_unbound_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-unbound-reusable-token",
            "url": "http://127.0.0.1/transfer",
            "method": "POST",
            "token": "STATIC_CSRF_TOKEN_DEMO",
            "session_bound": False,
            "reusable": True,
            "unbound_marker": "STATIC_CSRF_TOKEN_DEMO",
            "expect": {"unbound": True, "reusable": True},
        }
    ]


def _missing_csrf_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("state_changing")
        or fixtures.get("missing_csrf")
        or fixtures.get("forms")
        or []
    )
    if not rows and not fixtures:
        rows = _default_state_change_fixtures()
        notes.append("using built-in 127.0.0.1 missing-CSRF state-change fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        if not url:
            continue
        host = _resolve_host(ctx, url, notes, label="missing_csrf")
        if host is None:
            continue

        method = _method_of(row)
        if method not in STATE_CHANGING_METHODS:
            notes.append(
                f"skipped non-state-changing method={method} url={url} "
                "(CSRF pack focuses on POST/PUT/DELETE/PATCH)"
            )
            continue

        # Require an explicit missing-token signal — never invent from method alone
        if _has_csrf_signal(row) and not _missing_token_explicit(row):
            notes.append(
                f"state_changing has CSRF signal — not emitting missing-token "
                f"name={row.get('name') or url}"
            )
            continue
        if not _missing_token_explicit(row) and _has_csrf_signal(row) is False:
            # Method is state-changing AND no CSRF field present: still need
            # an explicit expect/missing flag to avoid blind spray inference.
            expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
            if not (
                expect.get("missing_csrf")
                or expect.get("missing_token")
                or row.get("csrf_present") is False
                or row.get("has_csrf_token") is False
                or row.get("missing_csrf") is True
            ):
                notes.append(
                    f"state_changing without explicit missing_csrf signal "
                    f"skipped (no spray) name={row.get('name') or url}"
                )
                continue

        check = "csrf_state_missing_token"
        verification = "needs_human"
        fields = _body_fields(row)
        stub = {
            "check": check,
            "request": {
                "method": method,
                "url": url,
                "body_keys": sorted(str(k) for k in fields.keys()),
                "csrf_field_present": _has_csrf_signal(row),
                "note": (
                    "Fixture-only missing-token candidate — not a live "
                    "cross-site form flood"
                ),
            },
            "response": {
                "observed": {
                    "state_changing_method": method,
                    "missing_csrf_signal": True,
                    "csrf_field_names_checked": sorted(CSRF_FIELD_NAMES),
                    "fixture_name": row.get("name"),
                },
                "evidence_signal": (
                    f"explicit missing_csrf/missing_token marker on "
                    f"{method} {url}; no non-empty CSRF field/header in fixture"
                ),
                "note": (
                    "Evidence = fixture signal (missing token field / flag). "
                    "Human must confirm Origin/Referer/custom-header defenses."
                ),
            },
        }
        out.append(
            _candidate(
                title=f"Missing CSRF token on state-changing {method}",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="csrf_missing_token_candidate",
                evidence_summary=(
                    f"{check}: method={method} missing_csrf_signal=True "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.45,
                reproducible=False,
                coach_hints=[COACH_CSRF] + hints_for_pattern("missing_token")[:3],
            )
        )
    return out


def _unbound_token_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("unbound_token")
        or fixtures.get("reusable_token")
        or fixtures.get("token_binding")
        or []
    )
    if not rows and not fixtures:
        rows = _default_unbound_fixtures()
        notes.append("using built-in 127.0.0.1 unbound/reusable token fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        if not url:
            continue
        host = _resolve_host(ctx, url, notes, label="unbound_token")
        if host is None:
            continue

        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
        unbound = bool(
            expect.get("unbound")
            or expect.get("reusable")
            or row.get("session_bound") is False
            or row.get("reusable") is True
            or row.get("unbound") is True
        )
        marker = (
            row.get("unbound_marker")
            or row.get("token")
            or row.get("csrf_token")
            or ""
        )
        marker_s = str(marker).strip()
        if not unbound:
            notes.append(
                f"unbound_token fixture lacks unbound/reusable signal "
                f"name={row.get('name') or url}"
            )
            continue
        if not marker_s:
            notes.append(
                f"unbound_token fixture missing token/unbound_marker "
                f"name={row.get('name') or url}"
            )
            continue

        check = "csrf_state_unbound_token"
        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": _method_of(row),
                "url": url,
                "token_stub": marker_s[:64],
                "session_bound": row.get("session_bound"),
                "reusable": row.get("reusable") or expect.get("reusable"),
                "note": "Fixture unbound/reusable token signal — not a live replay farm",
            },
            "response": {
                "observed": {
                    "unbound_marker": marker_s[:64],
                    "session_bound": row.get("session_bound"),
                    "reusable": bool(row.get("reusable") or expect.get("reusable")),
                    "fixture_name": row.get("name"),
                },
                "evidence_signal": (
                    f"unbound_marker={marker_s[:64]!r}; "
                    f"session_bound={row.get('session_bound')!r}; "
                    f"reusable={row.get('reusable') or expect.get('reusable')!r}"
                ),
                "note": (
                    "Evidence = fixture unbound/reusable marker. "
                    "Confirm cross-session rejection before VERIFIED."
                ),
            },
        }
        out.append(
            _candidate(
                title="CSRF token not bound to session / reusable candidate",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="csrf_unbound_token_candidate",
                evidence_summary=(
                    f"{check}: unbound_marker={marker_s[:32]!r} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.4,
                reproducible=False,
                coach_hints=[COACH_CSRF] + hints_for_pattern("unbound_token")[:3],
            )
        )
    return out


def _parse_set_cookie(raw: str) -> dict[str, Any]:
    """Parse a single Set-Cookie string into name/attrs (best-effort)."""
    parts = [p.strip() for p in (raw or "").split(";") if p.strip()]
    if not parts:
        return {}
    name_val = parts[0]
    name, _, value = name_val.partition("=")
    attrs: dict[str, Any] = {
        "name": name.strip(),
        "value": value.strip(),
        "raw": raw,
        "flags": {},
    }
    flags: dict[str, Any] = {}
    for part in parts[1:]:
        if "=" in part:
            k, _, v = part.partition("=")
            flags[k.strip().lower()] = v.strip()
        else:
            flags[part.strip().lower()] = True
    attrs["flags"] = flags
    return attrs


def _cookie_flag_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("cookie_flags")
        or fixtures.get("set_cookie")
        or fixtures.get("cookies")
        or []
    )
    if not rows and not fixtures:
        rows = _default_cookie_flag_fixtures()
        notes.append("using built-in 127.0.0.1 SameSite cookie-flag fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "http://127.0.0.1/")
        host = _resolve_host(ctx, url, notes, label="cookie_flags")
        if host is None:
            continue

        raw = str(
            row.get("set_cookie")
            or row.get("cookie")
            or row.get("header")
            or ""
        )
        if not raw and isinstance(row.get("flags"), dict):
            # Synthetic: build a raw-ish string from flags for evidence
            name = str(row.get("name") or "session")
            parts = [f"{name}=lab"]
            for fk, fv in row["flags"].items():
                if fv is True:
                    parts.append(str(fk))
                elif fv is False or fv is None:
                    continue
                else:
                    parts.append(f"{fk}={fv}")
            raw = "; ".join(parts)

        if not raw:
            notes.append(f"cookie_flags fixture missing set_cookie string name={row.get('name')}")
            continue

        parsed = _parse_set_cookie(raw)
        flags = parsed.get("flags") or {}
        # Also merge explicit flags from fixture
        if isinstance(row.get("flags"), dict):
            for fk, fv in row["flags"].items():
                flags[str(fk).lower()] = fv

        samesite = str(flags.get("samesite") or "").strip().lower()
        secure = bool(flags.get("secure"))
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}

        none_without_secure = (samesite == "none" and not secure) or bool(
            expect.get("samesite_none_without_secure")
        )
        # Weak / missing SameSite hint (not auto-finding alone unless flagged)
        weak_samesite = bool(
            expect.get("weak_samesite")
            or (samesite == "" and expect.get("missing_samesite"))
        )

        if not none_without_secure and not weak_samesite:
            # Only emit when we have a concrete weak-flag signal
            if samesite == "none" and secure:
                notes.append(
                    f"cookie SameSite=None with Secure — ok signal name={row.get('name')}"
                )
            else:
                notes.append(
                    f"cookie_flags no weak-flag signal name={row.get('name') or url}"
                )
            continue

        check = (
            "csrf_state_samesite_none_without_secure"
            if none_without_secure
            else "csrf_state_weak_cookie_flags"
        )
        verification = "needs_human" if none_without_secure else "unverified"
        impact = (
            "csrf_samesite_none_without_secure_candidate"
            if none_without_secure
            else "csrf_weak_cookie_flag_candidate"
        )
        stub = {
            "check": check,
            "request": {
                "method": "GET",
                "url": url,
                "note": "Fixture Set-Cookie flag analysis — no live cookie spray",
            },
            "response": {
                "set_cookie": raw[:320],
                "observed": {
                    "cookie_name": parsed.get("name"),
                    "samesite": samesite or None,
                    "secure": secure,
                    "samesite_none_without_secure": none_without_secure,
                    "fixture_name": row.get("name"),
                },
                "evidence_signal": (
                    f"Set-Cookie flag string shows SameSite={samesite or '(missing)'} "
                    f"Secure={secure}"
                ),
                "note": (
                    "Evidence = cookie flag string from fixture. "
                    "Confirm cookie role (session vs CSRF) before VERIFIED."
                ),
            },
        }
        title = (
            "SameSite=None without Secure on cookie"
            if none_without_secure
            else "Weak / missing SameSite cookie flag hint"
        )
        out.append(
            _candidate(
                title=title,
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact=impact,
                evidence_summary=(
                    f"{check}: SameSite={samesite or '(missing)'} Secure={secure} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.5 if none_without_secure else 0.3,
                reproducible=False,
                coach_hints=[COACH_CSRF] + hints_for_pattern("samesite_cookie")[:3],
            )
        )
    return out


def _pattern_coach_hints(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    """Double-submit vs synchronizer-token pattern notes (hints only)."""
    hints: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(
        fixtures.get("csrf_patterns")
        or fixtures.get("patterns")
        or fixtures.get("anti_csrf_patterns")
        or []
    )

    if not rows:
        # Always emit baseline coach hints (business_logic style)
        for kind in ("synchronizer_token", "double_submit_cookie"):
            hints.append(build_hint_record(pattern_kind=kind))
        notes.append(
            "csrf pattern coach: synchronizer_token + double_submit_cookie hints only "
            "(not auto-confirmed)"
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
            kind = "generic_csrf"
        url = str(row.get("url") or row.get("endpoint") or "") or None
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        extra = []
        if row.get("note"):
            extra.append(str(row.get("note")))
        if "cookie_name" in row:
            extra.append(f"Fixture cookie_name={row.get('cookie_name')!r}.")
        if "form_field" in row:
            extra.append(f"Fixture form_field={row.get('form_field')!r}.")
        hints.append(
            build_hint_record(
                pattern_kind=kind,
                host=host,
                url=url,
                extra=extra or None,
            )
        )
    notes.append(f"csrf pattern coach hints from fixtures: {len(hints)}")
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
        f"(hard_max={HARD_MAX_REQUESTS}); no CSRF farm / form flood"
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
                opener({"probe": "csrf_state_typename"})
            except Exception as exc:  # noqa: BLE001
                notes.append(f"live mock opener soft-fail: {exc}")
        caps_dict["requests_used"] = budget.used


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """Run csrf_state pack v0 checks (fixture-first, evidence-backed, scope-gated)."""
    notes: list[str] = [
        "csrf_state v0: fixture-driven missing-token / unbound / cookie-flag candidates",
        COACH_CSRF,
        "findings default needs_human|unverified; never auto-VERIFIED/confirmed",
        "evidence must cite concrete fixture signals — no blind form POSTs",
        "no cross-site CSRF farms / browser automation / form flood",
        f"live-mock hard cap requests≤{HARD_MAX_REQUESTS}",
    ]

    try:
        caps = resolve_caps(
            max_requests=ctx.get("max_requests"),
            i_understand_lab=bool(ctx.get("i_understand_lab")),
        )
    except CsrfStateCapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    caps_dict = caps.to_dict()
    _maybe_live_mock(ctx, caps_dict, notes)

    candidates: list[dict[str, Any]] = []
    candidates.extend(_missing_csrf_candidates(ctx, notes))
    candidates.extend(_unbound_token_candidates(ctx, notes))
    candidates.extend(_cookie_flag_candidates(ctx, notes))
    hints = _pattern_coach_hints(ctx, notes)

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
            "no CSRF/state-token candidates — provide fixtures.state_changing / "
            "unbound_token / cookie_flags under lab fixtures "
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
    }


__all__ = [
    "run_checks",
    "COACH_CSRF",
    "STATE_CHANGING_METHODS",
    "CSRF_FIELD_NAMES",
]
