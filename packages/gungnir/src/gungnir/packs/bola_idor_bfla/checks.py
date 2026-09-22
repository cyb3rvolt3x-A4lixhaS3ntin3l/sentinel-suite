"""BOLA/IDOR/BFLA v0 checks — dual-role fixture candidates + evidence stubs.

Defensive only: no live multi-tenant abuse, no data destruction, no exploit PoCs.
Tests inject fixtures (mocked HTTP responses). Evidence request/response come
from fixtures only.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from gungnir.packs.manifest import finding_gate_checklist
from sentinel_core import Scope, ScopeDenied, assert_url_in_scope

_SUCCESS_STATUSES = frozenset(range(200, 300))
_DENY_STATUSES = frozenset({401, 403, 404, 405, 501})


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


def _status_ok(status: Any) -> bool:
    try:
        return int(status) in _SUCCESS_STATUSES
    except (TypeError, ValueError):
        return False


def _status_denied(status: Any) -> bool:
    try:
        return int(status) in _DENY_STATUSES
    except (TypeError, ValueError):
        return False


def _body_text(resp: dict[str, Any] | None) -> str:
    if not isinstance(resp, dict):
        return ""
    return str(resp.get("body") or "")


def _norm_body(text: str) -> str:
    return " ".join(text.split())


def _roles_present(ctx: dict[str, Any]) -> bool:
    roles = ctx.get("roles") or {}
    return "a" in roles and "b" in roles


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
) -> dict[str, Any]:
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
        "evidence_summary": evidence_summary,
        "evidence_stub": evidence_stub,
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=reproducible,
            impact=impact,
            evidence_attached=True,
        ),
    }


def _horizontal_idor_candidates(ctx: dict[str, Any]) -> list[dict]:
    """
    Horizontal IDOR / BOLA: Role A reads Role B's object (fixture).

    Fixture row keys (lab)::

        {
          "url": "https://lab.example/api/objects/obj-b",
          "object_id_a": "obj-a",
          "object_id_b": "obj-b",
          "role_a_on_b": {"method": "GET", "status": 200, "body": "...B data..."},
          "role_b_on_b": {"method": "GET", "status": 200, "body": "...B data..."},
          "role_a_on_a": {"method": "GET", "status": 200, "body": "...A data..."},
          "expect": {"idor": true}   # optional — forces confirmed when pattern holds
        }

    Confirmed when A-on-B succeeds and body matches B-on-B (or expect.idor),
    and preferably differs from A-on-A. Unverified soft candidate when A-on-B
    succeeds without a B baseline.
    """
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))

    for row in fixtures.get("horizontal_idor") or []:
        url = str(
            row.get("url")
            or row.get("url_b")
            or row.get("object_url_b")
            or ""
        )
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        if not url or host is None:
            continue

        a_on_b = row.get("role_a_on_b") or row.get("role_a_response") or {}
        b_on_b = row.get("role_b_on_b") or row.get("role_b_response") or {}
        a_on_a = row.get("role_a_on_a") or row.get("role_a_own_response") or {}
        if not isinstance(a_on_b, dict) or not a_on_b:
            continue

        method = str(a_on_b.get("method") or row.get("method") or "GET").upper()
        a_status = a_on_b.get("status")
        a_body = _norm_body(_body_text(a_on_b))
        b_body = _norm_body(_body_text(b_on_b)) if isinstance(b_on_b, dict) else ""
        own_body = _norm_body(_body_text(a_on_a)) if isinstance(a_on_a, dict) else ""

        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
        issues: list[tuple[str, str]] = []

        if not _status_ok(a_status):
            # A was denied — no IDOR candidate (honest negative)
            continue

        cross_match = bool(b_body) and a_body == b_body and a_body != ""
        differs_from_own = bool(own_body) and a_body != own_body
        expect_idor = bool(expect.get("idor") or expect.get("horizontal_idor"))

        if cross_match or (expect_idor and _status_ok(a_status)):
            verification = "confirmed"
            check = "horizontal_idor_confirmed"
            confidence = 0.75
            issues.append((check, verification))
        elif _status_ok(a_status) and (differs_from_own or not b_body):
            # Soft: A got 2xx on B's object without full baseline proof
            verification = "unverified"
            check = "horizontal_idor_candidate"
            confidence = 0.4
            issues.append((check, verification))
        else:
            continue

        for check, verification in issues:
            stub = {
                "check": check,
                "request": {
                    "method": method,
                    "url": url,
                    "role": "a",
                    "object_id_b": row.get("object_id_b"),
                    "object_id_a": row.get("object_id_a"),
                },
                "response": {
                    "role_a_on_b_status": a_status,
                    "role_b_on_b_status": b_on_b.get("status")
                    if isinstance(b_on_b, dict)
                    else None,
                    "bodies_match_b_baseline": cross_match,
                    "differs_from_a_own": differs_from_own,
                    "note": (
                        "Fixture-only dual-role compare — no live multi-tenant abuse"
                    ),
                    "body_stub_a_on_b": a_body[:240] if a_body else None,
                },
            }
            out.append(
                _candidate(
                    title="Horizontal IDOR/BOLA candidate (A reads B object)",
                    host=host,
                    url=url,
                    check=check,
                    verification=verification,
                    impact="broken_object_level_authorization_candidate",
                    evidence_summary=(
                        f"{check}: Role A session on object B returned "
                        f"status={a_status} (verification={verification})"
                    ),
                    evidence_stub=stub,
                    confidence=confidence,
                    reproducible=verification == "confirmed",
                )
            )
    return out


def _vertical_bfla_candidates(ctx: dict[str, Any]) -> list[dict]:
    """
    Vertical privilege / BFLA: low-priv Role A hits admin-ish path.

    Fixture row::

        {
          "url": "https://lab.example/admin/users",
          "role_a": {"method": "GET", "status": 200, "body": "..."},
          "role_b_admin": {"method": "GET", "status": 200, "body": "..."},
          "expect": {"bfla": true}
        }
    """
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))

    for row in fixtures.get("vertical_bfla") or fixtures.get("bfla") or []:
        url = str(row.get("url") or row.get("admin_url") or "")
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        if not url or host is None:
            continue

        role_a = row.get("role_a") or row.get("role_a_response") or {}
        role_b = (
            row.get("role_b_admin")
            or row.get("role_b")
            or row.get("admin_response")
            or {}
        )
        if not isinstance(role_a, dict) or not role_a:
            continue

        method = str(role_a.get("method") or row.get("method") or "GET").upper()
        a_status = role_a.get("status")
        a_body = _norm_body(_body_text(role_a))
        b_body = _norm_body(_body_text(role_b)) if isinstance(role_b, dict) else ""
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}

        if not _status_ok(a_status):
            continue

        admin_match = bool(b_body) and a_body == b_body and a_body != ""
        expect_bfla = bool(expect.get("bfla") or expect.get("vertical"))

        if admin_match or expect_bfla:
            check, verification, confidence = (
                "vertical_bfla_confirmed",
                "confirmed",
                0.75,
            )
        else:
            # A got 2xx on admin-ish path without admin baseline — soft
            path_hint = urlparse(url).path.lower()
            adminish = any(
                t in path_hint
                for t in ("/admin", "/manage", "/internal", "/staff", "/root")
            )
            if not adminish and not row.get("admin_path"):
                continue
            check, verification, confidence = (
                "vertical_bfla_candidate",
                "unverified",
                0.4,
            )

        stub = {
            "check": check,
            "request": {"method": method, "url": url, "role": "a"},
            "response": {
                "role_a_status": a_status,
                "role_b_admin_status": role_b.get("status")
                if isinstance(role_b, dict)
                else None,
                "bodies_match_admin_baseline": admin_match,
                "note": (
                    "Fixture-only vertical/BFLA compare — Role A must not "
                    "reach admin functions in production"
                ),
                "body_stub_role_a": a_body[:240] if a_body else None,
            },
        }
        out.append(
            _candidate(
                title="Vertical privilege / BFLA candidate (A hits admin path)",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="broken_function_level_authorization_candidate",
                evidence_summary=(
                    f"{check}: Role A on admin-ish path status={a_status} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=confidence,
                reproducible=verification == "confirmed",
            )
        )
    return out


def _sibling_methods_candidates(ctx: dict[str, Any]) -> list[dict]:
    """
    Sibling HTTP methods on same resource (GET vs DELETE/PUT/PATCH).

    Fixture row::

        {
          "url": "https://lab.example/api/objects/1",
          "get_response": {"status": 200, "body": "..."},
          "probe_method": "DELETE",
          "probe_response": {"status": 200, "body": "deleted"},
          "expected_deny_statuses": [401, 403, 405],
          "expect": {"method_confusion": true}
        }
    """
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))

    for row in fixtures.get("sibling_methods") or []:
        url = str(row.get("url") or "")
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        if not url or host is None:
            continue

        probe_method = str(
            row.get("probe_method") or row.get("method") or "DELETE"
        ).upper()
        if probe_method in ("GET", "HEAD", "OPTIONS"):
            # Not a privilege-escalating sibling for this v0 check
            continue

        probe = row.get("probe_response") or row.get("response") or {}
        get_resp = row.get("get_response") or {}
        if not isinstance(probe, dict) or not probe:
            continue

        deny = row.get("expected_deny_statuses") or list(_DENY_STATUSES)
        try:
            deny_set = {int(x) for x in deny}
        except (TypeError, ValueError):
            deny_set = set(_DENY_STATUSES)

        probe_status = probe.get("status")
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
        expect_conf = bool(
            expect.get("method_confusion")
            or expect.get("unauthorized_method")
            or expect.get("sibling_method")
        )

        try:
            probe_status_i = int(probe_status) if probe_status is not None else None
        except (TypeError, ValueError):
            probe_status_i = None

        if probe_status_i is None:
            continue
        if probe_status_i in deny_set or _status_denied(probe_status_i):
            # Properly denied — no finding
            continue
        if not _status_ok(probe_status_i) and not expect_conf:
            continue

        if expect_conf or _status_ok(probe_status_i):
            check = (
                "sibling_method_confusion_confirmed"
                if expect_conf or _status_ok(probe_status_i)
                else "sibling_method_confusion_candidate"
            )
            # Confirmed when probe succeeded (2xx) on mutating method
            if _status_ok(probe_status_i):
                verification = "confirmed"
                check = "sibling_method_confusion_confirmed"
                confidence = 0.7
            else:
                verification = "unverified"
                check = "sibling_method_confusion_candidate"
                confidence = 0.35
        else:
            continue

        stub = {
            "check": check,
            "request": {
                "method": probe_method,
                "url": url,
                "role": "a",
                "sibling_of": "GET",
            },
            "response": {
                "probe_status": probe_status_i,
                "get_status": get_resp.get("status")
                if isinstance(get_resp, dict)
                else None,
                "expected_deny_statuses": sorted(deny_set),
                "note": (
                    "Fixture-only sibling method compare — mutating method "
                    "appeared allowed for Role A"
                ),
                "body_stub_probe": _norm_body(_body_text(probe))[:240] or None,
            },
        }
        out.append(
            _candidate(
                title=(
                    f"Sibling method confusion candidate "
                    f"(GET vs {probe_method})"
                ),
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="broken_function_level_authorization_candidate",
                evidence_summary=(
                    f"{check}: {probe_method} on {url} returned "
                    f"status={probe_status_i} (verification={verification})"
                ),
                evidence_stub=stub,
                confidence=confidence,
                reproducible=verification == "confirmed",
            )
        )
    return out


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """Run all v0 BOLA/IDOR/BFLA fixture checks; filter OOS before return."""
    notes = [
        "bola_idor_bfla v0: fixture-driven dual-role candidates only",
        "requires Role A + Role B session fixtures (needs_roles=2)",
        "horizontal IDOR, vertical/BFLA, sibling method confusion",
        "no live multi-tenant abuse; no data destruction; no nuclei-all",
        "evidence request/response from fixtures only",
    ]

    if not _roles_present(ctx):
        # Runner fail-closes before reach; keep honesty if called directly
        notes.append(
            "warning: Role A and Role B not both present in ctx — "
            "runner should have fail-closed; checks may still evaluate fixtures"
        )

    candidates: list[dict[str, Any]] = []
    candidates.extend(_horizontal_idor_candidates(ctx))
    candidates.extend(_vertical_bfla_candidates(ctx))
    candidates.extend(_sibling_methods_candidates(ctx))

    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for c in candidates:
        key = (str(c.get("title")), str(c.get("url")), str(c.get("check")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    if not unique:
        notes.append(
            "no BOLA/IDOR/BFLA candidates — provide fixtures.horizontal_idor / "
            "vertical_bfla / sibling_methods under lab fixtures"
        )

    return {"candidates": unique, "notes": notes}
