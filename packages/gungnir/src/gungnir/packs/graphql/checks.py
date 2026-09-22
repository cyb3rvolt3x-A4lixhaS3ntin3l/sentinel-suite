"""graphql pack v0 — fixture-driven GraphQL candidates (defensive only).

GraphQL is not "a URL." This pack evaluates:
  - introspection enabled / disabled fixtures
  - unauth vs auth mutation diffs (Role A optional — soft coach if missing)
  - opaque / global ID enumeration-ish fixture candidates
  - batch / alias abuse as needs_human hints only

Never auto-VERIFIED. No data-dump modules. Hard request caps if live mock used.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from gungnir.packs.graphql.caps import (
    COACH_CAPS,
    HARD_MAX_REQUESTS,
    GraphqlCapExceededError,
    RequestBudget,
    host_of,
    is_lab_local_host,
    resolve_caps,
)
from gungnir.packs.manifest import finding_gate_checklist
from gungnir.packs.roles import coach_optional_role_a_missing_graphql
from gungnir.packs.runner import PackRunError
from sentinel_core import Scope, ScopeDenied, assert_url_in_scope

_AUTO_STATUSES = frozenset({"needs_human", "unverified"})
_SUCCESS = frozenset(range(200, 300))

COACH_GRAPHQL = (
    "GraphQL is not a single URL — treat schema, mutations, and ID encoding "
    "as separate surfaces. Fixture-driven only unless authorized lab mock."
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


def _status_ok(status: Any) -> bool:
    try:
        return int(status) in _SUCCESS
    except (TypeError, ValueError):
        return False


def _body_text(resp: dict[str, Any] | None) -> str:
    if not isinstance(resp, dict):
        return ""
    body = resp.get("body")
    if body is None and "data" in resp:
        # allow compact fixture shapes
        return str(resp.get("data") or "")
    return str(body or "")


def _has_introspection_schema(body: str, resp: dict[str, Any] | None) -> bool:
    blob = (body or "").lower()
    if "__schema" in blob or "__type" in blob:
        return True
    if isinstance(resp, dict):
        data = resp.get("data")
        if isinstance(data, dict) and (
            "__schema" in data or "__type" in data or "schema" in {k.lower() for k in data}
        ):
            return True
        errors = resp.get("errors")
        if isinstance(errors, list) and errors:
            # errors alone do not mean introspection succeeded
            return False
    return False


def _introspection_disabled(body: str, resp: dict[str, Any] | None) -> bool:
    blob = (body or "").lower()
    deny_tokens = (
        "introspection is not allowed",
        "introspection disabled",
        "introspection has been disabled",
        "__schema",
    )
    if isinstance(resp, dict):
        status = resp.get("status")
        try:
            st = int(status) if status is not None else None
        except (TypeError, ValueError):
            st = None
        errors = resp.get("errors")
        if isinstance(errors, list) and errors:
            err_blob = str(errors).lower()
            if any(
                t in err_blob
                for t in (
                    "introspection",
                    "forbidden",
                    "not allowed",
                    "disabled",
                )
            ):
                return True
        if st in (401, 403, 404) and not _has_introspection_schema(body, resp):
            return True
    # body mentions disabled without schema dump
    if "introspection" in blob and any(
        t in blob for t in ("disabled", "not allowed", "forbidden")
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
        "coach_hints": list(coach_hints or [COACH_GRAPHQL]),
        "evidence_summary": evidence_summary,
        "evidence_stub": evidence_stub,
        "checklist": finding_gate_checklist(
            in_scope=True,
            reproducible=reproducible,
            impact=impact,
            evidence_attached=True,
        ),
    }


def _role_a_present(ctx: dict[str, Any]) -> bool:
    roles = ctx.get("roles") or {}
    a = roles.get("a")
    if a is None:
        return False
    usable = getattr(a, "is_usable", None)
    if callable(usable):
        return bool(usable())
    return True


def _default_introspection_fixtures() -> list[dict[str, Any]]:
    return [
        {
            "name": "lab-introspection-enabled",
            "url": "http://127.0.0.1/graphql",
            "host": "127.0.0.1",
            "query": "{ __schema { queryType { name } } }",
            "response": {
                "status": 200,
                "body": '{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                "data": {"__schema": {"queryType": {"name": "Query"}}},
            },
            "expect": {"introspection_enabled": True},
        },
        {
            "name": "lab-introspection-disabled",
            "url": "http://127.0.0.1/graphql",
            "host": "127.0.0.1",
            "query": "{ __schema { queryType { name } } }",
            "response": {
                "status": 200,
                "body": '{"errors":[{"message":"GraphQL introspection is not allowed"}]}',
                "errors": [{"message": "GraphQL introspection is not allowed"}],
            },
            "expect": {"introspection_disabled": True},
        },
    ]


def _introspection_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))
    rows = list(fixtures.get("introspection") or [])
    if not rows and not fixtures:
        rows = _default_introspection_fixtures()
        notes.append("using built-in 127.0.0.1 introspection fixtures")

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "http://127.0.0.1/graphql")
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        if host is None and is_lab_local_host(host_of(url)):
            # lab-local + i_own_this already covered; allow default fixtures under i_own
            if i_own or scope is None and bool(ctx.get("i_own_this")):
                host = host_of(url) or "127.0.0.1"
            elif i_own:
                host = host_of(url) or "127.0.0.1"
        if not url or host is None:
            # still allow pure fixture rows marked lab_local
            if row.get("lab_local") or is_lab_local_host(host_of(url)):
                if i_own:
                    host = host_of(url) or "127.0.0.1"
                else:
                    notes.append(f"skipped introspection OOS/unscoped url={url}")
                    continue
            else:
                notes.append(f"skipped introspection OOS/unscoped url={url}")
                continue

        resp = row.get("response") or row.get("unauth_response") or {}
        if not isinstance(resp, dict) or not resp:
            continue
        body = _body_text(resp)
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
        enabled = bool(expect.get("introspection_enabled")) or _has_introspection_schema(
            body, resp
        )
        disabled = bool(expect.get("introspection_disabled")) or (
            _introspection_disabled(body, resp) and not enabled
        )

        if enabled:
            check = "graphql_introspection_enabled"
            verification = "needs_human"
            title = "GraphQL introspection appears enabled (fixture candidate)"
            impact = "graphql_introspection_exposure_candidate"
            confidence = 0.45
            summary = (
                f"{check}: fixture response exposes __schema/__type "
                f"(verification={verification})"
            )
        elif disabled:
            # Honest negative / disabled observation — emit low-noise note candidate
            # only when expect.report_disabled is set; otherwise skip finding.
            if not expect.get("report_disabled"):
                notes.append(
                    f"introspection disabled observed name={row.get('name') or host}"
                )
                continue
            check = "graphql_introspection_disabled"
            verification = "unverified"
            title = "GraphQL introspection appears disabled (fixture observation)"
            impact = "graphql_introspection_hardening_observation"
            confidence = 0.2
            summary = (
                f"{check}: fixture indicates introspection blocked "
                f"(verification={verification})"
            )
        else:
            continue

        stub = {
            "check": check,
            "request": {
                "method": "POST",
                "url": url,
                "query": row.get("query") or "{ __schema { queryType { name } } }",
                "role": "unauth",
            },
            "response": {
                "status": resp.get("status"),
                "has_schema": enabled,
                "body_stub": body[:240] if body else None,
                "note": "Fixture-only introspection probe — no live third-party hammering",
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
                evidence_summary=summary,
                evidence_stub=stub,
                confidence=confidence,
                reproducible=False,
                coach_hints=[
                    COACH_GRAPHQL,
                    "Confirm whether introspection is intentionally enabled in this env.",
                    "Disable introspection in production; prefer persisted queries.",
                ],
            )
        )
    return out


def _mutation_auth_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    """Unauth vs auth mutation diffs. Soft-skip with coach if Role A missing."""
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(fixtures.get("mutations") or fixtures.get("mutation_auth") or [])
    if not rows:
        return out

    if not _role_a_present(ctx):
        notes.append(coach_optional_role_a_missing_graphql())
        return out

    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        if not url or host is None:
            continue

        unauth = row.get("unauth_response") or row.get("anonymous") or {}
        auth = row.get("auth_response") or row.get("role_a_response") or {}
        if not isinstance(unauth, dict) or not isinstance(auth, dict):
            continue
        if not unauth or not auth:
            continue

        u_status = unauth.get("status")
        a_status = auth.get("status")
        u_body = _body_text(unauth)
        a_body = _body_text(auth)
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}

        unauth_ok = _status_ok(u_status) and not _looks_denied(unauth)
        auth_ok = _status_ok(a_status) and not _looks_denied(auth)
        expect_open = bool(
            expect.get("unauth_mutation_allowed")
            or expect.get("missing_auth_on_mutation")
            or expect.get("auth_bypass")
        )

        # Candidate: unauth succeeds similarly to auth (mutation open)
        if (unauth_ok and auth_ok) or (unauth_ok and expect_open):
            check = "graphql_mutation_unauth_allowed"
            verification = "needs_human"
            confidence = 0.5 if expect_open else 0.4
            title = (
                "GraphQL mutation appears allowed without auth "
                f"({row.get('mutation') or row.get('name') or 'mutation'})"
            )
            impact = "graphql_mutation_auth_bypass_candidate"
        elif unauth_ok and not auth_ok:
            # weird: unauth works, auth fails — still needs human
            check = "graphql_mutation_unauth_allowed"
            verification = "needs_human"
            confidence = 0.35
            title = "GraphQL mutation unauth success / auth failure (review)"
            impact = "graphql_mutation_auth_bypass_candidate"
        else:
            notes.append(
                f"mutation auth OK or inconclusive name={row.get('name') or url}"
            )
            continue

        stub = {
            "check": check,
            "request": {
                "method": "POST",
                "url": url,
                "mutation": row.get("mutation") or row.get("name"),
                "roles_compared": ["unauth", "a"],
            },
            "response": {
                "unauth_status": u_status,
                "auth_status": a_status,
                "unauth_body_stub": u_body[:200] if u_body else None,
                "auth_body_stub": a_body[:200] if a_body else None,
                "note": (
                    "Fixture-only unauth vs Role A mutation compare — "
                    "not a live abuse run"
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
                    f"{check}: unauth_status={u_status} auth_status={a_status} "
                    f"(verification={verification})"
                ),
                evidence_stub=stub,
                confidence=confidence,
                reproducible=False,
                coach_hints=[
                    COACH_GRAPHQL,
                    "Require auth on mutations that change state.",
                    "Compare field-level auth directives / resolvers.",
                ],
            )
        )
    return out


def _looks_denied(resp: dict[str, Any]) -> bool:
    try:
        st = int(resp.get("status")) if resp.get("status") is not None else None
    except (TypeError, ValueError):
        st = None
    if st in (401, 403):
        return True
    errors = resp.get("errors")
    if isinstance(errors, list) and errors:
        blob = str(errors).lower()
        if any(t in blob for t in ("unauthorized", "forbidden", "not authenticated", "access denied")):
            return True
    body = _body_text(resp).lower()
    if any(t in body for t in ("unauthorized", "forbidden", "not authenticated")):
        return True
    return False


def _global_id_candidates(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    """Opaque / Relay global ID enumeration-ish candidates (fixture only)."""
    out: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(fixtures.get("global_ids") or fixtures.get("opaque_ids") or [])
    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))

    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        if not url or host is None:
            continue

        samples = row.get("samples") or row.get("ids") or []
        responses = row.get("responses") or []
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
        enumerable = bool(
            expect.get("enumerable")
            or expect.get("sequential")
            or expect.get("global_id_leak")
        )

        # Fixture signal: multiple neighboring IDs return 200 with distinct objects
        success_bodies: list[str] = []
        for resp in responses:
            if not isinstance(resp, dict):
                continue
            if _status_ok(resp.get("status")) and not _looks_denied(resp):
                success_bodies.append(_body_text(resp))

        distinct = len({b for b in success_bodies if b}) >= 2
        if not (enumerable or distinct):
            notes.append(f"global_id no signal url={url}")
            continue

        check = "graphql_global_id_enumeration_candidate"
        verification = "needs_human"
        stub = {
            "check": check,
            "request": {
                "method": "POST",
                "url": url,
                "samples": list(samples)[:8] if isinstance(samples, list) else samples,
                "note": "Fixture-only ID neighbors — not a live IDOR sweep",
            },
            "response": {
                "success_count": len(success_bodies),
                "distinct_bodies": distinct,
                "note": "Opaque/global ID candidate for human review only",
            },
        }
        out.append(
            _candidate(
                title="GraphQL opaque/global ID enumeration-ish candidate",
                host=host,
                url=url,
                check=check,
                verification=verification,
                impact="graphql_global_id_enumeration_candidate",
                evidence_summary=(
                    f"{check}: {len(success_bodies)} fixture successes, "
                    f"distinct={distinct} (verification={verification})"
                ),
                evidence_stub=stub,
                confidence=0.35 if distinct else 0.25,
                reproducible=False,
                coach_hints=[
                    COACH_GRAPHQL,
                    "Prefer non-sequential / authorization-checked global IDs.",
                    "Do not brute-force IDs on production tenants.",
                ],
            )
        )
    return out


def _batch_alias_hints(ctx: dict[str, Any], notes: list[str]) -> list[dict]:
    """Batch/alias abuse — needs_human hints only (no exploit loop)."""
    hints: list[dict[str, Any]] = []
    fixtures = ctx.get("fixtures") or {}
    rows = list(fixtures.get("batch_alias") or fixtures.get("aliases") or [])
    if not rows:
        # Always emit a generic coach hint so operators remember the surface
        hints.append(
            {
                "kind": "batch_alias_coach",
                "note": (
                    "Review GraphQL batching and alias limits manually. "
                    "This pack does not run alias floods."
                ),
                "questions": [
                    COACH_GRAPHQL,
                    "Are batched operations rate-limited and cost-analyzed?",
                    "Is alias count capped per request?",
                    "Needs human: treat batch/alias abuse as a review checklist only.",
                ],
                "verification": "needs_human",
            }
        )
        notes.append("batch/alias: coach hint only (no automated abuse)")
        return hints

    scope: Scope | None = ctx.get("scope")
    i_own = bool(ctx.get("i_own_this"))
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("endpoint") or "")
        host = _scope_gate(scope, url, i_own_this=i_own) if url else None
        alias_count = row.get("alias_count") or row.get("batch_size")
        expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
        hints.append(
            {
                "kind": "batch_alias_candidate_hint",
                "url": url or None,
                "host": host,
                "alias_count": alias_count,
                "note": (
                    "needs_human: batch/alias abuse candidate hint from fixture — "
                    "pack will not flood aliases."
                ),
                "questions": [
                    COACH_GRAPHQL,
                    f"Fixture suggests alias/batch size={alias_count}.",
                    "Confirm server enforces max aliases / query cost.",
                ],
                "verification": "needs_human",
                "expect": expect,
            }
        )
    return hints


def _maybe_live_mock(ctx: dict[str, Any], caps_dict: dict[str, Any], notes: list[str]) -> None:
    """If opener/live_mock present, enforce hard request caps (no third-party hammer)."""
    opener = ctx.get("opener")
    live_mock = (ctx.get("fixtures") or {}).get("live_mock")
    if opener is None and not live_mock:
        return

    budget = RequestBudget(max_requests=int(caps_dict["max_requests"]))
    notes.append(
        f"live mock path active — hard cap requests≤{caps_dict['max_requests']} "
        f"(hard_max={HARD_MAX_REQUESTS})"
    )

    # Allow tests to inject a callable opener that must respect budget
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
        # Single probe max under budget
        if budget.try_acquire():
            try:
                opener({"query": "{ __typename }"})
            except Exception as exc:  # noqa: BLE001
                notes.append(f"live mock opener soft-fail: {exc}")
        caps_dict["requests_used"] = budget.used


def run_checks(ctx: dict[str, Any]) -> dict[str, Any]:
    """Run graphql pack v0 checks (fixture-first, scope-gated)."""
    notes: list[str] = [
        "graphql v0: fixture-driven introspection / mutation-auth / global-id candidates",
        COACH_GRAPHQL,
        "findings default needs_human|unverified; never auto-VERIFIED/confirmed",
        "batch/alias = needs_human hints only; no alias floods",
        f"live-mock hard cap requests≤{HARD_MAX_REQUESTS}",
    ]

    try:
        caps = resolve_caps(
            max_requests=ctx.get("max_requests"),
            i_understand_lab=bool(ctx.get("i_understand_lab")),
        )
    except GraphqlCapExceededError as exc:
        raise PackRunError(str(exc), exit_code=exc.exit_code) from exc

    caps_dict = caps.to_dict()
    _maybe_live_mock(ctx, caps_dict, notes)

    candidates: list[dict[str, Any]] = []
    candidates.extend(_introspection_candidates(ctx, notes))
    candidates.extend(_mutation_auth_candidates(ctx, notes))
    candidates.extend(_global_id_candidates(ctx, notes))
    hints = _batch_alias_hints(ctx, notes)

    # Deduplicate
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
            "no GraphQL candidates — provide fixtures.introspection / mutations / "
            "global_ids under lab fixtures (or rely on built-in introspection mock)"
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


__all__ = ["run_checks", "COACH_GRAPHQL"]
