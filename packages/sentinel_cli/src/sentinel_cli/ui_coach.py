"""Phase D3 — Coach: static/rule methodology hints from live program counts.

Never invents findings. No LLM. Hints cite evidence_counts only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Hours of Eye/mapping before time-budget nudge (still map-heavy).
MAP_BUDGET_HOURS = 4

# URL path tokens that look like interesting API surfaces (heuristic only).
_API_PATH_TOKENS = (
    "/api/",
    "/api?",
    "/graphql",
    "/v1/",
    "/v2/",
    "/v3/",
    "/rest/",
    "/rpc/",
    "/json",
    "/swagger",
    "/openapi",
)


def _parse_iso_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (TypeError, ValueError):
        return None


def _hint(
    *,
    id: str,
    kind: str,
    title: str,
    body: str,
    evidence_counts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": id,
        "kind": kind,
        "title": title,
        "body": body,
    }
    if evidence_counts is not None:
        row["evidence_counts"] = evidence_counts
    return row


def _is_interesting_api_url(url: str) -> bool:
    u = (url or "").lower()
    return any(tok in u for tok in _API_PATH_TOKENS)


def collect_program_stats(program_id: str) -> dict[str, Any]:
    """Gather graph / findings / Eye age counts for coach rules (read-only)."""
    from gungnir.packs.confirm import list_findings
    from gungnir.packs.surface import detect_auth_surface_candidates
    from sentinel_core import open_graph, program_dir
    from shadowseye.watch import load_latest_snapshot

    counts: dict[str, Any] = {
        "domain": 0,
        "dns": 0,
        "ip": 0,
        "port": 0,
        "url": 0,
        "interesting_api": 0,
        "auth_surface": 0,
        "findings_total": 0,
        "findings_by_pack": {},
        "findings_needs_human": 0,
        "findings_confirmed": 0,
        "eye_last_run_age_hours": None,
        "eye_last_run_ts": None,
        "graph_present": False,
        "has_scope": False,
    }

    root = program_dir(program_id)
    counts["has_scope"] = (root / "scope.txt").is_file()

    urls: list[str] = []
    try:
        graph = open_graph(program_id)
    except FileNotFoundError:
        graph = None

    if graph is not None:
        counts["graph_present"] = True
        try:
            counts["domain"] = len(list(graph.list_by_type("DOMAIN")))
            counts["dns"] = len(list(graph.list_by_type("DNS_NAME")))
            counts["ip"] = len(list(graph.list_by_type("IP")))
            counts["port"] = len(list(graph.list_by_type("OPEN_PORT")))
            for ev in graph.list_by_type("URL"):
                url = str((ev.payload or {}).get("url") or "").strip()
                if not url:
                    continue
                counts["url"] += 1
                urls.append(url)
                if _is_interesting_api_url(url):
                    counts["interesting_api"] += 1
        finally:
            close = getattr(graph, "close", None)
            if callable(close):
                close()

    auth_cands = detect_auth_surface_candidates(urls=urls)
    counts["auth_surface"] = len(auth_cands)

    findings = list_findings(program_id, status="all")
    counts["findings_total"] = len(findings)
    by_pack: dict[str, int] = {}
    for f in findings:
        pid = str(f.get("pack_id") or "unknown")
        by_pack[pid] = by_pack.get(pid, 0) + 1
        ver = str(f.get("verification") or "").lower()
        if ver in ("needs_human", "unverified", "pending"):
            counts["findings_needs_human"] += 1
        if ver in ("confirmed", "verified"):
            counts["findings_confirmed"] += 1
    counts["findings_by_pack"] = by_pack

    latest = load_latest_snapshot(root) if root.is_dir() else None
    if latest and latest.get("ts"):
        counts["eye_last_run_ts"] = latest.get("ts")
        dt = _parse_iso_ts(latest.get("ts"))
        if dt is not None:
            age_h = (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
            counts["eye_last_run_age_hours"] = round(age_h, 2)

    return counts


def generate_coach_hints(
    program_id: str,
    *,
    stats: dict[str, Any] | None = None,
    map_budget_hours: float = MAP_BUDGET_HOURS,
) -> list[dict[str, Any]]:
    """
    Build ordered methodology hints from counts.

    Never claims a vulnerability exists that is not in the findings store.
    Pack suggestions are methodology only ("consider running …"), not bug claims.
    """
    c = stats if stats is not None else collect_program_stats(program_id)
    hints: list[dict[str, Any]] = []

    # --- Stage checklist (map vs test) ---
    map_done = (
        bool(c.get("graph_present"))
        and (int(c.get("url") or 0) + int(c.get("dns") or 0) + int(c.get("domain") or 0)) > 0
    )
    test_started = int(c.get("findings_total") or 0) > 0
    stage_body_parts = [
        "Map phase: Eye inventory on graph "
        + ("present" if map_done else "empty — run `sentinel eye run` (owned/scoped)"),
        f"· domains={c.get('domain', 0)} dns={c.get('dns', 0)} "
        f"urls={c.get('url', 0)} ports={c.get('port', 0)}",
        "Test phase: hunt packs against role sessions "
        + (
            f"— {c.get('findings_total', 0)} finding event(s) on store "
            f"({c.get('findings_needs_human', 0)} needs_human)"
            if test_started
            else "— no FINDING events yet (packs never auto-VERIFIED)"
        ),
        "Confirm phase: human confirm-finding with note before any report claim.",
    ]
    if not c.get("has_scope"):
        stage_body_parts.append("Scope: scope.txt missing — init program / import brief first.")
    hints.append(
        _hint(
            id="stage-checklist",
            kind="stage_checklist",
            title="Stage checklist — map vs test",
            body="\n".join(stage_body_parts),
            evidence_counts={
                "domain": c.get("domain", 0),
                "dns": c.get("dns", 0),
                "url": c.get("url", 0),
                "port": c.get("port", 0),
                "findings_total": c.get("findings_total", 0),
                "findings_needs_human": c.get("findings_needs_human", 0),
                "has_scope": bool(c.get("has_scope")),
                "graph_present": bool(c.get("graph_present")),
            },
        )
    )

    # --- Pack rule hints from graph counts (methodology, not vuln claims) ---
    auth_n = int(c.get("auth_surface") or 0)
    api_n = int(c.get("interesting_api") or 0)
    bola_n = int((c.get("findings_by_pack") or {}).get("bola_idor_bfla") or 0)
    xss_n = int((c.get("findings_by_pack") or {}).get("xss_dom") or 0)
    ato_n = int((c.get("findings_by_pack") or {}).get("ato_oauth_oidc") or 0)
    if auth_n >= 2 and bola_n == 0 and api_n >= 1:
        hints.append(
            _hint(
                id="rule-bola-over-xss",
                kind="pack_rule",
                title="Next pack hint: prefer BOLA/IDOR over XSS",
                body=(
                    f"You have {api_n} interesting API URL(s) and {auth_n} auth surface "
                    f"candidate(s) on the graph, but 0 bola_idor_bfla FINDING events. "
                    f"Methodology: prioritize `bola_idor_bfla` (role A/B) before XSS chrome. "
                    f"This is a pack-order hint — not a claim that BOLA exists."
                ),
                evidence_counts={
                    "interesting_api": api_n,
                    "auth_surface": auth_n,
                    "bola_idor_bfla_findings": bola_n,
                    "xss_dom_findings": xss_n,
                },
            )
        )
    elif auth_n >= 1 and ato_n == 0:
        hints.append(
            _hint(
                id="rule-ato-oauth",
                kind="pack_rule",
                title="Next pack hint: ATO / OAuth surface",
                body=(
                    f"{auth_n} auth surface candidate(s) detected from URL path/query "
                    f"heuristics, with 0 ato_oauth_oidc FINDING events. "
                    f"Consider `ato_oauth_oidc` after roles are loaded — methodology only."
                ),
                evidence_counts={
                    "auth_surface": auth_n,
                    "ato_oauth_oidc_findings": ato_n,
                },
            )
        )
    elif api_n >= 3 and bola_n == 0 and xss_n > bola_n:
        hints.append(
            _hint(
                id="rule-api-dense-bola",
                kind="pack_rule",
                title="API-dense map — BOLA before more XSS",
                body=(
                    f"{api_n} interesting API URL(s) vs xss_dom findings={xss_n}, "
                    f"bola_idor_bfla findings={bola_n}. "
                    f"Rule of thumb: object-level auth on APIs usually outranks DOM XSS "
                    f"when the map is API-heavy. Not a vulnerability claim."
                ),
                evidence_counts={
                    "interesting_api": api_n,
                    "bola_idor_bfla_findings": bola_n,
                    "xss_dom_findings": xss_n,
                },
            )
        )
    elif map_done and int(c.get("findings_total") or 0) == 0:
        hints.append(
            _hint(
                id="rule-start-testing",
                kind="pack_rule",
                title="Map has inventory — start a gated pack run",
                body=(
                    f"Graph has inventory (urls={c.get('url', 0)}, dns={c.get('dns', 0)}) "
                    f"but no FINDING events yet. Pick a pack on Hunt with i_own_this — "
                    f"Coach never invents bugs; packs stay needs_human until confirm."
                ),
                evidence_counts={
                    "url": c.get("url", 0),
                    "dns": c.get("dns", 0),
                    "findings_total": 0,
                },
            )
        )

    # GraphQL path heuristic
    # (graphql pack findings already tracked; suggest if /graphql URLs and no findings)
    # Reuse auth/api counts only — avoid inventing.

    # --- Time budget ---
    age = c.get("eye_last_run_age_hours")
    if age is not None and float(age) >= float(map_budget_hours):
        still_map_heavy = int(c.get("findings_total") or 0) == 0 and (
            int(c.get("url") or 0) + int(c.get("dns") or 0) > 0
        )
        if still_map_heavy or float(age) >= float(map_budget_hours) * 2:
            hints.append(
                _hint(
                    id="time-budget-eye",
                    kind="time_budget",
                    title="Time-budget — Eye mapping has run long",
                    body=(
                        f"Latest Eye/watch snapshot is ~{age}h old "
                        f"(budget threshold {map_budget_hours}h). "
                        + (
                            "Inventory exists but no FINDING events — "
                            "shift from map to test (gated pack run) "
                            "instead of endless remapping."
                            if still_map_heavy
                            else "Reassess: remapping vs testing vs report triage."
                        )
                    ),
                    evidence_counts={
                        "eye_last_run_age_hours": age,
                        "eye_last_run_ts": c.get("eye_last_run_ts"),
                        "map_budget_hours": map_budget_hours,
                        "findings_total": c.get("findings_total", 0),
                        "url": c.get("url", 0),
                    },
                )
            )

    # --- False-positive school (static) ---
    hints.append(
        _hint(
            id="fp-school",
            kind="fp_school",
            title="False-positive school",
            body=(
                "Static tips (not claims about this program):\n"
                "· Reflection ≠ XSS — need sink + context + exploitability.\n"
                "· 403/401 on ID swap ≠ BOLA — confirm object access across roles.\n"
                "· Open redirect candidates need chain to account takeover / token leak.\n"
                "· Collaborator ping alone is not SSRF impact — prove reachability class.\n"
                "· Pack emits stay needs_human; confirm-finding note is the gate.\n"
                f"This program: findings_total={c.get('findings_total', 0)}, "
                f"needs_human={c.get('findings_needs_human', 0)} "
                "(triage these rows — Coach does not invent extras)."
            ),
            evidence_counts={
                "findings_total": c.get("findings_total", 0),
                "findings_needs_human": c.get("findings_needs_human", 0),
            },
        )
    )

    # --- Report school (impact sentence templates; no fabricated CVSS) ---
    confirmed = int(c.get("findings_confirmed") or 0)
    needs = int(c.get("findings_needs_human") or 0)
    report_body = (
        "Impact sentence templates (fill with YOUR confirmed evidence only — "
        "never invent CVSS or unconfirmed bugs):\n"
        "· Confidentiality: \"An authorized role-A session can read role-B object "
        "{id} via {method} {path}, exposing {data_class}.\"\n"
        "· Integrity: \"Without CSRF/SameSite controls, state-changing {action} "
        "accepts cross-site requests as the victim session.\"\n"
        "· Availability / abuse: \"Unauthenticated {endpoint} accepts "
        "{expensive_op} without rate/cost limits (lab-measured).\"\n"
        "Do not assign CVSS in Coach. Export markdown from Reports after "
        "confirm-finding."
    )
    if confirmed:
        report_body += (
            f"\nStore: {confirmed} confirmed finding(s) ready for report wording; "
            f"{needs} still needs_human."
        )
    elif needs:
        report_body += (
            f"\nStore: {needs} needs_human finding(s) — confirm before impact claims."
        )
    else:
        report_body += (
            "\nStore: no FINDING events yet — templates only; nothing to report."
        )
    hints.append(
        _hint(
            id="report-school",
            kind="report_school",
            title="Report-school — impact sentences",
            body=report_body,
            evidence_counts={
                "findings_confirmed": confirmed,
                "findings_needs_human": needs,
                "findings_total": c.get("findings_total", 0),
            },
        )
    )

    return hints


def coach_payload(program_id: str) -> dict[str, Any]:
    """API payload for GET /api/programs/<id>/coach."""
    from sentinel_core import program_dir

    root = program_dir(program_id)
    if not root.is_dir():
        raise FileNotFoundError(
            f"program {program_id!r} not found; run: sentinel program init {program_id}"
        )
    stats = collect_program_stats(program_id)
    hints = generate_coach_hints(program_id, stats=stats)
    lab_bound = False
    lab_kinds: list[str] = []
    lab_progress: dict[str, Any] | None = None
    # Phase E0/E1 — lab hooks (curriculum only; never invent findings)
    try:
        from sentinel_cli.ui_labs import (
            generate_lab_coach_hints,
            lab_status_payload,
            load_lab_binding,
        )

        lab_bound = load_lab_binding(program_id) is not None
        if lab_bound:
            lab_hints = generate_lab_coach_hints(program_id)
            hints = list(hints) + lab_hints
            lab_kinds = sorted(
                {str(h.get("kind") or "") for h in lab_hints if h.get("kind")}
            )
            try:
                st = lab_status_payload(program_id)
                lab_progress = {
                    "lab_id": st.get("lab_id"),
                    "counts": st.get("counts"),
                    "base_url": st.get("base_url"),
                    "lab_stage": next(
                        (
                            h.get("lab_stage") or (h.get("evidence_counts") or {}).get("lab_stage")
                            for h in lab_hints
                            if h.get("kind") == "lab_stage"
                        ),
                        None,
                    ),
                }
            except FileNotFoundError:
                lab_progress = None
    except Exception:  # noqa: BLE001 — coach must not fail if labs import issues
        lab_bound = False
        lab_kinds = []
        lab_progress = None
    return {
        "program_id": program_id,
        "hints": hints,
        "count": len(hints),
        "evidence_counts": stats,
        "lab_bound": lab_bound,
        "lab_kinds": lab_kinds,
        "lab_progress": lab_progress,
        "disclaimer": (
            "Coach is a methodology tutor from live counts + static rules. "
            "It never invents vulnerabilities. No LLM. "
            "Only FINDING events on the store are real findings. "
            "Lab hints are curriculum gates (attempt → unlock), not bug claims."
        ),
        "llm": False,
        "phase": "E3",
    }


__all__ = [
    "MAP_BUDGET_HOURS",
    "coach_payload",
    "collect_program_stats",
    "generate_coach_hints",
]
