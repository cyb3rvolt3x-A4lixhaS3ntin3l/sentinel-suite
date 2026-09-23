"""Thin platform-shaped markdown report export for pack findings.

Steps to Reproduce come ONLY from evidence records + stored checklist fields
on the graph — never LLM-invented. Skeleton: Summary, Scope, Steps, Impact,
Remediation placeholders.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel_core import open_graph


def _steps_from_evidence(evidence_events: list[Any]) -> list[str]:
    """Build numbered steps strictly from EVIDENCE payloads / stubs."""
    steps: list[str] = []
    for idx, evi in enumerate(evidence_events, start=1):
        payload = getattr(evi, "payload", None) or {}
        if not isinstance(payload, dict):
            continue
        summary = payload.get("summary")
        stub = payload.get("stub")
        if isinstance(stub, dict):
            req = stub.get("request") or {}
            resp = stub.get("response") or {}
            if isinstance(req, dict) and (req.get("method") or req.get("url")):
                method = req.get("method") or "GET"
                url = req.get("url") or ""
                steps.append(f"{len(steps) + 1}. Request: {method} {url}")
            if isinstance(resp, dict) and resp:
                bits: list[str] = []
                if resp.get("status") is not None:
                    bits.append(f"status={resp.get('status')}")
                if resp.get("note"):
                    bits.append(str(resp.get("note")))
                observed = resp.get("observed")
                if isinstance(observed, dict):
                    obs_bits = [
                        f"{k}={observed[k]}"
                        for k in sorted(observed)
                        if not str(k).endswith("_value")
                        and "token" not in str(k).lower()
                    ]
                    if obs_bits:
                        bits.append("observed: " + ", ".join(obs_bits[:12]))
                if resp.get("diff"):
                    bits.append(
                        "diff=" + ",".join(str(x) for x in resp.get("diff"))
                    )
                if resp.get("label"):
                    bits.append(f"label={resp.get('label')}")
                if resp.get("reasons"):
                    bits.append(
                        "reasons="
                        + ",".join(str(x) for x in resp.get("reasons"))
                    )
                if resp.get("token_types_observed"):
                    bits.append(
                        "token_types="
                        + ",".join(
                            str(x) for x in resp.get("token_types_observed")
                        )
                    )
                if resp.get("sink_kind"):
                    bits.append(f"sink_kind={resp.get('sink_kind')}")
                if resp.get("marker"):
                    bits.append(f"marker={resp.get('marker')}")
                if resp.get("marker_in_sink") is not None:
                    bits.append(f"marker_in_sink={resp.get('marker_in_sink')}")
                if resp.get("sink_snippet"):
                    snip = str(resp.get("sink_snippet"))
                    bits.append("sink_snippet=" + snip[:160])
                if bits:
                    steps.append(
                        f"{len(steps) + 1}. Response/evidence: "
                        + "; ".join(bits)
                    )
            check = stub.get("check")
            if check and not any(check in s for s in steps):
                steps.append(f"{len(steps) + 1}. Check id: {check}")
        elif summary:
            steps.append(f"{len(steps) + 1}. Evidence summary: {summary}")
        elif summary is None and not stub:
            steps.append(
                f"{len(steps) + 1}. Evidence record "
                f"{getattr(evi, 'id', idx)} (empty payload)"
            )
        if summary and isinstance(stub, dict):
            steps.append(f"{len(steps) + 1}. Evidence summary: {summary}")
    return steps


def _checklist_evidence_lines(payload: dict[str, Any]) -> list[str]:
    """Checklist / confirm stamps as evidence-log lines (stored data only)."""
    lines: list[str] = []
    checklist = payload.get("checklist")
    if not isinstance(checklist, dict):
        checklist = {}
        for key in ("in_scope", "reproducible", "impact", "evidence_attached"):
            if key in payload:
                checklist[key] = payload[key]
    if checklist:
        bits = []
        for key in ("in_scope", "reproducible", "impact", "evidence_attached"):
            if key in checklist:
                bits.append(f"{key}={checklist[key]}")
        if bits:
            lines.append("Checklist: " + "; ".join(bits))
    if payload.get("human_confirm_note"):
        lines.append(f"Human confirm note: {payload.get('human_confirm_note')}")
    if payload.get("human_confirm_by") or payload.get("human_confirm_at"):
        lines.append(
            "Human confirm stamp: "
            f"by={payload.get('human_confirm_by') or '?'}; "
            f"at={payload.get('human_confirm_at') or '?'}"
        )
    if payload.get("pack_auto_confirm_refused"):
        lines.append(
            "Pack auto-confirm refused "
            f"(claimed={payload.get('pack_claimed_verification')}; "
            "graph status coerced to needs_human)"
        )
    return lines


def _finding_markdown(
    finding: Any,
    evidence_for_finding: list[Any],
) -> str:
    payload = getattr(finding, "payload", None) or {}
    if not isinstance(payload, dict):
        payload = {}
    title = str(payload.get("title") or "Untitled finding")
    verification = str(payload.get("verification") or "unverified")
    host = payload.get("host") or ""
    url = payload.get("url") or ""
    check = payload.get("check") or ""
    impact = (
        payload.get("impact")
        or (payload.get("checklist") or {}).get("impact")
        or "unknown"
    )
    confidence = getattr(finding, "confidence", None)
    pack_id = payload.get("pack_id") or ""

    summary_bits = [
        f"Verification: {verification}",
        f"Check: {check}" if check else None,
        f"Host: {host}" if host else None,
        f"URL: {url}" if url else None,
        f"Pack: {pack_id}" if pack_id else None,
        f"Confidence: {confidence}" if confidence is not None else None,
    ]
    if payload.get("human_confirmed"):
        summary_bits.append(
            f"Human-confirmed by={payload.get('human_confirm_by') or '?'}"
        )
    summary = "; ".join(b for b in summary_bits if b)

    scope_bits: list[str] = []
    if host:
        scope_bits.append(f"host={host}")
    if url:
        scope_bits.append(f"url={url}")
    checklist = payload.get("checklist") if isinstance(payload.get("checklist"), dict) else {}
    if "in_scope" in checklist:
        scope_bits.append(f"in_scope={checklist.get('in_scope')}")
    elif "in_scope" in payload:
        scope_bits.append(f"in_scope={payload.get('in_scope')}")
    scope_line = (
        "; ".join(scope_bits) if scope_bits else "_(no scope fields on finding)_"
    )

    steps = _steps_from_evidence(evidence_for_finding)
    for line in _checklist_evidence_lines(payload):
        steps.append(f"{len(steps) + 1}. {line}")
    if not steps:
        steps_block = (
            "_(no evidence records linked — steps unavailable; "
            "re-run pack with fixtures to attach evidence stubs)_"
        )
    else:
        steps_block = "\n".join(steps)

    return "\n".join(
        [
            f"## {title}",
            "",
            "### Summary",
            "",
            summary or "_(no summary fields)_",
            "",
            "### Scope",
            "",
            scope_line,
            "",
            "### Steps to Reproduce",
            "",
            steps_block,
            "",
            "### Impact",
            "",
            f"{impact}",
            "",
            "_(Impact narrative placeholder — fill for platform submission.)_",
            "",
            "### Remediation",
            "",
            "_(Remediation placeholder — recommend fixing the misconfiguration "
            "described by the check id / evidence above.)_",
            "",
        ]
    )


def collect_pack_findings(
    program_id: str,
    *,
    pack_id: str | None = None,
) -> list[dict[str, Any]]:
    """
    Load FINDING (+ linked EVIDENCE) from the program graph.

    When ``pack_id`` is set, only findings with matching ``payload.pack_id``.
    """
    rows: list[dict[str, Any]] = []
    with open_graph(program_id) as graph:
        findings = graph.list_by_type("FINDING")
        evidence = graph.list_by_type("EVIDENCE")
        by_parent: dict[str, list[Any]] = {}
        for evi in evidence:
            for pid in evi.parents or []:
                by_parent.setdefault(pid, []).append(evi)
        for finding in findings:
            payload = finding.payload or {}
            fid_pack = payload.get("pack_id")
            if pack_id and fid_pack != pack_id:
                src = getattr(finding, "source_module", "") or ""
                if pack_id not in src and fid_pack != pack_id:
                    continue
            evi_list = by_parent.get(finding.id, [])
            rows.append(
                {
                    "finding": finding,
                    "evidence": evi_list,
                    "markdown": _finding_markdown(finding, evi_list),
                }
            )
    return rows


def render_report_markdown(
    program_id: str,
    *,
    pack_id: str | None = None,
    all_packs: bool = False,
) -> str:
    """Render a thin multi-finding markdown report (platform-shaped skeleton)."""
    if all_packs:
        pack_id = None
    rows = collect_pack_findings(program_id, pack_id=pack_id)
    header = [
        f"# Hunt report — `{program_id}`",
        "",
        f"Pack filter: `{pack_id or '(all packs / findings)'}`",
        "",
        f"Findings included: {len(rows)}",
        "",
        "---",
        "",
    ]
    if not rows:
        header.append(
            "_No matching findings in the program graph. "
            "Run `sentinel hunt pack run ...` first._\n"
        )
        return "\n".join(header)
    body: list[str] = []
    for i, row in enumerate(rows):
        body.append(row["markdown"])
        if i < len(rows) - 1:
            body.append("---\n")
    return "\n".join(header + body)


def export_report(
    program_id: str,
    *,
    pack_id: str | None = None,
    all_packs: bool = False,
    output: str | Path | None = None,
) -> dict[str, Any]:
    """
    Export markdown report. If ``output`` is set, write the file; always return meta.
    """
    if all_packs:
        pack_id = None
    md = render_report_markdown(program_id, pack_id=pack_id, all_packs=all_packs)
    written: str | None = None
    if output is not None:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(md, encoding="utf-8")
        written = str(path)
    rows = collect_pack_findings(program_id, pack_id=pack_id)
    return {
        "program_id": program_id,
        "pack_id": pack_id,
        "all_packs": bool(all_packs or pack_id is None),
        "findings": len(rows),
        "output": written,
        "markdown": md,
    }


__all__ = [
    "collect_pack_findings",
    "export_report",
    "render_report_markdown",
]
