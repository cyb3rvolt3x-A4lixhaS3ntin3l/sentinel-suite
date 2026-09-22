"""Thin Gungnir hunt runner — findings → emit_verified_finding into program graph."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

from gungnir.bridge import emit_evidence_event, emit_verified_finding, require_scope_or_lab
from gungnir.correlate import correlate_findings
from sentinel_core import Scope, create_program, load_scope_file, open_graph, program_dir


def _load_findings_json(raw: str) -> list[dict[str, Any]]:
    data = json.loads(raw)
    if isinstance(data, dict):
        if "findings" in data and isinstance(data["findings"], list):
            return [f for f in data["findings"] if isinstance(f, dict)]
        return [data]
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    raise ValueError("findings JSON must be an object, list, or {findings: [...]}")


def load_findings(
    *,
    stdin: TextIO | None = None,
    title: str | None = None,
    host: str | None = None,
    findings_file: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Load findings from file, stdin JSON, or a demo --title."""
    if findings_file is not None:
        text = Path(findings_file).read_text(encoding="utf-8")
        return _load_findings_json(text)

    if title:
        item: dict[str, Any] = {"title": title, "verification": "unverified"}
        if host:
            item["host"] = host
        return [item]

    stream = stdin if stdin is not None else sys.stdin
    if not stream.isatty():
        text = stream.read()
        if text.strip():
            return _load_findings_json(text)

    raise ValueError(
        "no findings: pass --title, --findings FILE, or JSON on stdin"
    )


def run_hunt(
    program_id: str,
    findings: Sequence[dict[str, Any]] | None = None,
    *,
    scope_path: str | Path | None = None,
    i_own_this: bool = False,
    title: str | None = None,
    host: str | None = None,
    findings_file: str | Path | None = None,
    correlate: bool = True,
    evidence_summary: str | None = None,
    create_if_missing: bool = True,
    stdin: TextIO | None = None,
) -> dict[str, Any]:
    """
    Require --scope OR --i-own-this; emit verified findings into program graph.

    Optional thin correlate (dedupe + unverified default). Scope hard_kill when
    scope + host are present on a finding.
    """
    if create_if_missing:
        create_program(program_id)

    effective_scope_path: Path | None = Path(scope_path) if scope_path else None
    if effective_scope_path is None and not i_own_this:
        candidate = program_dir(program_id) / "scope.txt"
        if candidate.is_file():
            loaded = load_scope_file(candidate)
            if loaded.allow:
                effective_scope_path = candidate

    require_scope_or_lab(effective_scope_path, i_own_this=i_own_this)

    scope: Scope | None = None
    if effective_scope_path is not None:
        scope = load_scope_file(effective_scope_path)

    if findings is None:
        findings = load_findings(
            stdin=stdin, title=title, host=host, findings_file=findings_file
        )

    prepared = list(findings)
    if correlate:
        prepared = correlate_findings(prepared)

    emitted: list[dict[str, Any]] = []
    with open_graph(program_id) as graph:
        for item in prepared:
            f_title = str(item.get("title") or "untitled")
            f_host = item.get("host") or host
            f_host_s = str(f_host) if f_host else None
            verification = str(item.get("verification") or "unverified")
            confidence = float(item.get("confidence") or 0.5)
            payload = {
                k: v
                for k, v in item.items()
                if k
                not in (
                    "title",
                    "host",
                    "verification",
                    "verification_status",
                    "verified",
                    "confidence",
                    "parents",
                )
            }
            ev = emit_verified_finding(
                graph,
                program_id=program_id,
                title=f_title,
                verification=verification,
                host=f_host_s,
                scope=scope if f_host_s else None,
                confidence=confidence,
                payload=payload,
                source_module="gungnir.runner",
            )
            record = {
                "id": ev.id,
                "type": ev.type,
                "title": f_title,
                "verification": verification,
                "host": f_host_s,
            }
            if evidence_summary:
                evi = emit_evidence_event(
                    graph,
                    program_id=program_id,
                    summary=evidence_summary,
                    parents=[ev.id],
                    source_module="gungnir.runner",
                )
                record["evidence_id"] = evi.id
            emitted.append(record)

    return {
        "program_id": program_id,
        "findings_in": len(findings),
        "findings_emitted": len(emitted),
        "events": emitted,
        "correlated": bool(correlate),
        "scoped": scope is not None,
        "i_own_this": bool(i_own_this),
    }
