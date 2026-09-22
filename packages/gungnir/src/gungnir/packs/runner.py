"""Orchestrate hunt pack runs — scope gate, role fail-closed, graph emit."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Sequence

from gungnir.bridge import emit_evidence_event, emit_verified_finding, require_scope_or_lab
from gungnir.packs.manifest import CHECKLIST_FIELDS, finding_gate_checklist
from gungnir.packs.registry import get_pack
from gungnir.packs.roles import (
    RoleSession,
    RoleSessionError,
    coach_missing_roles_message,
    load_role_session,
)
from gungnir.packs.surface import detect_auth_surface_candidates
from sentinel_core import (
    Event,
    Scope,
    ScopeDenied,
    create_program,
    load_scope_file,
    open_graph,
    program_dir,
)


class PackRunError(Exception):
    """Pack refused to start or failed closed (roles / scope / unknown pack)."""

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _resolve_scope(
    program_id: str,
    scope_path: str | Path | None,
    i_own_this: bool,
) -> tuple[Path | None, Scope | None]:
    effective: Path | None = Path(scope_path) if scope_path else None
    if effective is None and not i_own_this:
        candidate = program_dir(program_id) / "scope.txt"
        if candidate.is_file():
            loaded = load_scope_file(candidate)
            if loaded.allow:
                effective = candidate
    require_scope_or_lab(effective, i_own_this=i_own_this)
    scope: Scope | None = None
    if effective is not None:
        scope = load_scope_file(effective)
    elif i_own_this:
        # Lab override still needs a Scope object for hard_kill of explicit URLs;
        # permissive lab scope from hosts we touch is built later per-URL via
        # optional allow-all only when i_own_this — packs must still pass hosts.
        scope = None
    return effective, scope


def _load_roles(
    program_id: str,
    needs_roles: int,
    *,
    role_a_path: str | Path | None = None,
    role_b_path: str | Path | None = None,
) -> dict[str, RoleSession]:
    """Load role sessions.

    ``needs_roles=0``: Role A optional — load if present, never fail-closed.
    ``needs_roles=1``: Role A required (fail-closed).
    ``needs_roles=2``: Role A + Role B required (fail-closed).
    """
    sessions: dict[str, RoleSession] = {}
    if needs_roles == 0:
        # Soft: try Role A; pack decides how to coach if absent
        try:
            sessions["a"] = load_role_session(
                program_id, "a", path=role_a_path
            )
        except RoleSessionError:
            pass
        return sessions

    missing: list[str] = []
    try:
        sessions["a"] = load_role_session(
            program_id, "a", path=role_a_path
        )
    except RoleSessionError:
        missing.append("a")
    if needs_roles >= 2:
        try:
            sessions["b"] = load_role_session(
                program_id, "b", path=role_b_path
            )
        except RoleSessionError:
            missing.append("b")
    if missing:
        raise PackRunError(
            coach_missing_roles_message(needs_roles=needs_roles, missing=missing),
            exit_code=2,
        )
    return sessions


def _inventory_from_program(program_id: str) -> dict[str, Any]:
    """Best-effort: load runs/latest.json inventory if Eye left one."""
    latest = program_dir(program_id) / "runs" / "latest.json"
    if not latest.is_file():
        return {}
    try:
        data = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(data, dict):
        return data.get("inventory") or data
    return {}


def run_pack(
    pack_id: str,
    program_id: str,
    *,
    scope_path: str | Path | None = None,
    i_own_this: bool = False,
    urls: Sequence[str] | None = None,
    role_a_path: str | Path | None = None,
    role_b_path: str | Path | None = None,
    opener: Callable[..., Any] | None = None,
    create_if_missing: bool = True,
    fixtures: dict[str, Any] | None = None,
    max_workers: int | None = None,
    max_requests: int | None = None,
    max_duration: float | None = None,
    i_understand_lab: bool = False,
) -> dict[str, Any]:
    """
    Run a hunt pack: require_scope_or_lab, fail-closed on roles, emit candidates.

    ``opener`` / ``fixtures`` are for tests (mocked HTTP + replay stubs).
    Live third-party IdP abuse is out of scope — lab / authorized only.
    """
    if create_if_missing:
        create_program(program_id)

    try:
        pack = get_pack(pack_id)
    except KeyError as exc:
        raise PackRunError(str(exc), exit_code=2) from exc

    manifest = pack["manifest"]
    effective_scope_path, scope = _resolve_scope(program_id, scope_path, i_own_this)
    roles = _load_roles(
        program_id,
        manifest.needs_roles,
        role_a_path=role_a_path,
        role_b_path=role_b_path,
    )

    inventory = _inventory_from_program(program_id)
    surface = detect_auth_surface_candidates(
        list(urls) if urls else None,
        inventory=inventory,
    )

    ctx: dict[str, Any] = {
        "program_id": program_id,
        "scope": scope,
        "scope_path": str(effective_scope_path) if effective_scope_path else None,
        "i_own_this": bool(i_own_this),
        "roles": roles,
        "urls": list(urls or []),
        "surface": surface,
        "inventory": inventory,
        "opener": opener,
        "fixtures": fixtures or {},
        "manifest": manifest,
        "max_workers": max_workers,
        "max_requests": max_requests,
        "max_duration": max_duration,
        "i_understand_lab": bool(i_understand_lab),
    }

    result = pack["run"](ctx)
    if not isinstance(result, dict):
        raise PackRunError(f"pack {pack_id} returned non-dict result", exit_code=1)

    candidates = list(result.get("candidates") or [])
    flow_rows = list(result.get("flows") or [])
    step_rows = list(result.get("steps") or [])
    hint_rows = list(result.get("hints") or [])
    emitted: list[dict[str, Any]] = []
    flow_events: list[dict[str, Any]] = []
    step_events: list[dict[str, Any]] = []
    flow_id_map: dict[str, str] = {}

    with open_graph(program_id) as graph:
        src = f"gungnir.packs.{pack_id}"

        for flow in flow_rows:
            host_s = str(flow.get("host") or "") or None
            if scope is not None and host_s:
                try:
                    scope.hard_kill(host_s)
                except ScopeDenied:
                    continue
            local_id = str(flow.get("local_id") or flow.get("id") or "")
            payload = {
                k: v
                for k, v in flow.items()
                if k not in ("local_id", "confidence", "parents")
            }
            payload["pack_id"] = pack_id
            payload["pack_class"] = manifest.pack_class
            payload.setdefault("human_marked", False)
            fe = Event(
                type="FLOW",
                source_module=src,
                program_id=program_id,
                confidence=float(flow.get("confidence") or 0.25),
                payload=payload,
            )
            graph.insert(fe)
            if local_id:
                flow_id_map[local_id] = fe.id
            flow_events.append(
                {
                    "id": fe.id,
                    "type": "FLOW",
                    "local_id": local_id or None,
                    "kind": payload.get("kind"),
                    "name": payload.get("name"),
                    "host": host_s,
                    "confidence": fe.confidence,
                }
            )

        for step in step_rows:
            host_s = str(step.get("host") or "") or None
            if scope is not None and host_s:
                try:
                    scope.hard_kill(host_s)
                except ScopeDenied:
                    continue
            parent_local = str(step.get("flow_local_id") or "")
            parents = (
                [flow_id_map[parent_local]] if parent_local in flow_id_map else []
            )
            payload = {
                k: v
                for k, v in step.items()
                if k not in ("flow_local_id", "confidence", "parents")
            }
            payload["pack_id"] = pack_id
            payload.setdefault("human_marked", False)
            se = Event(
                type="STEP",
                source_module=src,
                program_id=program_id,
                parents=parents,
                confidence=float(step.get("confidence") or 0.25),
                payload=payload,
            )
            graph.insert(se)
            step_events.append(
                {
                    "id": se.id,
                    "type": "STEP",
                    "flow_id": parents[0] if parents else None,
                    "name": payload.get("name"),
                    "index": payload.get("index"),
                    "host": host_s,
                }
            )

        for item in candidates:
            title = str(item.get("title") or "pack candidate")
            host = item.get("host")
            host_s = str(host) if host else None
            verification = str(item.get("verification") or "unverified")
            checklist = item.get("checklist") or finding_gate_checklist(
                in_scope=bool(item.get("in_scope", scope is not None or i_own_this)),
                reproducible=bool(item.get("reproducible", False)),
                impact=str(item.get("impact") or "unknown"),
                evidence_attached=bool(item.get("evidence_attached", False)),
            )
            for key in CHECKLIST_FIELDS:
                checklist.setdefault(key, False if key != "impact" else "unknown")

            # Scope hard-kill when we have a scope + host
            if scope is not None and host_s:
                try:
                    scope.hard_kill(host_s)
                    checklist["in_scope"] = True
                except ScopeDenied:
                    # Should have been filtered by pack; skip emit
                    continue

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
                    "checklist",
                    "evidence_summary",
                    "evidence_stub",
                    "flow_local_id",
                )
            }
            payload["checklist"] = checklist
            payload["pack_id"] = pack_id
            payload["pack_class"] = manifest.pack_class
            for ck, cv in checklist.items():
                payload[ck] = cv

            flow_local = item.get("flow_local_id")
            parents: list[str] = list(item.get("parents") or [])
            if flow_local and str(flow_local) in flow_id_map:
                parents.append(flow_id_map[str(flow_local)])
            if "coach_hints" not in payload and hint_rows and flow_local:
                for h in hint_rows:
                    if h.get("flow_id") == flow_local:
                        payload["coach_hints"] = list(h.get("questions") or [])
                        break

            ev = emit_verified_finding(
                graph,
                program_id=program_id,
                title=title,
                verification=verification,
                host=host_s,
                scope=scope if host_s else None,
                confidence=float(item.get("confidence") or 0.4),
                payload=payload,
                parents=parents,
                source_module=src,
            )
            record: dict[str, Any] = {
                "id": ev.id,
                "type": ev.type,
                "title": title,
                "verification": verification,
                "host": host_s,
                "checklist": checklist,
            }
            evidence_summary = item.get("evidence_summary")
            evidence_stub = item.get("evidence_stub")
            if evidence_summary or evidence_stub:
                evi = emit_evidence_event(
                    graph,
                    program_id=program_id,
                    summary=str(evidence_summary or "pack evidence stub"),
                    parents=[ev.id],
                    payload={"stub": evidence_stub} if evidence_stub else None,
                    source_module=src,
                )
                record["evidence_id"] = evi.id
            emitted.append(record)

    return {
        "program_id": program_id,
        "pack_id": pack_id,
        "pack_class": manifest.pack_class,
        "surface_candidates": len(surface),
        "candidates_in": len(candidates),
        "findings_emitted": len(emitted),
        "flows_emitted": len(flow_events),
        "steps_emitted": len(step_events),
        "events": emitted,
        "flows": flow_events,
        "steps": step_events,
        "hints": hint_rows,
        "scoped": scope is not None,
        "i_own_this": bool(i_own_this),
        "roles_loaded": sorted(roles.keys()),
        "pack_notes": result.get("notes") or [],
        "caps": result.get("caps"),
        "observations": result.get("observations") or [],
        "fixtures_only": result.get("fixtures_only"),
    }
