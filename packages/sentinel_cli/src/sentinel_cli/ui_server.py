"""Phase D0–D2 — local UI shell (stdlib HTTP, bind 127.0.0.1:8888 by default)."""

from __future__ import annotations

import json
import sys
import threading
import traceback
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from sentinel_cli.ui_auth import (
    UIAuthError,
    auth_status,
    extract_bearer,
    login as auth_login,
    logout as auth_logout,
    require_mutating_auth,
    setup_auth,
)

# --- Bind gate (mirror collaborator ethics; UI-specific messages) ---

DEFAULT_UI_BIND = "127.0.0.1"
DEFAULT_UI_PORT = 8888
_WILDCARD_BINDS = frozenset({"0.0.0.0", "::", "*", "[::]"})
_LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})

COACH_UI_BIND_NON_LOOPBACK = (
    "sentinel ui refuses non-loopback bind "
    "(0.0.0.0 / :: / public interfaces) without --i-understand-lab. "
    "Default bind is 127.0.0.1:8888 only. "
    "Public bind is a lab exception, never the default."
)

# In-flight UI pack runs (hard-kill / stop + denser log poll).
_runs_lock = threading.Lock()
_runs: dict[str, dict[str, Any]] = {}
_active_run_id: str | None = None


class UIBindError(Exception):
    """Non-loopback bind refused without lab flag."""

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def is_loopback_bind(bind: str | None) -> bool:
    """True for 127.0.0.1 / localhost / ::1 / 127.* only (not 0.0.0.0 / ::)."""
    import ipaddress

    raw = (bind or "").strip().lower()
    if not raw:
        return False
    if raw in _WILDCARD_BINDS:
        return False
    if raw in _LOOPBACK_NAMES or raw.startswith("127."):
        return True
    host = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        addr = ipaddress.ip_address(host)
        return bool(addr.is_loopback)
    except ValueError:
        return False


def assert_ui_bind_allowed(
    bind: str | None,
    *,
    i_understand_lab: bool = False,
) -> str:
    """Refuse non-loopback binds unless --i-understand-lab. Returns normalized bind."""
    b = (bind or DEFAULT_UI_BIND).strip() or DEFAULT_UI_BIND
    if is_loopback_bind(b):
        return b
    if not i_understand_lab:
        raise UIBindError(COACH_UI_BIND_NON_LOOPBACK, exit_code=2)
    return b


def resolve_ui_static_root() -> Path:
    """Prefer repo ``ui/``; fall back to package ``static/`` if vendored later."""
    here = Path(__file__).resolve()
    # packages/sentinel_cli/src/sentinel_cli/ui_server.py → repo root = parents[4]
    repo_ui = here.parents[4] / "ui"
    if (repo_ui / "index.html").is_file():
        return repo_ui
    pkg_static = here.parent / "static"
    if (pkg_static / "index.html").is_file():
        return pkg_static
    raise FileNotFoundError(
        f"UI static root not found (looked for {repo_ui} and {pkg_static})"
    )


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log_line(level: str, msg: str, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"ts": _ts(), "level": level, "msg": msg}
    row.update(extra)
    return row


def doctor_status() -> dict[str, Any]:
    """Structured doctor check (same facts as ``sentinel doctor``)."""
    lines: list[str] = []
    ok = True
    detail: dict[str, Any] = {}

    lines.append(f"python: {sys.version.split()[0]} ({sys.executable})")
    detail["python"] = sys.version.split()[0]

    try:
        import sentinel_core
        from sentinel_core import (
            Event,
            engine_catalog_summary,
            get_sentinel_home,
            list_engine_status,
        )

        lines.append(f"sentinel_core: import OK (v{sentinel_core.__version__})")
        detail["sentinel_core"] = sentinel_core.__version__
    except Exception as exc:  # noqa: BLE001
        ok = False
        lines.append(f"sentinel_core: FAIL ({exc})")
        return {
            "ok": False,
            "status": "FAIL",
            "lines": lines,
            "detail": detail,
            "error": str(exc),
        }

    home = get_sentinel_home()
    detail["SENTINEL_HOME"] = str(home)
    lines.append(f"SENTINEL_HOME: {home}")

    try:
        home.mkdir(parents=True, exist_ok=True)
        probe = home / ".doctor_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        lines.append("SENTINEL_HOME writable: yes")
        detail["writable"] = True
    except OSError as exc:
        ok = False
        lines.append(f"SENTINEL_HOME writable: no ({exc})")
        detail["writable"] = False

    catalog = engine_catalog_summary()
    detail["engines"] = {
        "allowlisted": list(catalog.get("allowlisted") or []),
        "status_rows": list_engine_status(home),
    }
    lines.append(
        "engines allowlisted: "
        + (str(catalog.get("allowlisted") or "[]"))
    )

    try:
        Event(type="DOMAIN", source_module="doctor", program_id="doctor")
        lines.append("event schema: ok")
        detail["event_schema"] = True
    except Exception as exc:  # noqa: BLE001
        ok = False
        lines.append(f"event schema: FAIL ({exc})")
        detail["event_schema"] = False

    for pkg in ("shadowseye", "gungnir"):
        try:
            mod = __import__(pkg)
            ver = getattr(mod, "__version__", "?")
            lines.append(f"{pkg}: import OK (v{ver})")
            detail[pkg] = ver
        except Exception as exc:  # noqa: BLE001
            lines.append(f"{pkg}: not importable ({exc})")
            detail[pkg] = None

    # D1: surface auth config in doctor (no secrets)
    try:
        a = auth_status(home)
        detail["ui_auth"] = {
            "configured": a.get("configured"),
            "mode": a.get("mode"),
            "need_first_run": a.get("need_first_run"),
        }
        lines.append(
            f"ui_auth: mode={a.get('mode') or 'unset'} "
            f"configured={a.get('configured')}"
        )
    except Exception as exc:  # noqa: BLE001
        lines.append(f"ui_auth: status error ({exc})")

    status = "PASS" if ok else "FAIL"
    lines.append(f"doctor: {status}")
    return {"ok": ok, "status": status, "lines": lines, "detail": detail}


def packs_payload() -> dict[str, Any]:
    from gungnir.packs import list_pack_manifests

    packs = list_pack_manifests()
    rows = []
    for m in packs:
        rows.append(
            {
                "id": m.id,
                "class": m.pack_class,
                "needs_roles": m.needs_roles,
                "noise_class": m.noise_class,
                "version": m.version,
                "description": m.description,
                "consumes": list(m.consumes),
                "emits": list(m.emits),
                "role_paths_hint": {
                    "a": "roles/a.json",
                    "b": "roles/b.json" if m.needs_roles >= 2 else None,
                },
            }
        )
    return {"packs": rows, "count": len(rows)}


def programs_payload() -> dict[str, Any]:
    from sentinel_core import list_programs

    rows = list_programs()
    return {"programs": rows, "count": len(rows)}


def findings_payload(
    program_id: str,
    *,
    status: str = "all",
    pack_id: str | None = None,
) -> dict[str, Any]:
    from gungnir.packs.confirm import list_findings

    rows = list_findings(program_id, pack_id=pack_id, status=status)
    return {
        "program_id": program_id,
        "pack_id": pack_id,
        "status": status,
        "count": len(rows),
        "findings": rows,
    }


def confirm_finding_action(body: dict[str, Any]) -> dict[str, Any]:
    from gungnir.packs import ConfirmError, confirm_finding

    program_id = str(body.get("program_id") or "").strip()
    finding_id = str(body.get("finding_id") or "").strip()
    status = str(body.get("status") or "confirmed").strip()
    note = body.get("note")
    if not program_id or not finding_id:
        raise ValueError("program_id and finding_id are required")
    if not note or not str(note).strip():
        raise ValueError("note is required (human confirm gate)")
    # Never invent auto-VERIFIED from UI without human status+note path
    try:
        return confirm_finding(
            program_id,
            finding_id,
            status=status,
            note=str(note),
            mark_role=body.get("mark_role"),
            who=body.get("who"),
        )
    except ConfirmError as exc:
        raise ValueError(str(exc)) from exc


def scope_payload(program_id: str) -> dict[str, Any]:
    from sentinel_core import load_scope_text, program_dir

    root = program_dir(program_id)
    scope_path = root / "scope.txt"
    if not scope_path.is_file():
        raise FileNotFoundError(
            f"scope.txt missing for program {program_id!r}; "
            f"run: sentinel program init {program_id}"
        )
    text = scope_path.read_text(encoding="utf-8")
    scope = load_scope_text(text)
    return {
        "program_id": program_id,
        "path": str(scope_path),
        "text": text,
        "allow_count": len(scope.allow),
        "deny_count": len(scope.deny),
        "allow": list(scope.allow),
        "deny": list(scope.deny),
        "hard_kill": True,
        "hard_kill_note": (
            "Out-of-scope targets raise ScopeDenied (hard kill). "
            "Use POST .../scope/hard-kill to probe a host."
        ),
    }


def scope_write_action(
    program_id: str,
    body: dict[str, Any],
    *,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    from sentinel_core import load_scope_text, program_dir, update_program_yml_fields

    text = body.get("text")
    if text is None:
        raise ValueError("text is required (full scope.txt contents)")
    text_s = str(text)
    if len(text_s.encode("utf-8")) > 500_000:
        raise ValueError("scope text too large")
    scope = load_scope_text(text_s)
    if dry_run is None:
        dry_run = bool(body.get("dry_run"))
    root = program_dir(program_id)
    scope_path = root / "scope.txt"
    summary = {
        "program_id": program_id,
        "dry_run": bool(dry_run),
        "path": str(scope_path),
        "allow_count": len(scope.allow),
        "deny_count": len(scope.deny),
        "allow": list(scope.allow),
        "deny": list(scope.deny),
        "written": False,
    }
    if dry_run:
        return summary
    if not root.is_dir():
        raise FileNotFoundError(
            f"program {program_id!r} not found; run: sentinel program init {program_id}"
        )
    scope_path.write_text(text_s if text_s.endswith("\n") else text_s + "\n", encoding="utf-8")
    try:
        update_program_yml_fields(
            program_id,
            allow_count=len(scope.allow),
            deny_count=len(scope.deny),
        )
    except Exception:  # noqa: BLE001
        pass
    summary["written"] = True
    return summary


def scope_brief_import_action(
    program_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    """Parse brief text → scope summary; dry_run default True."""
    from sentinel_core import (
        detect_brief_platform,
        parse_brief,
        program_dir,
        scope_to_raw_text,
        update_program_yml_fields,
    )

    brief = body.get("brief") or body.get("text") or ""
    if not str(brief).strip():
        raise ValueError("brief text is required")
    platform = str(body.get("platform") or "auto").strip() or "auto"
    dry_run = body.get("dry_run")
    if dry_run is None:
        dry_run = True
    dry_run = bool(dry_run)

    detected = detect_brief_platform(str(brief))
    use_platform = platform if platform != "auto" else detected
    scope = parse_brief(str(brief), platform=use_platform)
    raw = scope_to_raw_text(scope)
    summary = {
        "program_id": program_id,
        "dry_run": dry_run,
        "platform_requested": platform,
        "platform_detected": detected,
        "platform_used": use_platform,
        "allow_count": len(scope.allow),
        "deny_count": len(scope.deny),
        "allow": list(scope.allow),
        "deny": list(scope.deny),
        "scope_text_preview": raw,
        "written": False,
    }
    if dry_run:
        return summary
    root = program_dir(program_id)
    if not root.is_dir():
        raise FileNotFoundError(f"program {program_id!r} not found")
    scope_path = root / "scope.txt"
    scope_path.write_text(raw, encoding="utf-8")
    try:
        update_program_yml_fields(
            program_id,
            platform=use_platform,
            allow_count=len(scope.allow),
            deny_count=len(scope.deny),
        )
    except Exception:  # noqa: BLE001
        pass
    summary["written"] = True
    summary["path"] = str(scope_path)
    return summary


def scope_hard_kill_probe(program_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Visible hard-kill: probe whether target host is in scope."""
    from sentinel_core import ScopeDenied, load_scope_file, program_dir

    target = str(body.get("target") or body.get("host") or "").strip()
    if not target:
        raise ValueError("target (host) is required")
    # strip URL → host if needed
    host = target
    if "://" in host:
        from urllib.parse import urlparse as _up

        host = _up(host).hostname or host
    host = host.split("/")[0].split(":")[0].strip().lower().rstrip(".")
    scope_path = program_dir(program_id) / "scope.txt"
    if not scope_path.is_file():
        raise FileNotFoundError(f"scope.txt missing for {program_id}")
    scope = load_scope_file(scope_path)
    try:
        scope.hard_kill(host)
        return {
            "program_id": program_id,
            "target": host,
            "allowed": True,
            "hard_kill": False,
            "message": f"in scope: {host}",
        }
    except ScopeDenied as exc:
        return {
            "program_id": program_id,
            "target": host,
            "allowed": False,
            "hard_kill": True,
            "message": str(exc),
        }


def report_payload(
    program_id: str,
    *,
    pack_id: str | None = None,
    all_packs: bool = False,
) -> dict[str, Any]:
    from gungnir.packs import export_report

    return export_report(
        program_id,
        pack_id=pack_id,
        all_packs=all_packs,
    )


def role_status_payload(program_id: str) -> dict[str, Any]:
    from gungnir.packs.roles import role_session_path
    from sentinel_core import program_dir

    root = program_dir(program_id)
    rows = {}
    for letter in ("a", "b"):
        p = role_session_path(program_id, letter)
        rows[letter] = {
            "path": str(p),
            "rel": f"roles/{letter}.json",
            "exists": p.is_file(),
        }
    return {"program_id": program_id, "program_dir": str(root), "roles": rows}


def _build_run_log_preamble(body: dict[str, Any], pack_id: str, program_id: str) -> list[dict]:
    from gungnir.packs.registry import get_pack
    from gungnir.packs.roles import role_session_path
    from sentinel_core import program_dir

    lines: list[dict[str, Any]] = []
    lines.append(_log_line("info", "UI pack run accepted", pack_id=pack_id, program_id=program_id))
    try:
        entry = get_pack(pack_id)
        manifest = entry["manifest"]
        lines.append(
            _log_line(
                "info",
                "pack manifest",
                pack_id=pack_id,
                pack_class=manifest.pack_class,
                needs_roles=manifest.needs_roles,
                noise_class=manifest.noise_class,
            )
        )
        for letter in ("a", "b"):
            if letter == "b" and manifest.needs_roles < 2:
                continue
            p = role_session_path(program_id, letter)
            lines.append(
                _log_line(
                    "info",
                    f"role {letter.upper()} path check",
                    role=letter,
                    path=str(p),
                    exists=p.is_file(),
                    required=manifest.needs_roles >= (1 if letter == "a" else 2),
                )
            )
    except Exception as exc:  # noqa: BLE001
        lines.append(_log_line("warn", f"manifest/role probe: {exc}", pack_id=pack_id))

    scope_path = body.get("scope_path")
    prog_scope = program_dir(program_id) / "scope.txt"
    lines.append(
        _log_line(
            "info",
            "ownership / scope gate",
            i_own_this=bool(body.get("i_own_this")),
            i_understand_lab=bool(body.get("i_understand_lab")),
            scope_path=str(scope_path) if scope_path else None,
            program_scope_exists=prog_scope.is_file(),
            hard_kill="enabled when scope loaded",
        )
    )
    return lines


def _append_run_log_from_result(lines: list[dict], result: dict[str, Any]) -> None:
    lines.append(
        _log_line(
            "info",
            "pack finished",
            pack_id=result.get("pack_id"),
            findings_emitted=result.get("findings_emitted"),
            flows_emitted=result.get("flows_emitted"),
            steps_emitted=result.get("steps_emitted"),
            surface_candidates=result.get("surface_candidates"),
            candidates_in=result.get("candidates_in"),
            roles_loaded=result.get("roles_loaded"),
            scoped=result.get("scoped"),
        )
    )
    for hint in result.get("hints") or []:
        lines.append(_log_line("hint", str(hint)))
    for note in result.get("pack_notes") or []:
        lines.append(_log_line("note", str(note)))
    # Never claim VERIFIED from pack emit
    for ev in result.get("events") or []:
        ver = (ev.get("verification") or ev.get("verification_status") or "").lower()
        lines.append(
            _log_line(
                "finding",
                ev.get("title") or ev.get("id") or "finding",
                finding_id=ev.get("id"),
                verification=ver or "needs_human",
            )
        )
        if ver in ("verified", "confirmed"):
            lines.append(
                _log_line(
                    "warn",
                    "unexpected confirmed/verified on pack emit — human gate required",
                    finding_id=ev.get("id"),
                )
            )


def pack_run_action(body: dict[str, Any]) -> dict[str, Any]:
    """Run a hunt pack — requires i_own_this (no silent live runs). Returns denser log."""
    from gungnir.packs import PackRunError, run_pack
    from sentinel_core import ScopeDenied

    pack_id = str(body.get("pack_id") or "").strip()
    program_id = str(body.get("program_id") or "").strip()
    i_own_this = bool(body.get("i_own_this"))
    scope_path = body.get("scope_path")
    scope_path = str(scope_path).strip() if scope_path else None
    i_understand_lab = bool(body.get("i_understand_lab"))
    role_a_path = body.get("role_a_path") or body.get("role_a")
    role_b_path = body.get("role_b_path") or body.get("role_b")
    role_a_path = str(role_a_path).strip() if role_a_path else None
    role_b_path = str(role_b_path).strip() if role_b_path else None

    if not pack_id or not program_id:
        raise ValueError("pack_id and program_id are required")
    if not i_own_this and not scope_path:
        raise ValueError(
            "ownership required: set i_own_this=true and/or provide scope_path "
            "(no silent live runs from the UI)"
        )
    if not i_own_this:
        raise ValueError(
            "UI pack run requires i_own_this acknowledgment "
            "(check the ownership box); scope_path alone is not enough from the UI"
        )

    log_lines = _build_run_log_preamble(body, pack_id, program_id)
    try:
        result = run_pack(
            pack_id,
            program_id,
            scope_path=scope_path,
            i_own_this=True,
            i_understand_lab=i_understand_lab,
            urls=body.get("urls") or None,
            role_a_path=role_a_path,
            role_b_path=role_b_path,
        )
    except PackRunError as exc:
        log_lines.append(_log_line("error", str(exc), pack_id=pack_id))
        raise ValueError(str(exc)) from exc
    except ScopeDenied as exc:
        log_lines.append(_log_line("error", f"scope denied (hard kill): {exc}"))
        raise ValueError(f"scope denied: {exc}") from exc

    _append_run_log_from_result(log_lines, result)
    out = dict(result)
    out["log_lines"] = log_lines
    out["human_gate"] = (
        "Findings stay needs_human/unverified until confirm-finding — never auto-VERIFIED."
    )
    return out


def start_pack_run_job(body: dict[str, Any]) -> dict[str, Any]:
    """Background UI run with pollable log + cooperative stop."""
    global _active_run_id

    pack_id = str(body.get("pack_id") or "").strip()
    program_id = str(body.get("program_id") or "").strip()
    if not pack_id or not program_id:
        raise ValueError("pack_id and program_id are required")
    if not bool(body.get("i_own_this")):
        raise ValueError(
            "UI pack run requires i_own_this acknowledgment "
            "(check the ownership box)"
        )

    run_id = uuid.uuid4().hex[:12]
    cancel = threading.Event()
    state: dict[str, Any] = {
        "run_id": run_id,
        "status": "queued",
        "pack_id": pack_id,
        "program_id": program_id,
        "log_lines": _build_run_log_preamble(body, pack_id, program_id),
        "result": None,
        "error": None,
        "cancel_requested": False,
        "started_at": _ts(),
        "finished_at": None,
    }

    with _runs_lock:
        if _active_run_id and _runs.get(_active_run_id, {}).get("status") in (
            "queued",
            "running",
        ):
            raise ValueError(
                f"another UI pack run is in flight (run_id={_active_run_id}); "
                "POST /api/pack/stop first"
            )
        _runs[run_id] = state
        _active_run_id = run_id

    def _worker() -> None:
        global _active_run_id
        state["status"] = "running"
        state["log_lines"].append(_log_line("info", "worker started", run_id=run_id))
        if cancel.is_set():
            state["status"] = "stopped"
            state["cancel_requested"] = True
            state["finished_at"] = _ts()
            state["log_lines"].append(_log_line("warn", "stopped before pack start"))
            return
        try:
            result = pack_run_action(body)
            # pack_run_action already built log; merge uniquely by appending delta note
            state["result"] = result
            # Prefer denser log from result
            if result.get("log_lines"):
                state["log_lines"] = list(result["log_lines"])
            if cancel.is_set():
                state["status"] = "stopped"
                state["cancel_requested"] = True
                state["log_lines"].append(
                    _log_line("warn", "stop requested; pack already finished")
                )
            else:
                state["status"] = "done"
        except ValueError as exc:
            state["error"] = str(exc)
            state["status"] = "error"
            state["log_lines"].append(_log_line("error", str(exc)))
        except Exception as exc:  # noqa: BLE001
            state["error"] = str(exc)
            state["status"] = "error"
            state["log_lines"].append(_log_line("error", str(exc)))
            traceback.print_exc()
        finally:
            state["finished_at"] = _ts()
            with _runs_lock:
                if _active_run_id == run_id:
                    _active_run_id = None

    # Attach cancel event for stop
    state["_cancel"] = cancel
    threading.Thread(target=_worker, daemon=True, name=f"ui-pack-{run_id}").start()
    return {
        "ok": True,
        "run_id": run_id,
        "status": "queued",
        "pack_id": pack_id,
        "program_id": program_id,
        "poll": f"/api/pack/run/{run_id}",
        "stop": "/api/pack/stop",
    }


def get_pack_run_job(run_id: str) -> dict[str, Any]:
    with _runs_lock:
        state = _runs.get(run_id)
    if not state:
        raise FileNotFoundError(f"unknown run_id: {run_id}")
    return {
        "run_id": state["run_id"],
        "status": state["status"],
        "pack_id": state["pack_id"],
        "program_id": state["program_id"],
        "log_lines": list(state.get("log_lines") or []),
        "result": state.get("result"),
        "error": state.get("error"),
        "cancel_requested": bool(state.get("cancel_requested")),
        "started_at": state.get("started_at"),
        "finished_at": state.get("finished_at"),
    }


def stop_pack_run(body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Visible hard-kill control for in-flight UI-triggered runs."""
    global _active_run_id
    body = body or {}
    run_id = str(body.get("run_id") or "").strip() or _active_run_id
    with _runs_lock:
        if not run_id or run_id not in _runs:
            return {
                "ok": True,
                "stopped": False,
                "message": "no in-flight UI pack run",
                "active_run_id": _active_run_id,
            }
        state = _runs[run_id]
        cancel = state.get("_cancel")
        if cancel is not None:
            cancel.set()
        state["cancel_requested"] = True
        state["log_lines"].append(
            _log_line("warn", "stop requested (UI hard-kill control)", run_id=run_id)
        )
        if state["status"] in ("queued",):
            state["status"] = "stopped"
            state["finished_at"] = _ts()
        return {
            "ok": True,
            "stopped": True,
            "run_id": run_id,
            "status": state["status"],
            "message": (
                "Stop signaled. Cooperative cancel — takes effect before start "
                "or after current pack returns (stdlib thread)."
            ),
        }


_MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".map": "application/json",
    ".md": "text/markdown; charset=utf-8",
}


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


def _window_to_timedelta(window: str) -> Any:
    """Return timedelta for 24h/7d, or None for latest-vs-previous."""
    from datetime import timedelta

    w = (window or "24h").strip().lower()
    if w in ("24h", "1d", "day", "last_24h"):
        return timedelta(hours=24)
    if w in ("7d", "week", "last_7d"):
        return timedelta(days=7)
    if w in ("latest", "last", "prev", "previous"):
        return None
    raise ValueError("window must be one of: 24h, 7d, latest")


def _load_watch_history(program_root: Path) -> list[dict[str, Any]]:
    """Load history snapshots newest-first (includes latest.json when present)."""
    import json

    from shadowseye.watch import load_latest_snapshot, runs_dir

    rows: list[dict[str, Any]] = []
    seen_ts: set[str] = set()
    latest = load_latest_snapshot(program_root)
    if latest:
        ts = str(latest.get("ts") or "")
        rows.append(latest)
        if ts:
            seen_ts.add(ts)
    hist = runs_dir(program_root) / "history"
    if hist.is_dir():
        files = sorted(hist.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for fp in files:
            try:
                data = json.loads(fp.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            ts = str(data.get("ts") or "")
            if ts and ts in seen_ts:
                continue
            if ts:
                seen_ts.add(ts)
            data = dict(data)
            data["_path"] = str(fp)
            rows.append(data)
    # Sort by parsed ts descending
    def _key(r: dict[str, Any]) -> float:
        dt = _parse_iso_ts(r.get("ts"))
        return dt.timestamp() if dt else 0.0

    rows.sort(key=_key, reverse=True)
    return rows


def assets_payload(
    program_id: str,
    *,
    kind: str = "all",
    q: str = "",
    min_score: float | None = None,
) -> dict[str, Any]:
    """
    Read-only Eye inventory tables from the program graph.

    kind: all|domain|dns|ip|port|url
    Empty graph → honest empty tables (no fabricated rows).
    """
    from shadowseye.ranker import score_asset, score_hostname
    from sentinel_core import open_graph

    kind_l = (kind or "all").strip().lower()
    allowed = {"all", "domain", "dns", "dns_name", "ip", "port", "open_port", "url"}
    if kind_l not in allowed:
        raise ValueError(f"kind must be one of all/domain/dns/ip/port/url, got {kind!r}")
    q_l = (q or "").strip().lower()

    try:
        graph = open_graph(program_id)
    except FileNotFoundError:
        return {
            "program_id": program_id,
            "kind": kind_l,
            "q": q,
            "count": 0,
            "assets": [],
            "counts": {"domain": 0, "dns": 0, "ip": 0, "port": 0, "url": 0},
            "empty": True,
            "message": (
                f"No graph for program {program_id!r}. "
                f"Run: sentinel program init {program_id} && sentinel eye run …"
            ),
        }

    rows: list[dict[str, Any]] = []

    def _push(
        *,
        row_kind: str,
        name: str,
        score: float,
        reasons: list[str],
        first_seen: Any,
        last_seen: Any,
        event_id: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        rows.append(
            {
                "kind": row_kind,
                "name": name,
                "score": round(float(score), 2),
                "reasons": list(reasons or []),
                "first_seen": first_seen.isoformat()
                if hasattr(first_seen, "isoformat")
                else first_seen,
                "last_seen": last_seen.isoformat()
                if hasattr(last_seen, "isoformat")
                else last_seen,
                "event_id": event_id,
                **(extra or {}),
            }
        )

    for ev in graph.list_by_type("DOMAIN"):
        domain = str((ev.payload or {}).get("domain") or "").strip()
        if not domain:
            continue
        score, reasons = score_hostname(domain, first_seen=ev.first_seen)
        _push(
            row_kind="domain",
            name=domain,
            score=score,
            reasons=reasons,
            first_seen=ev.first_seen,
            last_seen=ev.last_seen,
            event_id=ev.id,
        )

    for ev in graph.list_by_type("DNS_NAME"):
        name = str((ev.payload or {}).get("name") or "").strip()
        if not name:
            continue
        score, reasons = score_hostname(name, first_seen=ev.first_seen)
        _push(
            row_kind="dns",
            name=name,
            score=score,
            reasons=reasons,
            first_seen=ev.first_seen,
            last_seen=ev.last_seen,
            event_id=ev.id,
        )

    for ev in graph.list_by_type("IP"):
        ip = str((ev.payload or {}).get("ip") or "").strip()
        if not ip:
            continue
        host = (ev.payload or {}).get("host")
        asset = {"key": ip, "ip": ip, "host": host, "first_seen": ev.first_seen}
        score, reasons = score_asset(asset)
        # Prefer host interestingness when present
        if host:
            hs, hr = score_hostname(str(host), first_seen=ev.first_seen)
            if hs > score:
                score, reasons = hs, hr + ["via_host"]
        _push(
            row_kind="ip",
            name=ip,
            score=score,
            reasons=reasons,
            first_seen=ev.first_seen,
            last_seen=ev.last_seen,
            event_id=ev.id,
            extra={"host": host},
        )

    for ev in graph.list_by_type("OPEN_PORT"):
        host = str((ev.payload or {}).get("host") or "").strip()
        port = (ev.payload or {}).get("port")
        if not host or port is None:
            continue
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            continue
        label = f"{host}:{port_i}"
        score, reasons = score_hostname(host, first_seen=ev.first_seen)
        service = (ev.payload or {}).get("service")
        _push(
            row_kind="port",
            name=label,
            score=score,
            reasons=reasons,
            first_seen=ev.first_seen,
            last_seen=ev.last_seen,
            event_id=ev.id,
            extra={"host": host, "port": port_i, "service": service},
        )

    for ev in graph.list_by_type("URL"):
        url = str((ev.payload or {}).get("url") or "").strip()
        if not url:
            continue
        asset = {
            "url": url,
            "first_seen": ev.first_seen,
            "title": (ev.payload or {}).get("title"),
        }
        score, reasons = score_asset(asset)
        _push(
            row_kind="url",
            name=url,
            score=score,
            reasons=reasons,
            first_seen=ev.first_seen,
            last_seen=ev.last_seen,
            event_id=ev.id,
            extra={
                "status": (ev.payload or {}).get("status"),
                "title": (ev.payload or {}).get("title"),
            },
        )

    # Close graph if supported
    close = getattr(graph, "close", None)
    if callable(close):
        close()

    kind_map = {
        "domain": "domain",
        "dns": "dns",
        "dns_name": "dns",
        "ip": "ip",
        "port": "port",
        "open_port": "port",
        "url": "url",
    }
    if kind_l != "all":
        want = kind_map[kind_l]
        rows = [r for r in rows if r["kind"] == want]
    if q_l:
        rows = [
            r
            for r in rows
            if q_l in str(r.get("name") or "").lower()
            or q_l in str(r.get("host") or "").lower()
            or q_l in str(r.get("title") or "").lower()
        ]
    if min_score is not None:
        rows = [r for r in rows if float(r.get("score") or 0) >= float(min_score)]

    rows.sort(key=lambda r: (-float(r.get("score") or 0), r.get("kind") or "", r.get("name") or ""))

    counts = {"domain": 0, "dns": 0, "ip": 0, "port": 0, "url": 0}
    for r in rows:
        k = r["kind"]
        if k in counts:
            counts[k] += 1

    empty = len(rows) == 0
    message = None
    if empty and kind_l == "all" and not q_l and min_score is None:
        message = (
            "No inventory events on the graph yet. "
            "Run ShadowsEye (`sentinel eye run`) against an owned/scoped target — "
            "this screen never fabricates assets."
        )
    elif empty:
        message = "No assets match the current filters."

    return {
        "program_id": program_id,
        "kind": kind_l,
        "q": q,
        "min_score": min_score,
        "count": len(rows),
        "counts": counts,
        "assets": rows,
        "empty": empty,
        "message": message,
    }


def _flatten_watch_diffs(diffs: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn watch diff buckets into ranked delta rows."""
    from shadowseye.ranker import score_asset, score_hostname

    out: list[dict[str, Any]] = []

    def _add(kind: str, change: str, name: str, extra: dict[str, Any] | None = None) -> None:
        if kind in ("dns", "domain") or (kind == "http"):
            score, reasons = score_hostname(name.split("://")[-1].split("/")[0] if "://" in name else name)
        elif kind == "port" and extra and extra.get("host"):
            score, reasons = score_hostname(str(extra["host"]))
        else:
            score, reasons = score_asset({"key": name, **(extra or {})})
        # Prefer additions slightly for ranking visibility
        if change == "added":
            score = float(score) + 2.0
            reasons = list(reasons) + ["delta:added"]
        else:
            reasons = list(reasons) + ["delta:removed"]
        out.append(
            {
                "kind": kind,
                "change": change,
                "name": name,
                "score": round(float(score), 2),
                "reasons": reasons,
                **(extra or {}),
            }
        )

    for change in ("added", "removed"):
        for name in diffs.get("dns_names", {}).get(change) or []:
            _add("dns", change, str(name))
        for row in diffs.get("ports", {}).get(change) or []:
            if isinstance(row, dict):
                host = str(row.get("host") or "")
                try:
                    port = int(row.get("port"))
                except (TypeError, ValueError):
                    continue
                _add("port", change, f"{host}:{port}", {"host": host, "port": port})
            else:
                _add("port", change, str(row))
        for url in diffs.get("http", {}).get(change) or []:
            _add("http", change, str(url))
        for tech in diffs.get("tech", {}).get(change) or []:
            _add("tech", change, str(tech), {"tech": str(tech)})

    out.sort(key=lambda r: (-float(r.get("score") or 0), r.get("change") or "", r.get("name") or ""))
    return out


def changes_payload(program_id: str, *, window: str = "24h") -> dict[str, Any]:
    """
    Interestingness-ranked watch deltas for 24h / 7d / latest-vs-previous.

    Missing runs/ store → honest empty + message (never invent diffs).
    """
    from shadowseye.watch import diff_snapshots, load_latest_snapshot, runs_dir
    from sentinel_core import program_dir

    root = program_dir(program_id)
    if not root.is_dir():
        raise FileNotFoundError(
            f"program {program_id!r} not found; run: sentinel program init {program_id}"
        )

    delta = _window_to_timedelta(window)
    window_l = (window or "24h").strip().lower()
    if window_l in ("1d", "day", "last_24h"):
        window_l = "24h"
    elif window_l in ("week", "last_7d"):
        window_l = "7d"
    elif window_l in ("last", "prev", "previous"):
        window_l = "latest"

    runs = runs_dir(root)
    latest_path = runs / "latest.json"
    history = _load_watch_history(root)
    latest = load_latest_snapshot(root)

    empty_base = {
        "program_id": program_id,
        "window": window_l,
        "count": 0,
        "deltas": [],
        "empty": True,
        "diffs": None,
        "baseline_ts": None,
        "current_ts": (latest or {}).get("ts") if latest else None,
        "history_count": len(history),
        "store_path": str(runs),
    }

    if not latest_path.is_file() and not history:
        return {
            **empty_base,
            "message": (
                "No watch store yet (runs/latest.json missing). "
                "Run ShadowsEye with --watch to persist snapshots — "
                "Changes never invents diffs."
            ),
        }

    if latest is None:
        return {
            **empty_base,
            "message": "Watch store unreadable or empty.",
        }

    baseline: dict[str, Any] | None = None
    note = None
    now = datetime.now(timezone.utc)

    if delta is None:
        # latest vs previous in history
        if len(history) < 2:
            return {
                **empty_base,
                "current_ts": latest.get("ts"),
                "message": (
                    "Only one watch snapshot on disk — need a prior run to diff. "
                    "Re-run eye with --watch after the surface changes."
                ),
            }
        baseline = history[1]
    else:
        cutoff = now - delta
        # Prefer the newest snapshot at or before cutoff
        candidates = []
        for snap in history:
            ts = _parse_iso_ts(snap.get("ts"))
            if ts is None:
                continue
            if ts <= cutoff:
                candidates.append(snap)
        if candidates:
            # history is newest-first; first candidate that is <= cutoff is newest such
            baseline = candidates[0]
        else:
            # No snapshot old enough — honest empty for this window
            return {
                **empty_base,
                "current_ts": latest.get("ts"),
                "message": (
                    f"No watch snapshot older than {window_l} "
                    f"(cutoff {cutoff.isoformat()}). "
                    "Older history will unlock this window; "
                    "try window=latest for previous-run diff."
                ),
            }

    diffs = diff_snapshots(baseline, latest)
    deltas = _flatten_watch_diffs(diffs)
    empty = len(deltas) == 0
    if empty:
        note = (
            f"No added/removed deltas vs baseline ({baseline.get('ts')}) "
            f"for window={window_l}."
        )

    return {
        "program_id": program_id,
        "window": window_l,
        "count": len(deltas),
        "deltas": deltas,
        "empty": empty,
        "message": note,
        "diffs": diffs,
        "baseline_ts": baseline.get("ts") if baseline else None,
        "current_ts": latest.get("ts"),
        "history_count": len(history),
        "store_path": str(runs),
        "first_run": bool(diffs.get("first_run")),
    }


def modules_payload() -> dict[str, Any]:
    """
    Read-only module/pack catalog from on-disk hunt pack manifests.

    No install/publish — Phase C freeze (12 packs).
    """
    from gungnir.packs import list_pack_manifests

    packs = list_pack_manifests()
    modules: list[dict[str, Any]] = []
    for m in packs:
        modules.append(
            {
                "id": m.id,
                "type": "hunt_pack",
                "class": m.pack_class,
                "version": m.version,
                "description": m.description,
                "needs_roles": m.needs_roles,
                "noise_class": m.noise_class,
                "consumes": list(m.consumes),
                "emits": list(m.emits),
                "installable": False,
                "status": "bundled",
            }
        )
    modules.sort(key=lambda r: r["id"])
    return {
        "modules": modules,
        "count": len(modules),
        "pack_count": len(modules),
        "installable": False,
        "message": (
            "Read-only catalog of bundled hunt packs (Phase C freeze: 12). "
            "Install/publish is not available in D2."
        ),
    }



_MUTATING_PREFIXES = (
    "/api/pack/run",
    "/api/pack/stop",
    "/api/hunt/pack-run",
    "/api/confirm-finding",
)


def _is_mutating_path(path: str, method: str) -> bool:
    if method == "POST":
        if path in _MUTATING_PREFIXES or path.startswith("/api/pack/run"):
            return True
        if path.endswith("/scope") or "/scope/" in path:
            # POST brief / hard-kill
            if path.rstrip("/").endswith("/brief") or path.rstrip("/").endswith(
                "/hard-kill"
            ):
                return True
        if path == "/api/confirm-finding":
            return True
    if method == "PUT":
        if path.endswith("/scope"):
            return True
    return False


class UIRequestHandler(BaseHTTPRequestHandler):
    """Serves SPA static files + JSON API under /api/*."""

    static_root: Path = Path(".")
    server_version = "SentinelUI/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, code: int, payload: Any) -> None:
        raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_text(self, code: int, text: str, content_type: str) -> None:
        raw = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > 1_000_000:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def _gate_mutating(self, path: str, method: str) -> bool:
        """Return True if request may proceed; False if response already sent."""
        if not _is_mutating_path(path, method):
            return True
        try:
            require_mutating_auth(self.headers)
            return True
        except UIAuthError as exc:
            self._send_json(
                exc.status,
                {
                    "ok": False,
                    "error": str(exc),
                    "code": exc.code,
                },
            )
            return False

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path or "/"

        if path.startswith("/api/"):
            self._handle_api_get(path, parsed)
            return

        self._serve_static(path)

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        if not path.startswith("/api/"):
            self._send_json(404, {"error": "not found"})
            return
        if not self._gate_mutating(path, "PUT"):
            return
        try:
            body = self._read_json_body()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
            return
        try:
            # /api/programs/<id>/scope
            parts = path.strip("/").split("/")
            if (
                len(parts) == 4
                and parts[0] == "api"
                and parts[1] == "programs"
                and parts[3] == "scope"
            ):
                result = scope_write_action(parts[2], body)
                self._send_json(200, {"ok": True, "result": result})
                return
            self._send_json(404, {"error": f"unknown API route {path}"})
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
        except FileNotFoundError as exc:
            self._send_json(404, {"ok": False, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            self._send_json(500, {"ok": False, "error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        if not path.startswith("/api/"):
            self._send_json(404, {"error": "not found"})
            return

        # Auth setup/login are not gated by require_mutating_auth
        auth_open = path in (
            "/api/auth/setup",
            "/api/auth/login",
            "/api/auth/logout",
        )
        if not auth_open and not self._gate_mutating(path, "POST"):
            return

        try:
            body = self._read_json_body()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
            return

        try:
            if path == "/api/auth/setup":
                result = setup_auth(
                    action=str(body.get("action") or ""),
                    password=body.get("password"),
                    force=bool(body.get("force")),
                )
                self._send_json(200, result)
                return
            if path == "/api/auth/login":
                result = auth_login(str(body.get("password") or ""))
                self._send_json(200, result)
                return
            if path == "/api/auth/logout":
                token = extract_bearer(self.headers) or body.get("token")
                self._send_json(200, auth_logout(str(token) if token else None))
                return
            if path == "/api/confirm-finding":
                result = confirm_finding_action(body)
                self._send_json(200, {"ok": True, "result": result})
                return
            if path in ("/api/pack/run", "/api/hunt/pack-run"):
                # async=true → background job; else sync (D0 compat) with log_lines
                if body.get("async") or body.get("background"):
                    job = start_pack_run_job(body)
                    self._send_json(200, job)
                    return
                result = pack_run_action(body)
                self._send_json(200, {"ok": True, "result": result})
                return
            if path == "/api/pack/stop":
                self._send_json(200, stop_pack_run(body))
                return

            parts = path.strip("/").split("/")
            # /api/programs/<id>/scope/brief
            if (
                len(parts) == 5
                and parts[0] == "api"
                and parts[1] == "programs"
                and parts[3] == "scope"
                and parts[4] == "brief"
            ):
                result = scope_brief_import_action(parts[2], body)
                self._send_json(200, {"ok": True, "result": result})
                return
            # /api/programs/<id>/scope/hard-kill
            if (
                len(parts) == 5
                and parts[0] == "api"
                and parts[1] == "programs"
                and parts[3] == "scope"
                and parts[4] == "hard-kill"
            ):
                result = scope_hard_kill_probe(parts[2], body)
                self._send_json(200, {"ok": True, "result": result})
                return

            self._send_json(404, {"error": f"unknown API route {path}"})
        except UIAuthError as exc:
            self._send_json(
                exc.status, {"ok": False, "error": str(exc), "code": exc.code}
            )
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
        except FileNotFoundError as exc:
            self._send_json(404, {"ok": False, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            self._send_json(500, {"ok": False, "error": str(exc)})

    def _handle_api_get(self, path: str, parsed: Any) -> None:
        qs = parse_qs(parsed.query or "")
        try:
            if path == "/api/doctor":
                self._send_json(200, doctor_status())
                return
            if path == "/api/programs":
                self._send_json(200, programs_payload())
                return
            if path == "/api/packs":
                self._send_json(200, packs_payload())
                return
            if path == "/api/modules":
                self._send_json(200, modules_payload())
                return
            if path == "/api/auth/status":
                self._send_json(200, auth_status())
                return
            if path == "/api/health":
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "service": "sentinel-ui",
                        "phase": "D2",
                        "default_bind": DEFAULT_UI_BIND,
                        "default_port": DEFAULT_UI_PORT,
                    },
                )
                return
            if path.startswith("/api/pack/run/"):
                run_id = path.rsplit("/", 1)[-1]
                self._send_json(200, get_pack_run_job(run_id))
                return

            parts = path.strip("/").split("/")
            # /api/programs/<id>/findings
            if (
                len(parts) == 4
                and parts[0] == "api"
                and parts[1] == "programs"
                and parts[3] == "findings"
            ):
                pid = parts[2]
                status = (qs.get("status") or ["all"])[0]
                pack_id = (qs.get("pack_id") or [None])[0]
                self._send_json(
                    200,
                    findings_payload(pid, status=status, pack_id=pack_id),
                )
                return
            # /api/programs/<id>/scope
            if (
                len(parts) == 4
                and parts[0] == "api"
                and parts[1] == "programs"
                and parts[3] == "scope"
            ):
                self._send_json(200, scope_payload(parts[2]))
                return
            # /api/programs/<id>/roles
            if (
                len(parts) == 4
                and parts[0] == "api"
                and parts[1] == "programs"
                and parts[3] == "roles"
            ):
                self._send_json(200, role_status_payload(parts[2]))
                return

            # /api/programs/<id>/assets
            if (
                len(parts) == 4
                and parts[0] == "api"
                and parts[1] == "programs"
                and parts[3] == "assets"
            ):
                pid = parts[2]
                kind = (qs.get("kind") or ["all"])[0]
                q = (qs.get("q") or [""])[0]
                min_raw = (qs.get("min_score") or [None])[0]
                min_score = float(min_raw) if min_raw not in (None, "") else None
                self._send_json(
                    200,
                    assets_payload(pid, kind=kind, q=q, min_score=min_score),
                )
                return
            # /api/programs/<id>/changes
            if (
                len(parts) == 4
                and parts[0] == "api"
                and parts[1] == "programs"
                and parts[3] == "changes"
            ):
                pid = parts[2]
                window = (qs.get("window") or ["24h"])[0]
                self._send_json(200, changes_payload(pid, window=window))
                return

            # /api/programs/<id>/report
            if (
                len(parts) == 4
                and parts[0] == "api"
                and parts[1] == "programs"
                and parts[3] == "report"
            ):
                pid = parts[2]
                pack_id = (qs.get("pack_id") or [None])[0]
                all_packs = (qs.get("all_packs") or ["0"])[0].lower() in (
                    "1",
                    "true",
                    "yes",
                )
                fmt = (qs.get("format") or ["json"])[0].lower()
                report = report_payload(
                    pid, pack_id=pack_id, all_packs=all_packs or not pack_id
                )
                if fmt == "markdown" or fmt == "md":
                    self._send_text(
                        200,
                        report.get("markdown") or "",
                        "text/markdown; charset=utf-8",
                    )
                    return
                self._send_json(200, report)
                return

            self._send_json(404, {"error": f"unknown API route {path}"})
        except FileNotFoundError as exc:
            self._send_json(404, {"ok": False, "error": str(exc)})
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            self._send_json(500, {"ok": False, "error": str(exc)})

    def _serve_static(self, path: str) -> None:
        root = self.static_root.resolve()
        rel = path.lstrip("/") or "index.html"
        candidate = (root / rel).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            self.send_error(403, "forbidden")
            return
        if not candidate.is_file():
            candidate = root / "index.html"
        if not candidate.is_file():
            self.send_error(404, "UI not found")
            return
        data = candidate.read_bytes()
        ctype = _MIME.get(candidate.suffix.lower(), "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def make_handler(static_root: Path) -> type[UIRequestHandler]:
    class BoundHandler(UIRequestHandler):
        pass

    BoundHandler.static_root = static_root
    return BoundHandler


def serve_ui(
    *,
    bind: str | None = None,
    port: int | None = None,
    i_understand_lab: bool = False,
    static_root: Path | None = None,
) -> dict[str, Any]:
    """
    Start the local UI HTTP server (blocking).

    Default bind 127.0.0.1:8888. Non-loopback requires i_understand_lab.
    """
    host = assert_ui_bind_allowed(bind, i_understand_lab=i_understand_lab)
    listen_port = int(port if port is not None else DEFAULT_UI_PORT)
    root = static_root or resolve_ui_static_root()
    handler = make_handler(root)
    httpd = ThreadingHTTPServer((host, listen_port), handler)
    url = f"http://{host}:{listen_port}/"
    summary = {
        "bind": host,
        "port": listen_port,
        "url": url,
        "static_root": str(root),
        "i_understand_lab": bool(i_understand_lab),
        "default_bind": DEFAULT_UI_BIND,
        "default_port": DEFAULT_UI_PORT,
        "phase": "D2",
    }
    print(json.dumps({"event": "ui_listening", **summary}, indent=2), flush=True)
    print(f"Sentinel UI → {url}", flush=True)
    print("Ctrl+C to stop.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down ui…", flush=True)
    finally:
        httpd.server_close()
    return summary


__all__ = [
    "COACH_UI_BIND_NON_LOOPBACK",
    "DEFAULT_UI_BIND",
    "DEFAULT_UI_PORT",
    "UIBindError",
    "assert_ui_bind_allowed",
    "confirm_finding_action",
    "doctor_status",
    "get_pack_run_job",
    "is_loopback_bind",
    "pack_run_action",
    "packs_payload",
    "modules_payload",
    "changes_payload",
    "assets_payload",
    "programs_payload",
    "report_payload",
    "resolve_ui_static_root",
    "scope_brief_import_action",
    "scope_hard_kill_probe",
    "scope_payload",
    "scope_write_action",
    "serve_ui",
    "start_pack_run_job",
    "stop_pack_run",
]
