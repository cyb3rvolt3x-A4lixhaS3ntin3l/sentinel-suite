"""Phase D0 — local UI shell (stdlib HTTP, bind 127.0.0.1:8888 by default)."""

from __future__ import annotations

import json
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

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


def pack_run_action(body: dict[str, Any]) -> dict[str, Any]:
    """Run a hunt pack — requires i_own_this and/or scope_path (no silent live runs)."""
    from gungnir.packs import PackRunError, run_pack
    from sentinel_core import ScopeDenied

    pack_id = str(body.get("pack_id") or "").strip()
    program_id = str(body.get("program_id") or "").strip()
    i_own_this = bool(body.get("i_own_this"))
    scope_path = body.get("scope_path")
    scope_path = str(scope_path).strip() if scope_path else None
    i_understand_lab = bool(body.get("i_understand_lab"))

    if not pack_id or not program_id:
        raise ValueError("pack_id and program_id are required")
    if not i_own_this and not scope_path:
        raise ValueError(
            "ownership required: set i_own_this=true and/or provide scope_path "
            "(no silent live runs from the UI)"
        )
    # UI form must explicitly acknowledge ownership even when scope_path is set
    # (defense-in-depth vs silent clicks).
    if not i_own_this:
        raise ValueError(
            "UI pack run requires i_own_this acknowledgment "
            "(check the ownership box); scope_path alone is not enough from the UI"
        )

    try:
        return run_pack(
            pack_id,
            program_id,
            scope_path=scope_path,
            i_own_this=True,
            i_understand_lab=i_understand_lab,
            urls=body.get("urls") or None,
        )
    except PackRunError as exc:
        raise ValueError(str(exc)) from exc
    except ScopeDenied as exc:
        raise ValueError(f"scope denied: {exc}") from exc


_MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".map": "application/json",
}


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

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path or "/"

        if path.startswith("/api/"):
            self._handle_api_get(path, parsed)
            return

        self._serve_static(path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        if not path.startswith("/api/"):
            self._send_json(404, {"error": "not found"})
            return
        try:
            body = self._read_json_body()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
            return

        try:
            if path == "/api/confirm-finding":
                result = confirm_finding_action(body)
                self._send_json(200, {"ok": True, "result": result})
                return
            if path in ("/api/pack/run", "/api/hunt/pack-run"):
                result = pack_run_action(body)
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
            if path.startswith("/api/programs/") and path.endswith("/findings"):
                # /api/programs/<id>/findings
                parts = path.strip("/").split("/")
                # api, programs, <id>, findings
                if len(parts) == 4 and parts[0] == "api" and parts[1] == "programs":
                    pid = parts[2]
                    status = (qs.get("status") or ["all"])[0]
                    pack_id = (qs.get("pack_id") or [None])[0]
                    self._send_json(
                        200,
                        findings_payload(pid, status=status, pack_id=pack_id),
                    )
                    return
            if path == "/api/health":
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "service": "sentinel-ui",
                        "default_bind": DEFAULT_UI_BIND,
                        "default_port": DEFAULT_UI_PORT,
                    },
                )
                return
            self._send_json(404, {"error": f"unknown API route {path}"})
        except FileNotFoundError as exc:
            self._send_json(404, {"ok": False, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            self._send_json(500, {"ok": False, "error": str(exc)})

    def _serve_static(self, path: str) -> None:
        root = self.static_root.resolve()
        rel = path.lstrip("/") or "index.html"
        # SPA fallback: unknown paths → index.html (no path traversal)
        candidate = (root / rel).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            self.send_error(403, "forbidden")
            return
        if not candidate.is_file():
            # client-side routes → index
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
    "doctor_status",
    "is_loopback_bind",
    "resolve_ui_static_root",
    "serve_ui",
]
