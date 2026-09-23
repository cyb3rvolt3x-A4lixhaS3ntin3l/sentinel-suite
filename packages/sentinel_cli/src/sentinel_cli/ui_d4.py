"""Phase D4 — OSINT graph, Surface map, Auth lab, Workbench, Tauri status.

Read-only viz/catalog helpers + gated workbench send. Never invents graph rows.
Never silent-live: workbench send requires i_own_this + scope hard-kill.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

# --- OpenAPI / surface path heuristics (no network) ---
_OPENAPI_PATH_HINTS = (
    "/openapi",
    "/openapi.json",
    "/openapi.yaml",
    "/swagger",
    "/swagger.json",
    "/swagger-ui",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/.well-known/openapi",
)

_JS_EXT = (".js", ".mjs", ".cjs")
_PARAM_RE = re.compile(r"\{([^}/]+)\}|/\:([A-Za-z_][\w]*)")


def _iso(v: Any) -> Any:
    return v.isoformat() if hasattr(v, "isoformat") else v


def _empty_graph_payload(program_id: str, *, message: str) -> dict[str, Any]:
    return {
        "program_id": program_id,
        "empty": True,
        "message": message,
        "nodes": [],
        "edges": [],
        "tables": {
            "org": [],
            "domain": [],
            "dns": [],
            "person": [],
            "email": [],
            "cert": [],
            "identity": [],
        },
        "counts": {
            "org": 0,
            "domain": 0,
            "dns": 0,
            "person": 0,
            "email": 0,
            "cert": 0,
            "identity": 0,
            "nodes": 0,
            "edges": 0,
        },
        "filter": {"kinds": [], "q": ""},
    }


def osint_graph_payload(
    program_id: str,
    *,
    kinds: str = "all",
    q: str = "",
) -> dict[str, Any]:
    """
    Filterable OSINT graph: org → domains → people/emails → certs (+identity).

    Honest empty when graph missing or no matching events. No fabricated nodes.
    """
    from sentinel_core import open_graph

    kind_set = {
        k.strip().lower()
        for k in (kinds or "all").split(",")
        if k.strip()
    }
    if not kind_set or "all" in kind_set:
        kind_set = {"org", "domain", "dns", "person", "email", "cert", "identity"}
    q_l = (q or "").strip().lower()

    try:
        graph = open_graph(program_id)
    except FileNotFoundError:
        return _empty_graph_payload(
            program_id,
            message=(
                f"No graph for program {program_id!r}. "
                f"Run: sentinel program init {program_id} && sentinel eye run …"
            ),
        )

    type_to_bucket = {
        "ORG": "org",
        "DOMAIN": "domain",
        "DNS_NAME": "dns",
        "PERSON": "person",
        "EMAIL": "email",
        "CERT": "cert",
        "IDENTITY": "identity",
    }

    nodes: list[dict[str, Any]] = []
    tables: dict[str, list[dict[str, Any]]] = {
        "org": [],
        "domain": [],
        "dns": [],
        "person": [],
        "email": [],
        "cert": [],
        "identity": [],
    }
    id_to_label: dict[str, str] = {}

    def _label(ev_type: str, payload: dict[str, Any]) -> str:
        for key in (
            "domain",
            "name",
            "value",
            "email",
            "person",
            "org",
            "cn",
            "subject",
            "fingerprint",
            "serial",
        ):
            v = payload.get(key)
            if v:
                return str(v)
        return ev_type.lower()

    for ev_type, bucket in type_to_bucket.items():
        if bucket not in kind_set:
            continue
        for ev in graph.list_by_type(ev_type):
            payload = dict(ev.payload or {})
            label = _label(ev_type, payload)
            if q_l and q_l not in label.lower() and q_l not in json.dumps(payload).lower():
                continue
            row = {
                "id": ev.id,
                "kind": bucket,
                "type": ev_type,
                "label": label,
                "confidence": float(ev.confidence),
                "parents": list(ev.parents or []),
                "first_seen": _iso(ev.first_seen),
                "last_seen": _iso(ev.last_seen),
                "payload": payload,
            }
            nodes.append(row)
            tables[bucket].append(row)
            id_to_label[ev.id] = label

    # Edges from parent links among collected nodes
    node_ids = {n["id"] for n in nodes}
    edges: list[dict[str, Any]] = []
    for n in nodes:
        for parent in n.get("parents") or []:
            if parent in node_ids:
                edges.append(
                    {
                        "from": parent,
                        "to": n["id"],
                        "from_label": id_to_label.get(parent, parent[:8]),
                        "to_label": n["label"],
                    }
                )

    close = getattr(graph, "close", None)
    if callable(close):
        close()

    counts = {k: len(tables[k]) for k in tables}
    counts["nodes"] = len(nodes)
    counts["edges"] = len(edges)
    empty = len(nodes) == 0
    message = None
    if empty:
        message = (
            "No OSINT org/domain/person/email/cert events on the graph yet. "
            "Run ShadowsEye against an owned target — this screen never fabricates nodes."
        )

    # Simple layered layout hints for SVG (deterministic, no invent)
    layers = ["org", "domain", "dns", "person", "email", "cert", "identity"]
    layout: list[dict[str, Any]] = []
    for li, layer in enumerate(layers):
        layer_nodes = [n for n in nodes if n["kind"] == layer]
        for i, n in enumerate(layer_nodes):
            layout.append(
                {
                    "id": n["id"],
                    "x": 40 + i * 140,
                    "y": 40 + li * 70,
                    "kind": n["kind"],
                    "label": n["label"][:40],
                }
            )

    return {
        "program_id": program_id,
        "empty": empty,
        "message": message,
        "nodes": nodes,
        "edges": edges,
        "layout": layout,
        "tables": tables,
        "counts": counts,
        "filter": {"kinds": sorted(kind_set), "q": q},
        "disclaimer": "Graph viz is read-only from stored events — never invents OSINT.",
    }


def _path_params(path: str) -> list[str]:
    found: list[str] = []
    for m in _PARAM_RE.finditer(path or ""):
        found.append(m.group(1) or m.group(2))
    return found


def _is_openapi_ish(url: str, path: str) -> bool:
    blob = f"{path} {url}".lower()
    return any(h in blob for h in _OPENAPI_PATH_HINTS)


def _is_js_asset(url: str, path: str) -> bool:
    low = (path or url or "").lower().split("?")[0]
    return any(low.endswith(ext) for ext in _JS_EXT) or "/static/" in low and low.endswith(".js")


def surface_payload(
    program_id: str,
    *,
    kind: str = "all",
    q: str = "",
) -> dict[str, Any]:
    """
    Surface map: endpoints / params / JS / OpenAPI-ish catalog from graph.

    Uses ENDPOINT, PARAM, JS_ASSET, URL (+ path heuristics). Honest empty.
    """
    from sentinel_core import open_graph

    kind_l = (kind or "all").strip().lower()
    allowed = {"all", "endpoint", "param", "js", "openapi", "url"}
    if kind_l not in allowed:
        raise ValueError(
            f"kind must be one of all/endpoint/param/js/openapi/url, got {kind!r}"
        )
    q_l = (q or "").strip().lower()

    try:
        graph = open_graph(program_id)
    except FileNotFoundError:
        return {
            "program_id": program_id,
            "empty": True,
            "message": (
                f"No graph for program {program_id!r}. "
                f"Run: sentinel program init {program_id} && sentinel eye run …"
            ),
            "kind": kind_l,
            "q": q,
            "count": 0,
            "counts": {"endpoint": 0, "param": 0, "js": 0, "openapi": 0, "url": 0},
            "items": [],
        }

    items: list[dict[str, Any]] = []

    def _push(
        *,
        row_kind: str,
        name: str,
        event_id: str,
        extra: dict[str, Any] | None = None,
        first_seen: Any = None,
        last_seen: Any = None,
    ) -> None:
        if q_l and q_l not in name.lower() and q_l not in json.dumps(extra or {}).lower():
            return
        items.append(
            {
                "kind": row_kind,
                "name": name,
                "event_id": event_id,
                "first_seen": _iso(first_seen),
                "last_seen": _iso(last_seen),
                **(extra or {}),
            }
        )

    for ev in graph.list_by_type("ENDPOINT"):
        p = ev.payload or {}
        name = str(p.get("path") or p.get("endpoint") or p.get("url") or "").strip()
        if not name:
            continue
        _push(
            row_kind="endpoint",
            name=name,
            event_id=ev.id,
            first_seen=ev.first_seen,
            last_seen=ev.last_seen,
            extra={"method": p.get("method"), "host": p.get("host")},
        )

    for ev in graph.list_by_type("PARAM"):
        p = ev.payload or {}
        name = str(p.get("name") or p.get("param") or "").strip()
        if not name:
            continue
        _push(
            row_kind="param",
            name=name,
            event_id=ev.id,
            first_seen=ev.first_seen,
            last_seen=ev.last_seen,
            extra={"in": p.get("in") or p.get("location"), "endpoint": p.get("endpoint")},
        )

    for ev in graph.list_by_type("JS_ASSET"):
        p = ev.payload or {}
        name = str(p.get("url") or p.get("path") or p.get("name") or "").strip()
        if not name:
            continue
        _push(
            row_kind="js",
            name=name,
            event_id=ev.id,
            first_seen=ev.first_seen,
            last_seen=ev.last_seen,
            extra={"source": p.get("source")},
        )

    # Derive from URL events (OpenAPI-ish, JS, param hints, generic endpoints)
    for ev in graph.list_by_type("URL"):
        p = ev.payload or {}
        url = str(p.get("url") or "").strip()
        if not url:
            continue
        parsed = urlparse(url)
        path = parsed.path or "/"
        query_keys = list(parse_qs(parsed.query or "").keys())
        host = parsed.hostname

        if _is_openapi_ish(url, path):
            _push(
                row_kind="openapi",
                name=url,
                event_id=ev.id,
                first_seen=ev.first_seen,
                last_seen=ev.last_seen,
                extra={"path": path, "host": host, "derived_from": "URL"},
            )
        if _is_js_asset(url, path):
            _push(
                row_kind="js",
                name=url,
                event_id=ev.id,
                first_seen=ev.first_seen,
                last_seen=ev.last_seen,
                extra={"path": path, "host": host, "derived_from": "URL"},
            )
        # Always catalog URL as surface endpoint candidate
        _push(
            row_kind="endpoint",
            name=f"{host or ''}{path}" if host else path,
            event_id=ev.id,
            first_seen=ev.first_seen,
            last_seen=ev.last_seen,
            extra={
                "url": url,
                "host": host,
                "path": path,
                "status": p.get("status"),
                "title": p.get("title"),
                "derived_from": "URL",
            },
        )
        for pk in query_keys:
            _push(
                row_kind="param",
                name=pk,
                event_id=ev.id,
                first_seen=ev.first_seen,
                last_seen=ev.last_seen,
                extra={"in": "query", "endpoint": path, "url": url, "derived_from": "URL"},
            )
        for pp in _path_params(path):
            _push(
                row_kind="param",
                name=pp,
                event_id=ev.id,
                first_seen=ev.first_seen,
                last_seen=ev.last_seen,
                extra={"in": "path", "endpoint": path, "url": url, "derived_from": "URL"},
            )

    close = getattr(graph, "close", None)
    if callable(close):
        close()

    # Dedupe by (kind, name, endpoint/url)
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for it in items:
        key = (
            it["kind"],
            str(it.get("name") or ""),
            str(it.get("url") or it.get("endpoint") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(it)
    items = deduped

    if kind_l != "all":
        items = [i for i in items if i["kind"] == kind_l]

    items.sort(key=lambda r: (r.get("kind") or "", r.get("name") or ""))
    counts = {"endpoint": 0, "param": 0, "js": 0, "openapi": 0, "url": 0}
    for i in items:
        k = i["kind"]
        if k in counts:
            counts[k] += 1

    empty = len(items) == 0
    message = None
    if empty:
        message = (
            "No surface catalog yet (no URL/ENDPOINT/PARAM/JS_ASSET on graph). "
            "Run Eye mapping first — never fabricates endpoints."
        )

    return {
        "program_id": program_id,
        "kind": kind_l,
        "q": q,
        "count": len(items),
        "counts": counts,
        "items": items,
        "empty": empty,
        "message": message,
        "disclaimer": "Surface map is derived from stored graph events only.",
    }


def _redact_value(s: str, *, keep: int = 4) -> str:
    if not s:
        return ""
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "…" + ("*" * min(8, max(0, len(s) - keep)))


def auth_lab_payload(program_id: str) -> dict[str, Any]:
    """
    Auth lab: role vault display (metadata + redacted flags) + replay stub.

    Never performs live requests. Replay stub returns prepared headers only.
    """
    from gungnir.packs.roles import RoleSessionError, load_role_session, role_session_path
    from sentinel_core import program_dir

    root = program_dir(program_id)
    roles: dict[str, Any] = {}
    for letter in ("a", "b"):
        path = role_session_path(program_id, letter)
        entry: dict[str, Any] = {
            "role": letter,
            "path": str(path),
            "rel": f"roles/{letter}.json",
            "exists": path.is_file(),
            "usable": False,
            "cookie_keys": [],
            "header_keys": [],
            "has_bearer": False,
            "bearer_preview": None,
            "replay_stub": None,
            "error": None,
        }
        if not path.is_file():
            entry["message"] = (
                f"No roles/{letter}.json — place a lab fixture with "
                "cookies|headers|bearer (authorized/lab only)."
            )
            roles[letter] = entry
            continue
        try:
            session = load_role_session(program_id, letter)
        except RoleSessionError as exc:
            entry["error"] = str(exc)
            # Still show raw keys if JSON parses but unusable
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    entry["cookie_keys"] = list((raw.get("cookies") or {}).keys())
                    entry["header_keys"] = list((raw.get("headers") or {}).keys())
                    entry["has_bearer"] = bool(raw.get("bearer"))
            except (OSError, json.JSONDecodeError):
                pass
            roles[letter] = entry
            continue

        entry["usable"] = session.is_usable()
        entry["cookie_keys"] = list(session.cookies.keys())
        entry["header_keys"] = list(session.headers.keys())
        entry["has_bearer"] = bool(session.bearer)
        if session.bearer:
            entry["bearer_preview"] = _redact_value(session.bearer)
        # Replay stub — prepared headers only (redacted values in display copy)
        prepared = session.as_request_headers()
        display_headers = {
            k: (_redact_value(v) if k.lower() in ("authorization", "cookie") else v)
            for k, v in prepared.items()
        }
        entry["replay_stub"] = {
            "live": False,
            "note": (
                "Stub only — headers prepared from vault; no network. "
                "Use Workbench with i_own_this for a gated live send."
            ),
            "headers_redacted": display_headers,
            "header_names": list(prepared.keys()),
        }
        roles[letter] = entry

    any_exist = any(r["exists"] for r in roles.values())
    empty = not any_exist
    return {
        "program_id": program_id,
        "program_dir": str(root),
        "empty": empty,
        "message": (
            None
            if not empty
            else (
                "No role session fixtures under program/roles/. "
                "Auth lab never fabricates credentials — add lab-only a.json / b.json."
            )
        ),
        "roles": roles,
        "disclaimer": (
            "Vault display + replay stub only. No silent live. "
            "Lab fixtures are operator-supplied; packs fail closed without them."
        ),
    }


def workbench_export(
    body: dict[str, Any],
) -> dict[str, Any]:
    """
    Export a composed request as curl / Burp XML / Caido-ish JSON.

    No network. Does not require i_own_this (export-only).
    """
    method = str(body.get("method") or "GET").upper().strip() or "GET"
    url = str(body.get("url") or "").strip()
    if not url:
        raise ValueError("url is required for export")
    headers = body.get("headers") or {}
    if not isinstance(headers, dict):
        raise ValueError("headers must be an object")
    headers = {str(k): str(v) for k, v in headers.items()}
    raw_body = body.get("body")
    if raw_body is None:
        body_text = ""
    elif isinstance(raw_body, (dict, list)):
        body_text = json.dumps(raw_body)
    else:
        body_text = str(raw_body)

    fmt = str(body.get("format") or "all").strip().lower()
    if fmt not in ("all", "curl", "burp", "caido"):
        raise ValueError("format must be all|curl|burp|caido")

    # curl
    parts = [f"curl -i -X {method}"]
    for k, v in headers.items():
        esc_v = v.replace("'", "'\\''")
        parts.append(f"-H '{k}: {esc_v}'")
    if body_text and method not in ("GET", "HEAD"):
        esc_b = body_text.replace("'", "'\\''")
        parts.append(f"-d '{esc_b}'")
    parts.append(f"'{url}'")
    curl = " \\\n  ".join(parts)

    # Burp-ish XML (simplified HTTP history item)
    hdr_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    req_line = f"{method} {urlparse(url).path or '/'} HTTP/1.1\r\n"
    if "Host" not in {h.title() for h in headers} and "host" not in {h.lower() for h in headers}:
        host = urlparse(url).netloc
        hdr_lines = f"Host: {host}\r\n" + hdr_lines
    raw_req = req_line + hdr_lines + "\r\n" + (body_text if method not in ("GET", "HEAD") else "")
    # Escape for XML
    xml_esc = (
        raw_req.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    burp = (
        '<?xml version="1.0"?>\n'
        "<items burpVersion=\"sentinel-suite-export\" exportTime=\"local\">\n"
        "  <item>\n"
        f"    <url><![CDATA[{url}]]></url>\n"
        f"    <method><![CDATA[{method}]]></method>\n"
        f"    <request base64=\"false\"><![CDATA[{xml_esc}]]></request>\n"
        "    <status>0</status>\n"
        "    <responselength>0</responselength>\n"
        "  </item>\n"
        "</items>\n"
    )

    caido = {
        "format": "sentinel-suite-caido-export-v1",
        "note": (
            "Interop stub — import manually into Caido if present. "
            "Not a Caido replacement; no live proxy."
        ),
        "request": {
            "method": method,
            "url": url,
            "headers": headers,
            "body": body_text or None,
        },
    }

    out: dict[str, Any] = {
        "ok": True,
        "method": method,
        "url": url,
        "live": False,
        "disclaimer": "Export only — no network performed.",
    }
    if fmt in ("all", "curl"):
        out["curl"] = curl
    if fmt in ("all", "burp"):
        out["burp_xml"] = burp
    if fmt in ("all", "caido"):
        out["caido_json"] = caido
    return out


def workbench_send(body: dict[str, Any]) -> dict[str, Any]:
    """
    Live workbench send — requires i_own_this + program scope hard-kill.

    Mutating auth is enforced by the HTTP handler (D1 gate). Never silent.
    """
    from sentinel_core import ScopeDenied, load_scope_file, program_dir
    from sentinel_core.http_guard import scoped_request
    from urllib.error import HTTPError, URLError

    program_id = str(body.get("program_id") or "").strip()
    method = str(body.get("method") or "GET").upper().strip() or "GET"
    url = str(body.get("url") or "").strip()
    i_own_this = bool(body.get("i_own_this"))
    headers = body.get("headers") or {}
    if not isinstance(headers, dict):
        raise ValueError("headers must be an object")
    headers = {str(k): str(v) for k, v in headers.items()}
    raw_body = body.get("body")
    data: bytes | None = None
    if raw_body is not None and method not in ("GET", "HEAD"):
        if isinstance(raw_body, (dict, list)):
            data = json.dumps(raw_body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(raw_body, str):
            data = raw_body.encode("utf-8")
        else:
            data = str(raw_body).encode("utf-8")

    if not program_id:
        raise ValueError("program_id is required")
    if not url:
        raise ValueError("url is required")
    if not i_own_this:
        raise ValueError(
            "Workbench live send requires i_own_this=true "
            "(no silent live from the UI). Use export for offline curl/Burp/Caido."
        )

    # Ensure program exists + load scope.txt (fail closed if missing)
    root = program_dir(program_id)
    scope_path = root / "scope.txt"
    if not scope_path.is_file():
        raise ValueError(
            f"No scope.txt for program {program_id!r}. "
            "Write scope before live workbench send (hard-kill requires scope)."
        )
    scope = load_scope_file(scope_path)

    timeout = float(body.get("timeout") or 15.0)
    timeout = max(1.0, min(timeout, 60.0))

    try:
        # Hard-kill first via scoped_request path
        resp = scoped_request(
            scope,
            method,
            url,
            headers=headers,
            data=data,
            timeout=timeout,
        )
    except ScopeDenied as exc:
        raise ValueError(f"scope denied (hard kill): {exc}") from exc
    except HTTPError as exc:
        body_bytes = exc.read() if hasattr(exc, "read") else b""
        text = body_bytes[:8192].decode("utf-8", errors="replace")
        return {
            "ok": True,
            "live": True,
            "status": int(exc.code),
            "reason": getattr(exc, "reason", None),
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "body_preview": text,
            "truncated": True,
            "url": url,
            "method": method,
            "program_id": program_id,
            "human_gate": "Live send completed under ownership gate — not a finding.",
        }
    except URLError as exc:
        raise ValueError(f"request failed: {exc}") from exc
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"request failed: {exc}") from exc

    try:
        body_bytes = resp.read(8192)
        text = body_bytes.decode("utf-8", errors="replace")
        status = getattr(resp, "status", None) or resp.getcode()
        resp_headers = dict(resp.headers.items()) if getattr(resp, "headers", None) else {}
    finally:
        close = getattr(resp, "close", None)
        if callable(close):
            close()

    return {
        "ok": True,
        "live": True,
        "status": int(status) if status is not None else None,
        "headers": resp_headers,
        "body_preview": text,
        "truncated": len(body_bytes) >= 8192,
        "url": url,
        "method": method,
        "program_id": program_id,
        "human_gate": "Live send completed under ownership gate — not a finding.",
    }


def tauri_status_payload() -> dict[str, Any]:
    """RO meta about Tauri scaffold + dry-run (no inventing green CI)."""
    here = Path(__file__).resolve()
    repo = here.parents[4]
    src_tauri = repo / "src-tauri"
    conf = src_tauri / "tauri.conf.json"
    cargo = src_tauri / "Cargo.toml"
    main_rs = src_tauri / "src" / "main.rs"
    dry_script = repo / "scripts" / "tauri_dry_run.py"
    pending_ci = repo / "docs" / "ci-pending" / "tauri.yml"
    workflows = repo / ".github" / "workflows"
    has_pushed_workflow = False
    if workflows.is_dir():
        has_pushed_workflow = any(workflows.glob("*.yml")) or any(workflows.glob("*.yaml"))

    return {
        "phase": "D4",
        "electron": False,
        "tauri_scaffold": {
            "src_tauri": src_tauri.is_dir(),
            "tauri_conf": conf.is_file(),
            "cargo_toml": cargo.is_file(),
            "main_rs": main_rs.is_file(),
            "dry_run_script": dry_script.is_file(),
        },
        "dev_url": "http://127.0.0.1:8888",
        "browser_first": True,
        "how_to": {
            "browser": "sentinel ui  # http://127.0.0.1:8888",
            "tauri_dev": "Start API first, then: cargo tauri dev (loads 127.0.0.1:8888)",
            "tauri_build": "cargo tauri build  # .dmg / .msi / .AppImage when host tooling OK",
            "dry_run": "python scripts/tauri_dry_run.py  # or npm run tauri:dry-run",
        },
        "packaging_ci": {
            "pushed_workflows": has_pushed_workflow,
            "pending_doc": str(pending_ci) if pending_ci.is_file() else None,
            "note": (
                "Workflow OAuth may HOLD — do not push new .github/workflows. "
                "Packaging CI scaffold lives under docs/ci-pending/ until unblocked."
            ),
        },
        "fences": {"electron": False, "guard_sdk": False, "engine_allowlist": {}},
    }


__all__ = [
    "auth_lab_payload",
    "osint_graph_payload",
    "surface_payload",
    "tauri_status_payload",
    "workbench_export",
    "workbench_send",
]
