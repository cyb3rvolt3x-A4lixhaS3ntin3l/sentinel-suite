"""Owned collaborator HTTP callback listener (Phase C slice15).

Stdlib-only thin listener for operator-owned SSRF collaborator callbacks.
Default bind = 127.0.0.1 (loopback). Public / wildcard binds require
``--i-understand-lab``. No interactsh client, no outbound scanning, never
suggest cloud metadata as collaborator.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import unquote

from gungnir.packs.ssrf_collaborator.caps import (
    BODY_SNIPPET_MAX,
    COACH_LISTEN_HITS,
    COACH_NO_OUTBOUND_SCAN,
    DEFAULT_BIND,
    DEFAULT_CALLBACK_PATH,
    CapExceededError,
    ListenCaps,
    assert_bind_allowed,
    collaborator_url_for_listen,
    is_cloud_metadata_target,
    resolve_listen_caps,
)
from sentinel_core import Event, EventGraph, create_program, open_graph

_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-amz-security-token",
    }
)


class ListenerHitCapError(CapExceededError):
    """Max hits exceeded — fail closed."""


class ListenerDurationCapError(CapExceededError):
    """Max listen duration exceeded — fail closed."""


def _sanitize_headers(raw: list[tuple[str, str]] | dict[str, str]) -> dict[str, str]:
    if isinstance(raw, dict):
        items = raw.items()
    else:
        items = raw
    out: dict[str, str] = {}
    for k, v in items:
        lk = str(k).lower()
        if lk in _SENSITIVE_HEADERS:
            out[lk] = "[redacted]"
        else:
            out[lk] = str(v)[:200]
    return out


def _body_snippet(body: bytes, *, max_len: int = BODY_SNIPPET_MAX) -> str:
    if not body:
        return ""
    text = body[:max_len].decode("utf-8", errors="replace")
    # Never retain obvious secret-looking material beyond short evidence
    lower = text.lower()
    if "authorization:" in lower or "api_key" in lower or "password=" in lower:
        return text[:64] + "…[truncated-sensitive]"
    return text


def hit_record_from_request(
    *,
    method: str,
    path: str,
    headers: list[tuple[str, str]] | dict[str, str],
    body: bytes,
    client_addr: str | None = None,
) -> dict[str, Any]:
    """Build a truncated COLLABORATOR_HIT payload (no long secrets)."""
    return {
        "method": (method or "GET").upper(),
        "path": unquote(path or "/"),
        "headers": _sanitize_headers(headers),
        "body_snippet": _body_snippet(body),
        "body_len": len(body or b""),
        "client": client_addr,
        "received": True,
        "note": COACH_NO_OUTBOUND_SCAN,
    }


def emit_collaborator_hit(
    graph: EventGraph,
    *,
    program_id: str,
    hit: dict[str, Any],
    source_module: str = "gungnir.packs.ssrf_collaborator.listener",
    confidence: float = 0.6,
    parents: list[str] | None = None,
) -> Event:
    """Insert a COLLABORATOR_HIT event on the program graph."""
    payload = dict(hit)
    payload.setdefault("event_kind", "COLLABORATOR_HIT")
    payload.setdefault("note", COACH_NO_OUTBOUND_SCAN)
    ev = Event(
        type="COLLABORATOR_HIT",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload=payload,
    )
    graph.insert(ev)
    return ev


class CollaboratorListener:
    """Threading HTTP listener that records inbound callbacks under hard caps."""

    def __init__(
        self,
        caps: ListenCaps,
        *,
        program_id: str | None = None,
        on_hit: Callable[[dict[str, Any]], None] | None = None,
        emit_to_graph: bool = True,
    ) -> None:
        self.caps = caps
        self.program_id = program_id
        self.on_hit = on_hit
        self.emit_to_graph = emit_to_graph and bool(program_id)
        self.hits: list[dict[str, Any]] = []
        self.hit_events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._started = threading.Event()
        self._stop = threading.Event()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._started_at: float | None = None
        self._closed_reason: str | None = None
        self._url: str | None = None

    @property
    def url(self) -> str:
        if self._url:
            return self._url
        return collaborator_url_for_listen(self.caps)

    @property
    def hits_logged(self) -> int:
        with self._lock:
            return len(self.hits)

    def _record_hit(self, hit: dict[str, Any]) -> None:
        with self._lock:
            if len(self.hits) >= self.caps.max_hits:
                self._closed_reason = "max_hits"
                # Fail closed: stop accepting further hits
                self._stop.set()
                raise ListenerHitCapError(
                    COACH_LISTEN_HITS + f" (hits={len(self.hits)})",
                    exit_code=2,
                )
            self.hits.append(hit)
            hit_copy = dict(hit)

        if self.on_hit:
            try:
                self.on_hit(hit_copy)
            except Exception:  # noqa: BLE001 — listener must stay up
                pass

        if self.emit_to_graph and self.program_id:
            try:
                with open_graph(self.program_id) as graph:
                    ev = emit_collaborator_hit(
                        graph,
                        program_id=self.program_id,
                        hit=hit_copy,
                    )
                with self._lock:
                    self.hit_events.append({"id": ev.id, "type": ev.type})
            except Exception:  # noqa: BLE001
                pass

        with self._lock:
            if len(self.hits) >= self.caps.max_hits:
                self._closed_reason = "max_hits"
                self._stop.set()

    def start(self) -> str:
        """Bind + start background serve thread. Returns collaborator URL."""
        assert_bind_allowed(
            self.caps.bind, i_understand_lab=self.caps.i_understand_lab
        )
        # Refuse metadata collaborator URL construction (paranoia)
        probe = collaborator_url_for_listen(self.caps)
        if is_cloud_metadata_target(probe):
            raise CapExceededError(
                "ssrf_collaborator listener refuses cloud metadata bind/URL. "
                + COACH_NO_OUTBOUND_SCAN,
                exit_code=2,
            )

        listener = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
                return  # quiet

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                # Cap read to avoid memory abuse (body snippet only needs a bit more)
                read_n = min(max(length, 0), BODY_SNIPPET_MAX * 4)
                body = self.rfile.read(read_n) if read_n else b""
                # Drain remainder without storing
                remaining = max(length - read_n, 0)
                while remaining > 0:
                    chunk = self.rfile.read(min(remaining, 65536))
                    if not chunk:
                        break
                    remaining -= len(chunk)

                hit = hit_record_from_request(
                    method=self.command,
                    path=self.path,
                    headers=list(self.headers.items()),
                    body=body,
                    client_addr=self.client_address[0] if self.client_address else None,
                )
                try:
                    listener._record_hit(hit)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", "3")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b"ok\n")
                except ListenerHitCapError:
                    self.send_response(429)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    msg = b"hit cap exceeded\n"
                    self.send_header("Content-Length", str(len(msg)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(msg)

            def do_GET(self) -> None:  # noqa: N802
                self._handle()

            def do_POST(self) -> None:  # noqa: N802
                self._handle()

            def do_PUT(self) -> None:  # noqa: N802
                self._handle()

            def do_HEAD(self) -> None:  # noqa: N802
                self._handle()

            def do_OPTIONS(self) -> None:  # noqa: N802
                self._handle()

        # ThreadingHTTPServer allows concurrent callbacks under caps
        server = ThreadingHTTPServer((self.caps.bind, self.caps.port), Handler)
        server.daemon_threads = True
        self._server = server
        # Actual port when port=0 (ephemeral)
        actual_port = int(server.server_address[1])
        # Rebuild caps-like URL with real port
        from dataclasses import replace

        effective = replace(self.caps, port=actual_port)
        self._url = collaborator_url_for_listen(effective)
        self.caps = effective

        self._started_at = time.monotonic()
        self._stop.clear()

        def _serve() -> None:
            self._started.set()
            while not self._stop.is_set():
                elapsed = time.monotonic() - (self._started_at or time.monotonic())
                if elapsed >= self.caps.max_duration_s:
                    self._closed_reason = "max_duration"
                    break
                server.handle_request()
            try:
                server.server_close()
            except Exception:  # noqa: BLE001
                pass

        # Use timeout so handle_request returns periodically for duration checks
        server.timeout = 0.5
        self._thread = threading.Thread(
            target=_serve, name="sentinel-collaborator-listener", daemon=True
        )
        self._thread.start()
        self._started.wait(timeout=5.0)
        return self.url

    def stop(self) -> None:
        self._stop.set()
        # Do not call HTTPServer.shutdown() — that expects serve_forever().
        # handle_request() wakes on server.timeout; then we close the socket.
        if self._server is not None:
            try:
                self._server.server_close()
            except Exception:  # noqa: BLE001
                pass
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._closed_reason = self._closed_reason or "stopped"

    def wait_until_done(self, *, raise_on_cap: bool = True) -> dict[str, Any]:
        """Block until stop / duration / hits. Optionally raise on cap exceed."""
        deadline = (self._started_at or time.monotonic()) + self.caps.max_duration_s
        while not self._stop.is_set():
            if time.monotonic() >= deadline:
                self._closed_reason = "max_duration"
                break
            if self.hits_logged >= self.caps.max_hits:
                self._closed_reason = "max_hits"
                break
            time.sleep(0.05)
        self.stop()
        summary = self.summary()
        if raise_on_cap and summary.get("closed_reason") == "max_hits":
            raise ListenerHitCapError(
                COACH_LISTEN_HITS + f" (hits={summary['hits']})",
                exit_code=2,
            )
        if raise_on_cap and summary.get("closed_reason") == "max_duration":
            # Duration exhaustion is the normal end for `serve`; do not raise
            # unless hits somehow empty and caller wants fail — treat as OK end.
            pass
        return summary

    def summary(self) -> dict[str, Any]:
        with self._lock:
            hits = list(self.hits)
            events = list(self.hit_events)
        elapsed = None
        if self._started_at is not None:
            elapsed = round(time.monotonic() - self._started_at, 3)
        return {
            "url": self.url,
            "bind": self.caps.bind,
            "port": self.caps.port,
            "hits": len(hits),
            "max_hits": self.caps.max_hits,
            "max_duration_s": self.caps.max_duration_s,
            "elapsed_s": elapsed,
            "closed_reason": self._closed_reason,
            "hit_event_ids": [e["id"] for e in events],
            "program_id": self.program_id,
            "note": COACH_NO_OUTBOUND_SCAN,
        }

    def __enter__(self) -> CollaboratorListener:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()


def start_ephemeral_listener(
    *,
    program_id: str | None = None,
    bind: str | None = None,
    port: int = 0,
    max_duration: float | None = None,
    max_hits: int | None = None,
    i_understand_lab: bool = False,
    callback_path: str | None = None,
    emit_to_graph: bool = True,
) -> CollaboratorListener:
    """Start a short-lived loopback listener (port 0 = ephemeral)."""
    caps = resolve_listen_caps(
        bind=bind or DEFAULT_BIND,
        port=port,
        max_duration=max_duration,
        max_hits=max_hits,
        i_understand_lab=i_understand_lab,
        callback_path=callback_path or DEFAULT_CALLBACK_PATH,
    )
    if program_id:
        create_program(program_id)
    listener = CollaboratorListener(
        caps,
        program_id=program_id,
        emit_to_graph=emit_to_graph and bool(program_id),
    )
    listener.start()
    return listener


def serve_collaborator(
    *,
    program_id: str,
    bind: str | None = None,
    port: int | None = None,
    max_duration: float | None = None,
    max_hits: int | None = None,
    i_understand_lab: bool = False,
    callback_path: str | None = None,
    create_if_missing: bool = True,
) -> dict[str, Any]:
    """
    Blocking serve for ``sentinel collaborator serve``.

    Binds loopback by default; logs COLLABORATOR_HIT events to the program graph
    until max duration or max hits (fail-closed on hit cap).
    """
    if create_if_missing:
        create_program(program_id)
    caps = resolve_listen_caps(
        bind=bind,
        port=port,
        max_duration=max_duration,
        max_hits=max_hits,
        i_understand_lab=i_understand_lab,
        callback_path=callback_path,
    )
    listener = CollaboratorListener(caps, program_id=program_id, emit_to_graph=True)
    url = listener.start()
    print(f"collaborator listening: {url}")
    print(f"program: {program_id}")
    print(
        f"caps: duration≤{caps.max_duration_s:g}s hits≤{caps.max_hits} "
        f"bind={caps.bind} (lab={caps.i_understand_lab})"
    )
    print(COACH_NO_OUTBOUND_SCAN)
    try:
        # Duration end is success for serve; hit-cap raises fail-closed
        while not listener._stop.is_set():  # noqa: SLF001 — intentional poll
            if listener.hits_logged >= caps.max_hits:
                listener._closed_reason = "max_hits"  # noqa: SLF001
                break
            started = listener._started_at or time.monotonic()  # noqa: SLF001
            if time.monotonic() - started >= caps.max_duration_s:
                listener._closed_reason = "max_duration"  # noqa: SLF001
                break
            time.sleep(0.1)
    finally:
        listener.stop()

    summary = listener.summary()
    if summary.get("closed_reason") == "max_hits":
        raise ListenerHitCapError(
            COACH_LISTEN_HITS + f" (hits={summary['hits']})",
            exit_code=2,
        )
    return summary


__all__ = [
    "CollaboratorListener",
    "ListenerHitCapError",
    "ListenerDurationCapError",
    "emit_collaborator_hit",
    "hit_record_from_request",
    "serve_collaborator",
    "start_ephemeral_listener",
]
