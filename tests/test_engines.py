import hashlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sentinel_core import (
    bin_dir,
    detect_engine,
    ensure_engine,
    list_engine_status,
    list_pinned,
    pin_engine,
    stamp_run,
)
from sentinel_core.engine_allowlist import set_allowlist_for_tests


def test_engine_pin(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    b = bin_dir()
    assert b.is_dir()
    pin_engine("httpx", "1.6.0")
    pinned = list_pinned()
    assert pinned["httpx"]["version"] == "1.6.0"
    rec = stamp_run("httpx")
    assert rec["version"] == "1.6.0"
    assert (b / "run_stamps.jsonl").is_file()


def test_detect_engine_finds_known_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    found = detect_engine("true") or detect_engine("python3") or detect_engine("python")
    assert found is not None
    assert found["path"]
    assert found["source"] in ("path", "bin_dir")


def test_ensure_engine_missing_and_not_allowlisted(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    missing = ensure_engine("definitely-not-a-real-engine-zzz", download=False)
    assert missing["status"] == "missing"
    rejected = ensure_engine("definitely-not-a-real-engine-zzz", download=True)
    assert rejected["status"] == "not_allowlisted"
    assert "allowlist" in rejected["message"].lower()


def test_ensure_engine_rejects_deferred_download(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    # subfinder is deferred catalog — not allowlisted
    result = ensure_engine("subfinder", download=True)
    assert result["status"] == "not_allowlisted"
    assert result.get("deferred") is True


def test_allowlist_download_with_local_server(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    payload = b"#!/bin/sh\necho mock-engine 0.0.1\n"
    digest = hashlib.sha256(payload).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/mock-engine"
    prev = set_allowlist_for_tests(
        {
            "mock-engine": {
                "version": "0.0.1",
                "url": url,
                "sha256": digest,
                "filename": "mock-engine",
            }
        }
    )
    try:
        result = ensure_engine("mock-engine", download=True)
        assert result["status"] == "downloaded"
        dest = Path(result["path"])
        assert dest.is_file()
        assert dest.read_bytes() == payload
        assert list_pinned()["mock-engine"]["version"] == "0.0.1"
        # PATH must not be mutated — binary only under SENTINEL_HOME/bin
        assert str(tmp_path / "home" / "bin") in str(dest)
    finally:
        set_allowlist_for_tests(prev)
        server.shutdown()


def test_allowlist_rejects_arbitrary_url_not_in_list(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    from sentinel_core.engines import download_allowlisted_engine

    with pytest.raises(ValueError, match="not in ENGINE_ALLOWLIST"):
        download_allowlisted_engine("totally-arbitrary-tool")


def test_list_engine_status_shapes(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    rows = list_engine_status()
    assert isinstance(rows, list)
    assert any(r["name"] == "subfinder" and r["deferred"] for r in rows)
    # python/true commonly detected
    names = {r["name"] for r in rows}
    assert "true" in names or "python3" in names or "python" in names
