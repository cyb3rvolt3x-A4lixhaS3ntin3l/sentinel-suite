"""Productization step 2 — webopen + demo/full-run CLI (honesty tests)."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel_cli.webopen import (
    loopback_display_url,
    open_ui_url,
    resolve_open_browser,
    url_is_safe_to_open,
)

REPO = Path(__file__).resolve().parents[1]


def _cli(*args: str, env: dict | None = None) -> subprocess.CompletedProcess[str]:
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run(
        [sys.executable, "-m", "sentinel_cli.cli", *args],
        capture_output=True,
        text=True,
        env=e,
        cwd=str(REPO),
    )


def test_resolve_open_explicit_flags():
    assert resolve_open_browser(open_flag=True, bind="127.0.0.1", isatty=False) is True
    assert resolve_open_browser(open_flag=False, bind="127.0.0.1", isatty=True) is False


def test_resolve_open_ci_and_env(monkeypatch):
    env = {"CI": "1"}
    assert resolve_open_browser(open_flag=None, bind="127.0.0.1", env=env, isatty=True) is False
    env2 = {"SENTINEL_UI_OPEN": "0"}
    assert resolve_open_browser(open_flag=None, bind="127.0.0.1", env=env2, isatty=True) is False
    env3 = {"SENTINEL_UI_OPEN": "1"}
    assert resolve_open_browser(open_flag=None, bind="127.0.0.1", env=env3, isatty=False) is True
    # Non-loopback + env alone → False (need explicit --open)
    assert resolve_open_browser(open_flag=None, bind="0.0.0.0", env=env3, isatty=True) is False
    assert resolve_open_browser(open_flag=True, bind="0.0.0.0", env={}, isatty=False) is True


def test_resolve_open_tty_default_loopback_only():
    assert resolve_open_browser(open_flag=None, bind="127.0.0.1", env={}, isatty=True) is True
    assert resolve_open_browser(open_flag=None, bind="127.0.0.1", env={}, isatty=False) is False
    assert resolve_open_browser(open_flag=None, bind="0.0.0.0", env={}, isatty=True) is False


def test_loopback_display_url_rewrites_wildcard():
    assert loopback_display_url("0.0.0.0", 8888) == "http://127.0.0.1:8888/"
    assert loopback_display_url("127.0.0.1", 8888) == "http://127.0.0.1:8888/"
    assert loopback_display_url("localhost", 9999) == "http://127.0.0.1:9999/"


def test_url_is_safe_to_open_gate():
    assert url_is_safe_to_open("http://127.0.0.1:8888/")
    assert not url_is_safe_to_open("http://example.com/")
    assert not url_is_safe_to_open("file:///etc/passwd")


def test_open_ui_url_mocks_webbrowser():
    with patch("webbrowser.open", return_value=True) as mocked:
        meta = open_ui_url("http://127.0.0.1:8888/")
        assert meta["opened"] is True
        mocked.assert_called_once_with("http://127.0.0.1:8888/")
    with patch("webbrowser.open", return_value=True) as mocked:
        meta = open_ui_url("http://evil.example/", require_loopback=True)
        assert meta["opened"] is False
        mocked.assert_not_called()


def test_cli_ui_help_mentions_open():
    proc = _cli("ui", "--help")
    assert proc.returncode == 0
    assert "--open" in proc.stdout
    assert "--no-open" in proc.stdout


def test_cli_demo_and_full_run_help():
    d = _cli("demo", "--help")
    assert d.returncode == 0
    assert "random" in d.stdout.lower() or "owned" in d.stdout.lower() or "lab" in d.stdout.lower()
    f = _cli("full-run", "--help")
    assert f.returncode == 0
    assert "--target" in f.stdout
    assert "--scope" in f.stdout or "scope" in f.stdout.lower()


def test_full_run_requires_target_and_scope(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    env = {**os.environ, "SENTINEL_HOME": str(home)}
    missing_target = _cli("full-run", "--program", "p1", "--scope", str(tmp_path / "s.txt"), env=env)
    assert missing_target.returncode == 2
    assert "target" in (missing_target.stderr + missing_target.stdout).lower()

    missing_scope = _cli(
        "full-run", "--program", "p1", "--target", "example.com", env=env
    )
    assert missing_scope.returncode == 2
    assert "scope" in (missing_scope.stderr + missing_scope.stdout).lower() or "i-own" in (
        missing_scope.stderr + missing_scope.stdout
    ).lower()


def test_cmd_ui_passes_open_flag_to_serve_ui(monkeypatch):
    from sentinel_cli import cli as cli_mod

    captured: dict = {}

    def fake_serve_ui(**kwargs):
        captured.update(kwargs)
        return {"ok": True}

    monkeypatch.setattr("sentinel_cli.ui_server.serve_ui", fake_serve_ui)
    # Also patch the import inside cmd_ui
    import sentinel_cli.ui_server as ui_server

    monkeypatch.setattr(ui_server, "serve_ui", fake_serve_ui)

    ns = argparse.Namespace(
        bind="127.0.0.1",
        port=8888,
        i_understand_lab=False,
        open_browser=True,
        no_open=False,
    )
    # cmd_ui imports serve_ui locally — patch via module used at call time
    with patch("sentinel_cli.ui_server.serve_ui", fake_serve_ui):
        rc = cli_mod.cmd_ui(ns)
    assert rc == 0
    assert captured.get("open_browser") is True

    captured.clear()
    ns2 = argparse.Namespace(
        bind="127.0.0.1",
        port=8888,
        i_understand_lab=False,
        open_browser=False,
        no_open=True,
    )
    with patch("sentinel_cli.ui_server.serve_ui", fake_serve_ui):
        rc = cli_mod.cmd_ui(ns2)
    assert rc == 0
    assert captured.get("open_browser") is False


def test_serve_ui_webopen_calls_webbrowser(monkeypatch, tmp_path):
    """Start server briefly; mock webbrowser; ensure open path runs."""
    import threading
    import time
    from http.server import ThreadingHTTPServer

    from sentinel_cli.ui_server import make_handler, resolve_ui_static_root, serve_ui

    root = resolve_ui_static_root()
    opened: list[str] = []

    def fake_open(url):
        opened.append(url)
        return True

    # Run serve_ui in a thread with KeyboardInterrupt after short delay
    # Better: unit-test the open branch by calling with a patched serve_forever
    from sentinel_cli import ui_server

    class BoomServer(ThreadingHTTPServer):
        def serve_forever(self, poll_interval=0.5):  # noqa: ARG002
            raise KeyboardInterrupt

    monkeypatch.setattr(ui_server, "ThreadingHTTPServer", BoomServer)
    with patch("webbrowser.open", side_effect=fake_open):
        summary = serve_ui(
            bind="127.0.0.1",
            port=18991,
            open_browser=True,
            static_root=root,
        )
    assert summary["open_browser"] is True
    assert opened == ["http://127.0.0.1:18991/"]
    assert summary["webopen"]["opened"] is True


def test_packaging_scripts_exist():
    scripts = REPO / "scripts"
    assert (scripts / "build_pyinstaller_linux.sh").is_file()
    assert (scripts / "build_pyinstaller_windows.ps1").is_file()
    assert (scripts / "build_macos_stub.sh").is_file()
    assert (scripts / "build_appimage_linux.sh").is_file()
