import json
import subprocess
import sys

import pytest

from gungnir import correlate_findings, require_scope_or_lab, run_hunt
from sentinel_core import ScopeDenied, open_graph


def test_hunt_refuses_without_scope_or_lab(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    with pytest.raises(ScopeDenied):
        run_hunt("hunt-deny", title="x", i_own_this=False, scope_path=None)


def test_hunt_accepts_i_own_this(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    result = run_hunt(
        "hunt-lab",
        title="open redirect candidate",
        host="example.com",
        i_own_this=True,
    )
    assert result["findings_emitted"] == 1
    assert result["events"][0]["verification"] == "unverified"
    with open_graph("hunt-lab") as g:
        ev = g.get(result["events"][0]["id"])
        assert ev.type == "FINDING"
        assert ev.payload["verification"] == "unverified"


def test_hunt_cli_requires_scope_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "run",
            "cli-deny",
            "--title",
            "x",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode != 0
    assert "scope" in (proc.stderr + proc.stdout).lower() or proc.returncode == 2


def test_hunt_cli_with_i_own_this(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "hunt",
            "run",
            "cli-ok",
            "--title",
            "lab finding",
            "--host",
            "example.com",
            "--i-own-this",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["findings_emitted"] == 1


def test_correlate_thin_honesty():
    findings = [
        {"title": "XSS", "host": "a.example", "verification": "unverified"},
        {"title": "XSS", "host": "a.example"},  # dup
        {"title": "SQLi", "host": "b.example"},
    ]
    out = correlate_findings(findings)
    assert len(out) == 2
    for item in out:
        assert item["verification"] == "unverified"
        assert item["verification_status"] == "unverified"
        assert item["verified"] is False
        assert item.get("chain_stubs") == []
