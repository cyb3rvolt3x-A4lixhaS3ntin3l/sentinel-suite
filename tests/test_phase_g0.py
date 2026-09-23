"""Phase G0 — free-promise lock: telemetry OFF default, zip export, settings."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from sentinel_core import (
    create_program,
    emit_event,
    export_program_zip,
    telemetry_enabled,
    telemetry_status,
)

REPO = Path(__file__).resolve().parents[1]


def _run_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sentinel_cli.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        cwd=str(REPO),
    )


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("SENTINEL_HOME", str(h))
    monkeypatch.delenv("SENTINEL_TELEMETRY", raising=False)
    return h


def test_telemetry_off_by_default(home, monkeypatch):
    monkeypatch.delenv("SENTINEL_TELEMETRY", raising=False)
    assert telemetry_enabled() is False
    st = telemetry_status()
    assert st["enabled"] is False
    assert st["default"] == "off"
    assert st["network"] is False
    assert st["phone_home"] is False
    assert st["sink"] == "noop"
    out = emit_event("g0_test", {"x": 1})
    assert out["emitted"] is False
    assert out["reason"] == "telemetry_off"
    assert not (home / "telemetry" / "local.jsonl").exists()


def test_telemetry_opt_in_local_only(home, monkeypatch):
    monkeypatch.setenv("SENTINEL_TELEMETRY", "1")
    assert telemetry_enabled() is True
    st = telemetry_status()
    assert st["enabled"] is True
    assert st["network"] is False
    assert st["phone_home"] is False
    assert st["sink"] == "local_jsonl"
    out = emit_event("g0_opt_in", {"anon": True})
    assert out["emitted"] is True
    assert out["network"] is False
    path = Path(out["path"])
    assert path.is_file()
    line = path.read_text(encoding="utf-8").strip().splitlines()[-1]
    rec = json.loads(line)
    assert rec["name"] == "g0_opt_in"
    assert rec["network"] is False
    assert rec["anonymous"] is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off", ""])
def test_telemetry_falsy_values(home, monkeypatch, val):
    if val == "":
        monkeypatch.delenv("SENTINEL_TELEMETRY", raising=False)
    else:
        monkeypatch.setenv("SENTINEL_TELEMETRY", val)
    assert telemetry_enabled() is False
    assert emit_event("noop")["emitted"] is False


def test_export_program_zip_roundtrip(home):
    root = create_program("g0demo")
    (root / "roles").mkdir(exist_ok=True)
    (root / "roles" / "a.json").write_text('{"bearer":"lab"}', encoding="utf-8")
    (root / "report.md").write_text("# report\n", encoding="utf-8")
    result = export_program_zip("g0demo")
    assert result["local_only"] is True
    assert result["account_required"] is False
    assert result["network"] is False
    zpath = Path(result["zip_path"])
    assert zpath.is_file()
    assert zpath.parent == home / "exports"
    with zipfile.ZipFile(zpath) as zf:
        names = set(zf.namelist())
    assert "g0demo/program.yml" in names
    assert "g0demo/scope.txt" in names
    assert "g0demo/graph.sqlite" in names
    assert "g0demo/roles/a.json" in names
    assert "g0demo/report.md" in names
    assert "g0demo/EXPORT_MANIFEST.txt" in names


def test_export_program_zip_custom_output(home, tmp_path):
    create_program("g0out")
    dest = tmp_path / "custom" / "out.zip"
    result = export_program_zip("g0out", output=dest)
    assert Path(result["zip_path"]) == dest.resolve()
    assert dest.is_file()


def test_export_missing_program_raises(home):
    with pytest.raises(FileNotFoundError):
        export_program_zip("missing-prog")


def test_cli_telemetry_status_and_export(home, monkeypatch):
    env = os.environ.copy()
    env["SENTINEL_HOME"] = str(home)
    env.pop("SENTINEL_TELEMETRY", None)
    create_program("g0cli")
    st = _run_cli(["telemetry", "status", "--json"], env)
    assert st.returncode == 0, st.stderr
    payload = json.loads(st.stdout)
    assert payload["enabled"] is False
    assert payload["phone_home"] is False

    exp = _run_cli(["program", "export", "g0cli", "--json"], env)
    assert exp.returncode == 0, exp.stderr
    meta = json.loads(exp.stdout)
    assert meta["program_id"] == "g0cli"
    assert meta["local_only"] is True
    assert Path(meta["zip_path"]).is_file()


def test_settings_payload_free_promise_and_telemetry(home):
    from sentinel_cli.ui_auth import setup_auth
    from sentinel_cli.ui_server import settings_payload

    setup_auth(action="skip_lab")
    out = settings_payload()
    assert out["phase"] == "G0"
    assert out["free_promise"]["account_required"] is False
    assert out["free_promise"]["card_required"] is False
    assert out["free_promise"]["calling_home_required"] is False
    assert "zip-export" in " ".join(out["free_promise"]["checklist"]).lower() or any(
        "zip" in c for c in out["free_promise"]["checklist"]
    )
    assert out["telemetry"]["enabled"] is False
    assert out["telemetry"]["phone_home"] is False
    assert out["fences"]["payments"] is False
    assert out["fences"]["guard_sdk"] is False
    assert out["fences"]["marketplace"] is False
    assert out["fences"]["sso"] is False
    assert out["fences"]["cloud_workers"] is False


def test_free_promise_docs_exist():
    assert (REPO / "docs" / "FREE_PROMISE.md").is_file()
    assert (REPO / "docs" / "PHASE_G0.md").is_file()
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "Free forever" in readme or "free forever" in readme.lower()
    assert "FREE_PROMISE" in readme
