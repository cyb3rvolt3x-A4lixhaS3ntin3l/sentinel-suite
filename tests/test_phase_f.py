"""Phase F — distribution + doctor degrade + packaging dry-runs + WSL helpers."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel_cli.doctor import (
    OPTIONAL_API_KEY_ENVS,
    check_optional_api_keys,
    check_port_scan_tools,
    check_wsl,
    format_doctor_extras,
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


def test_doctor_pass_with_phase_f_sections(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    # Ensure optional keys look missing
    for k in OPTIONAL_API_KEY_ENVS:
        monkeypatch.delenv(k, raising=False)
    env = dict(os.environ)
    env["SENTINEL_HOME"] = str(home)
    for k in OPTIONAL_API_KEY_ENVS:
        env.pop(k, None)
    proc = _run_cli(["doctor"], env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert "doctor: PASS" in out
    assert "port-scan tools:" in out
    assert "Nmap missing" in out or "nmap:" in out.lower()
    assert "optional api keys" in out.lower()
    assert "WSL/Windows:" in out or "wsl" in out.lower()
    assert "product_ok" in out or "degrade" in out.lower() or "Naabu" in out


def test_doctor_still_pass_when_fake_windows_wsl_missing(tmp_path, monkeypatch):
    """Degrade path must not flip doctor to FAIL when core is healthy."""
    home = tmp_path / "home"
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    # Force Windows-like platform reporting inside helpers via monkeypatch
    import sentinel_cli.doctor as doc

    monkeypatch.setattr(doc, "_is_windows", lambda: True)
    monkeypatch.setattr(doc.shutil, "which", lambda name: None)
    wsl = check_wsl()
    assert wsl["product_ok"] is True
    assert wsl["wsl_found"] is False
    assert "WSL not found" in wsl["messaging"] or "not found" in wsl["messaging"].lower()

    env = dict(os.environ)
    env["SENTINEL_HOME"] = str(home)
    proc = _run_cli(["doctor"], env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "doctor: PASS" in proc.stdout


def test_check_port_scan_degrade_without_nmap(tmp_path):
    # Point home_bin at empty dir so local nmap/naabu are absent; PATH may still
    # have nmap — assert product_ok and structured keys always.
    out = check_port_scan_tools(home_bin=tmp_path / "bin")
    assert out["product_ok"] is True
    assert out["mode"] in {"nmap", "naabu-class", "stdlib-tcp"}
    assert "messaging" in out
    if out["nmap_path"] is None:
        assert out["degrade"] is True
        assert "Naabu" in out["messaging"] or "naabu" in out["messaging"].lower()


def test_check_optional_api_keys_none_required(monkeypatch):
    for k in OPTIONAL_API_KEY_ENVS:
        monkeypatch.delenv(k, raising=False)
    out = check_optional_api_keys()
    assert out["required"] == []
    assert out["product_ok"] is True
    assert out["present"] == []
    assert "none required" in out["messaging"].lower()


def test_check_optional_api_keys_present_reported(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test-not-a-real-key")
    out = check_optional_api_keys()
    assert "SHODAN_API_KEY" in out["present"]
    assert out["product_ok"] is True


def test_check_wsl_native_unix():
    out = check_wsl()
    assert out["product_ok"] is True
    assert "guidance" in out
    assert "messaging" in out


def test_format_doctor_extras_lines(tmp_path):
    lines, payload = format_doctor_extras(home_bin=tmp_path / "bin")
    assert any("port-scan" in ln for ln in lines)
    assert any("API" in ln or "api" in ln.lower() for ln in lines)
    assert any("WSL" in ln for ln in lines)
    assert payload["product_ok"] is True


def test_packaging_dry_run_script():
    script = REPO / "scripts" / "packaging_dry_run.py"
    assert script.is_file()
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads(proc.stdout)
    assert report["ok"] is True
    assert report["phase"] == "F"
    for t in ("dmg", "msi", "appimage", "deb"):
        assert t in report["bundle_targets"]
    assert report["electron"] is False
    assert report["compose"]["docker_compose"] is True
    assert report["compose"]["dockerfile"] is True
    # Honest blockers expected in this environment
    assert isinstance(report["blockers"], list)


def test_tauri_dry_run_includes_deb():
    script = REPO / "scripts" / "tauri_dry_run.py"
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads(proc.stdout)
    assert report["ok"] is True
    conf = json.loads((REPO / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
    targets = conf["bundle"]["targets"]
    assert "deb" in targets
    assert "dmg" in targets
    assert "msi" in targets
    assert "appimage" in targets


def test_compose_and_dockerfile_exist():
    compose = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    assert "sentinel-suite" in compose
    assert "127.0.0.1:8888:8888" in compose
    assert "--i-understand-lab" in compose
    df = (REPO / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert "sentinel-suite" in df or "sentinel_suite" in df
    assert "sentinel" in df


def test_install_and_wsl_docs_exist():
    install = REPO / "docs" / "INSTALL.md"
    wsl = REPO / "docs" / "WSL2.md"
    assert install.is_file()
    assert wsl.is_file()
    it = install.read_text(encoding="utf-8")
    assert "pipx" in it.lower()
    assert "sentinel-suite" in it
    assert "not" in it.lower() and "published" in it.lower()
    wt = wsl.read_text(encoding="utf-8")
    assert "WSL2" in wt
    assert "127.0.0.1:8888" in wt


def test_meta_package_importable():
    import sentinel_suite

    assert getattr(sentinel_suite, "__version__", None)


def test_brand_shadowseye_cli_version():
    proc = subprocess.run(
        [sys.executable, "-m", "shadowseye.cli", "version"],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO),
        env={**os.environ, "PYTHONPATH": os.pathsep.join(
            [
                str(REPO / "packages" / "shadowseye" / "src"),
                str(REPO / "packages" / "sentinel_core" / "src"),
                os.environ.get("PYTHONPATH", ""),
            ]
        )},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "shadowseye" in proc.stdout.lower()


def test_brand_gungnir_cli_packs():
    proc = subprocess.run(
        [sys.executable, "-m", "gungnir.cli", "packs"],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO),
        env={**os.environ, "PYTHONPATH": os.pathsep.join(
            [
                str(REPO / "packages" / "gungnir" / "src"),
                str(REPO / "packages" / "sentinel_core" / "src"),
                os.environ.get("PYTHONPATH", ""),
            ]
        )},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert isinstance(data, list)
    assert len(data) >= 12  # Phase C freeze


def test_pyproject_console_scripts_declared():
    import tomllib

    sh = tomllib.loads((REPO / "packages" / "shadowseye" / "pyproject.toml").read_text())
    assert sh["project"]["scripts"]["shadowseye"].endswith(":main")
    gu = tomllib.loads((REPO / "packages" / "gungnir" / "pyproject.toml").read_text())
    assert gu["project"]["scripts"]["gungnir"].endswith(":main")
    meta = tomllib.loads((REPO / "packages" / "sentinel_suite" / "pyproject.toml").read_text())
    assert meta["project"]["name"] == "sentinel-suite"
    assert meta["project"]["scripts"]["sentinel"].endswith(":main")
    cli = tomllib.loads((REPO / "packages" / "sentinel_cli" / "pyproject.toml").read_text())
    assert cli["project"]["scripts"]["sentinel"].endswith(":main")


def test_engine_allowlist_still_empty():
    from sentinel_core import ENGINE_ALLOWLIST

    assert ENGINE_ALLOWLIST == {}


def test_phase_c_pack_count_frozen():
    from gungnir.packs import list_pack_manifests

    assert len(list_pack_manifests()) == 12


def test_labs_intact():
    from sentinel_cli.ui_labs import labs_payload

    labs = {row["lab_id"] for row in labs_payload()["labs"]}
    assert {"juice-shop", "crapi", "auth-session"} <= labs
