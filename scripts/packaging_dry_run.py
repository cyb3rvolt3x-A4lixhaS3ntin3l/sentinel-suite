#!/usr/bin/env python3
"""Phase F — desktop packaging scaffolding dry-run (.dmg / .msi / AppImage+deb).

Validates Tauri bundle targets + docs/scripts. Does **not** claim CI green or
produce installers when tauri-cli / platform webview deps are missing.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src-tauri"
EXPECTED_TARGETS = ("dmg", "msi", "appimage", "deb")


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []
    blockers: list[str] = []

    conf_path = SRC / "tauri.conf.json"
    cargo_path = SRC / "Cargo.toml"
    main_rs = SRC / "src" / "main.rs"
    icon = SRC / "icons" / "icon.png"
    tauri_dry = REPO / "scripts" / "tauri_dry_run.py"
    pending = REPO / "docs" / "ci-pending" / "tauri.yml"
    install_doc = REPO / "docs" / "INSTALL.md"
    wsl_doc = REPO / "docs" / "WSL2.md"
    compose = REPO / "docker-compose.yml"
    dockerfile = REPO / "docker" / "Dockerfile"

    for p in (conf_path, cargo_path, main_rs, icon, tauri_dry, pending):
        if not p.is_file():
            errors.append(f"missing {p.relative_to(REPO)}")

    for p in (install_doc, wsl_doc, compose, dockerfile):
        if not p.is_file():
            warnings.append(f"missing docs/compose artifact {p.relative_to(REPO)}")

    conf = None
    targets: list[str] = []
    if conf_path.is_file():
        try:
            conf = json.loads(conf_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"tauri.conf.json invalid JSON: {exc}")
    if conf:
        targets = list(((conf.get("bundle") or {}).get("targets")) or [])
        for t in EXPECTED_TARGETS:
            if t not in targets:
                errors.append(f"bundle.targets missing {t!r} (Phase F scaffolding)")
        long_desc = ((conf.get("bundle") or {}).get("longDescription")) or ""
        if "Electron" in long_desc and "No Electron" not in long_desc:
            warnings.append("longDescription mentions Electron without 'No Electron'")

    cargo_bin = shutil.which("cargo")
    rustc = shutil.which("rustc")
    tauri_cli = False
    if cargo_bin:
        import subprocess

        try:
            out = subprocess.run(
                ["cargo", "tauri", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            tauri_cli = out.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            tauri_cli = False

    if not tauri_cli:
        blockers.append(
            "tauri-cli missing — `cargo tauri build` cannot produce "
            ".dmg/.msi/.AppImage/.deb until `cargo install tauri-cli` + platform webview deps"
        )
    if not rustc or not cargo_bin:
        blockers.append("rustc/cargo missing on PATH — required for full desktop builds")

    workflows = REPO / ".github" / "workflows"
    pushed = False
    if workflows.is_dir():
        pushed = any(workflows.glob("*.yml")) or any(workflows.glob("*.yaml"))
    if not pushed:
        blockers.append(
            "GitHub Actions workflow OAuth HOLD — packaging CI stays in "
            "docs/ci-pending/tauri.yml (do not invent green CI)"
        )

    # Electron fence
    if cargo_path.is_file():
        cargo_code = "\n".join(
            ln.split("#", 1)[0] for ln in cargo_path.read_text(encoding="utf-8").splitlines()
        ).lower()
        if "electron" in cargo_code:
            errors.append("Electron must not appear in Tauri Cargo.toml")

    report = {
        "ok": not errors,
        "phase": "F",
        "errors": errors,
        "warnings": warnings,
        "blockers": blockers,
        "bundle_targets": targets,
        "expected_targets": list(EXPECTED_TARGETS),
        "artifacts": {
            "dmg": "macOS (needs macOS runner + tauri-cli)",
            "msi": "Windows (needs windows runner + tauri-cli + WebView2)",
            "appimage": "Linux AppImage (needs linux + tauri-cli + webkit)",
            "deb": "Linux .deb (needs linux + tauri-cli + webkit)",
        },
        "tooling": {
            "rustc": bool(rustc),
            "cargo": bool(cargo_bin),
            "tauri_cli": tauri_cli,
        },
        "packaging_ci": {
            "pushed_workflows": pushed,
            "pending_doc": str(pending.relative_to(REPO)) if pending.is_file() else None,
        },
        "compose": {
            "docker_compose": compose.is_file(),
            "dockerfile": dockerfile.is_file(),
        },
        "electron": False,
        "note": (
            "Dry-run only validates scaffolding + honest blockers. "
            "Does not upload to PyPI or claim installer artifacts exist."
        ),
    }
    print(json.dumps(report, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
