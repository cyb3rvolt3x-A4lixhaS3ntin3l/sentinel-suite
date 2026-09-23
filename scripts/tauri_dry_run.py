#!/usr/bin/env python3
"""Phase D4/F — Tauri scaffold dry-run (dmg/msi/AppImage/deb; no inventing green CI)."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src-tauri"


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []

    conf_path = SRC / "tauri.conf.json"
    cargo_path = SRC / "Cargo.toml"
    main_rs = SRC / "src" / "main.rs"
    icon = SRC / "icons" / "icon.png"

    for p in (conf_path, cargo_path, main_rs, icon):
        if not p.is_file():
            errors.append(f"missing {p.relative_to(REPO)}")

    conf = None
    if conf_path.is_file():
        try:
            conf = json.loads(conf_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"tauri.conf.json invalid JSON: {exc}")

    if conf:
        build = conf.get("build") or {}
        dev_url = build.get("devUrl") or build.get("devPath")
        if dev_url != "http://127.0.0.1:8888":
            errors.append(
                f"devUrl must be http://127.0.0.1:8888 (got {dev_url!r}) — "
                "Tauri wraps the same loopback SPA"
            )
        targets = ((conf.get("bundle") or {}).get("targets")) or []
        for t in ("dmg", "msi", "appimage", "deb"):
            if t not in targets:
                warnings.append(f"bundle.targets missing {t!r} (scaffolding hint)")

    if cargo_path.is_file():
        cargo = cargo_path.read_text(encoding="utf-8")
        if "tauri" not in cargo:
            errors.append("Cargo.toml missing tauri dependency")
        cargo_code = "\n".join(
            ln.split("#", 1)[0] for ln in cargo.splitlines()
        ).lower()
        if "electron" in cargo_code:
            errors.append("Electron must not appear in Tauri Cargo.toml")

    if main_rs.is_file():
        main = main_rs.read_text(encoding="utf-8")
        if "tauri::Builder" not in main:
            errors.append("main.rs missing tauri::Builder")
        # Forbid Electron deps/imports (comments mentioning "no Electron" are OK)
        for line in main.splitlines():
            s = line.split("//", 1)[0].strip().lower()
            if "electron" in s:
                errors.append("Electron forbidden in main.rs code")
                break

    # Tooling presence (informational — missing tools ≠ failed scaffold)
    rustc = shutil.which("rustc")
    cargo_bin = shutil.which("cargo")
    tauri_cli = shutil.which("cargo-tauri") or (
        "yes" if cargo_bin and _cargo_has_tauri() else None
    )

    workflows = REPO / ".github" / "workflows"
    pushed = False
    if workflows.is_dir():
        pushed = any(workflows.glob("*.yml")) or any(workflows.glob("*.yaml"))
    pending = REPO / "docs" / "ci-pending" / "tauri.yml"

    report = {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "scaffold": {
            "src_tauri": SRC.is_dir(),
            "tauri_conf": conf_path.is_file(),
            "cargo_toml": cargo_path.is_file(),
            "main_rs": main_rs.is_file(),
            "icon": icon.is_file(),
        },
        "dev_url": "http://127.0.0.1:8888",
        "browser_first": True,
        "electron": False,
        "tooling": {
            "rustc": bool(rustc),
            "cargo": bool(cargo_bin),
            "tauri_cli": bool(tauri_cli),
            "note": (
                "Full `cargo tauri build` needs tauri-cli + platform webview deps. "
                "Dry-run only validates scaffold; does not claim packaging CI green."
            ),
        },
        "packaging_ci": {
            "pushed_workflows": pushed,
            "pending_doc": str(pending.relative_to(REPO)) if pending.is_file() else None,
            "blocked_note": (
                "Do not push new .github/workflows while OAuth HOLD. "
                "See docs/ci-pending/tauri.yml."
            ),
        },
    }
    print(json.dumps(report, indent=2))
    return 0 if not errors else 1


def _cargo_has_tauri() -> bool:
    import subprocess

    try:
        out = subprocess.run(
            ["cargo", "tauri", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return out.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


if __name__ == "__main__":
    sys.exit(main())
