"""Phase F — structured doctor checks with graceful degrade (never product hard-fail on optional tools)."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any


# Optional third-party keys — core Eye/Hunt do **not** require these.
# Doctor only reports presence/absence honestly (no invented integrations).
OPTIONAL_API_KEY_ENVS: tuple[str, ...] = (
    "SHODAN_API_KEY",
    "SECURITYTRAILS_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "VIRUSTOTAL_API_KEY",
    "GITHUB_TOKEN",
)

# Port-scan tooling story (honest):
# - Eye default = bounded stdlib TCP connect (no Nmap required).
# - Nmap = optional richer scanner if present on PATH / SENTINEL_HOME/bin.
# - Naabu = deferred engine (not allowlisted); messaging when Nmap missing.
NMAP_NAMES: tuple[str, ...] = ("nmap",)
NAABU_NAMES: tuple[str, ...] = ("naabu",)


def _which_any(names: tuple[str, ...], *, home_bin: Path | None = None) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
        if home_bin is not None:
            local = home_bin / name
            if local.is_file() and os.access(local, os.X_OK):
                return str(local)
    return None


def check_port_scan_tools(home_bin: Path | None = None) -> dict[str, Any]:
    """
    Report Nmap / Naabu availability with degrade guidance.

    Missing tools never imply product failure — Eye uses socket probes by default.
    """
    nmap_path = _which_any(NMAP_NAMES, home_bin=home_bin)
    naabu_path = _which_any(NAABU_NAMES, home_bin=home_bin)

    if nmap_path:
        mode = "nmap"
        messaging = (
            f"Nmap detected @ {nmap_path}. Eye still defaults to bounded TCP connect "
            "unless you explicitly wire an external scanner later."
        )
        degrade = False
    elif naabu_path:
        mode = "naabu-class"
        messaging = (
            f"Nmap missing; Naabu-class binary detected @ {naabu_path}. "
            "Prefer Naabu-class / deferred tooling messaging until Nmap is installed. "
            "Eye continues with stdlib TCP connect probes (default)."
        )
        degrade = True
    else:
        mode = "stdlib-tcp"
        messaging = (
            "Nmap missing — degrading port scan story to Naabu-class messaging "
            "(Naabu is deferred / not allowlisted yet) and Eye stdlib TCP connect. "
            "Product remains usable; install Nmap optionally for richer scans later."
        )
        degrade = True

    return {
        "nmap_path": nmap_path,
        "naabu_path": naabu_path,
        "mode": mode,
        "degrade": degrade,
        "messaging": messaging,
        "product_ok": True,
    }


def check_optional_api_keys() -> dict[str, Any]:
    """
    Report optional API key env vars.

    Core suite does not require any of these. Missing keys → informational only.
    """
    present: list[str] = []
    missing: list[str] = []
    for name in OPTIONAL_API_KEY_ENVS:
        val = os.environ.get(name)
        if val and str(val).strip():
            present.append(name)
        else:
            missing.append(name)

    messaging = (
        "Optional API keys: none required for core Eye/Hunt/UI. "
        + (
            f"Present (not claimed as wired integrations): {', '.join(present)}. "
            if present
            else "None of the common optional keys are set. "
        )
        + "Missing keys do not fail doctor or block the product."
    )
    return {
        "required": [],
        "present": present,
        "missing": missing,
        "messaging": messaging,
        "product_ok": True,
    }


def _is_windows() -> bool:
    return sys.platform.startswith("win") or platform.system().lower() == "windows"


def check_wsl() -> dict[str, Any]:
    """
    Windows / WSL2 detection for doctor.

    On native Linux: report that WSL is N/A (engine already native).
    On Windows: look for `wsl.exe` / `wsl`; missing → guidance, not failure.
    """
    system = platform.system()
    machine = platform.machine()
    release = platform.release()

    # WSL guest often reports Linux + microsoft in release
    release_l = (release or "").lower()
    in_wsl_guest = "microsoft" in release_l or "wsl" in release_l

    if _is_windows():
        wsl_bin = shutil.which("wsl") or shutil.which("wsl.exe")
        if wsl_bin:
            messaging = (
                f"Windows host: WSL found @ {wsl_bin}. "
                "Recommended: run the Linux engine inside WSL2; UI may stay on Windows "
                "pointing at http://127.0.0.1:8888 (see docs/WSL2.md)."
            )
            return {
                "platform": "windows",
                "wsl_found": True,
                "wsl_path": wsl_bin,
                "in_wsl_guest": False,
                "guidance": "ui-windows-engine-wsl2",
                "messaging": messaging,
                "product_ok": True,
            }
        messaging = (
            "Windows host: WSL not found. Product still runs for browser UI + pure-Python "
            "paths, but Linux engine binaries / Docker labs prefer WSL2. "
            "Install WSL2 (wsl --install) or use native Linux/macOS — see docs/WSL2.md. "
            "Missing WSL does not fail doctor."
        )
        return {
            "platform": "windows",
            "wsl_found": False,
            "wsl_path": None,
            "in_wsl_guest": False,
            "guidance": "install-wsl2-or-use-native-linux",
            "messaging": messaging,
            "product_ok": True,
        }

    # Linux / Darwin / other
    if in_wsl_guest:
        messaging = (
            f"Running inside WSL guest ({system} {release}). "
            "Good path: keep engine here; Windows UI/browser can open "
            "http://127.0.0.1:8888 (localhost forwarded). See docs/WSL2.md."
        )
        return {
            "platform": system.lower(),
            "wsl_found": True,
            "wsl_path": None,
            "in_wsl_guest": True,
            "guidance": "engine-in-wsl-guest",
            "messaging": messaging,
            "machine": machine,
            "product_ok": True,
        }

    messaging = (
        f"Native {system} ({machine}) — WSL not applicable. "
        "Engine runs natively; Windows users should prefer WSL2 for the engine backend "
        "(docs/WSL2.md)."
    )
    return {
        "platform": system.lower(),
        "wsl_found": False,
        "wsl_path": None,
        "in_wsl_guest": False,
        "guidance": "native-unix",
        "messaging": messaging,
        "machine": machine,
        "product_ok": True,
    }


def format_doctor_extras(
    *,
    home_bin: Path | None = None,
) -> tuple[list[str], dict[str, Any]]:
    """Return human lines + structured payload for Phase F doctor sections."""
    port = check_port_scan_tools(home_bin)
    keys = check_optional_api_keys()
    wsl = check_wsl()

    lines: list[str] = []
    lines.append(f"port-scan tools: mode={port['mode']} (product_ok=yes)")
    lines.append(f"  nmap: {port['nmap_path'] or '(missing)'}")
    lines.append(f"  naabu: {port['naabu_path'] or '(missing — deferred engine)'}")
    lines.append(f"  note: {port['messaging']}")

    lines.append("optional API keys: none required for core")
    if keys["present"]:
        lines.append(f"  present: {', '.join(keys['present'])}")
    else:
        lines.append("  present: (none)")
    lines.append(f"  note: {keys['messaging']}")

    lines.append(
        f"WSL/Windows: platform={wsl.get('platform')} "
        f"wsl_found={wsl.get('wsl_found')} in_guest={wsl.get('in_wsl_guest')}"
    )
    lines.append(f"  guidance: {wsl.get('guidance')}")
    lines.append(f"  note: {wsl['messaging']}")

    payload = {
        "port_scan": port,
        "api_keys": keys,
        "wsl": wsl,
        "product_ok": True,
    }
    return lines, payload


__all__ = [
    "OPTIONAL_API_KEY_ENVS",
    "check_optional_api_keys",
    "check_port_scan_tools",
    "check_wsl",
    "format_doctor_extras",
]
