# Productization packaging (step 2)

Ship note (artifacts, checksums, platform honesty):

→ [`/workspace/deliverables/SENTINEL_SUITE_PRODUCTIZATION_PACKAGING.md`](/workspace/deliverables/SENTINEL_SUITE_PRODUCTIZATION_PACKAGING.md)

In-repo summary lives with deliverables; this file is the repo pointer for README / INSTALL links.

**Quick truth**

| Platform | Status |
| --- | --- |
| Install path/git + Docker Compose | **SHIPPED** (primary) |
| Linux CLI PyInstaller one-file | **SHIPPED** on Release (UNSIGNED) |
| Windows `.exe` | **SCRIPT-ONLY** (`scripts/build_pyinstaller_windows.ps1`) |
| macOS `.app`/`.dmg` | **BLOCKED** (no Mac builder / no notarization) |
| Linux Tauri AppImage | **BLOCKED** (`tauri-cli` missing) |
| PyPI / signed / notarized | **NOT claimed** |

See also: [`INSTALL.md`](INSTALL.md), [`PRODUCTIZATION_RESEARCH.md`](PRODUCTIZATION_RESEARCH.md), [`PRODUCTIZATION_DEMOS.md`](PRODUCTIZATION_DEMOS.md).
