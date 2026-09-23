# Windows + WSL2

Productization is complete. Historical build-phase notes live in `docs/PHASE_*`.

**Product stance:** On Windows, **WSL2 is the first-class engine backend**. The browser/UI may stay on Windows and talk to the engine on loopback.

## Recommended topology

```text
┌────────────────────────── Windows ──────────────────────────┐
│  Browser / optional Tauri shell                             │
│       │  http://127.0.0.1:8888                              │
│       ▼                                                     │
│  localhost forward ───────────────────────────────────────  │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼── WSL2 (Linux) ──────────────────┐
│  Python venv + sentinel CLI                                 │
│  sentinel ui --open --bind 127.0.0.1 --port 8888            │
│  sentinel doctor / eye / hunt / lab                         │
│  optional: docker compose (labs + suite)                    │
└─────────────────────────────────────────────────────────────┘
```

## Native Windows vs WSL2

| Path | Guidance |
| --- | --- |
| **WSL2 engine (recommended)** | Install Ubuntu (or similar) via `wsl --install`. Clone repo inside the distro. `pip install -e …` then `sentinel ui`. Open http://127.0.0.1:8888 from Windows browser. |
| **Native Windows Python** | Pure-Python Eye/Hunt/UI can run, but Linux-oriented binaries (future allowlisted engines), Docker labs, and Nmap packaging are smoother in WSL2. Doctor reports `WSL not found` as degrade guidance — **does not fail**. |
| **Native Linux / macOS** | Engine runs natively; WSL N/A. |

## Test path (automated)

Unit tests cover detection helpers in `sentinel_cli.doctor`:

- `check_wsl()` — Windows host ± `wsl` on PATH; WSL guest (`microsoft` in release); native Unix
- Doctor CLI still exits **0** when WSL is missing (core healthy)

Manual smoke (operator):

```powershell
# Windows PowerShell
wsl --status
wsl -e bash -lc 'cd ~/sentinel-suite && source .venv/bin/activate && sentinel doctor && sentinel ui --open'
# then browse http://127.0.0.1:8888 from Windows
```

## Doctor messaging

```bash
sentinel doctor
# … WSL/Windows: platform=… wsl_found=… …
# Missing WSL → guidance only; doctor: PASS when core OK
```

## Tauri on Windows

Tauri `.msi` scaffolding exists (`src-tauri`, bundle target `msi`). Full build needs Windows WebView2 + `tauri-cli`. Until packaging CI OAuth is unblocked, use:

```bash
python scripts/packaging_dry_run.py
```

Browser-first UI remains supported without any desktop installer.

## Fences

- Default UI bind remains loopback
- No Electron
- No invented “Windows native engine parity” claims
