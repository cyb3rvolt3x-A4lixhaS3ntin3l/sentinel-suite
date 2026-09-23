# Install — pip / pipx / path / git / Docker / binaries (productization)

**Honesty:** PyPI wheels are **not** published yet. Do not invent `pipx install …` success from an index. Use path/git editable installs (or Compose) as the **primary** multi-OS path. Optional GitHub Release binaries are **UNSIGNED** unless a note says otherwise — no Authenticode, no Apple notarization claimed.

## Brand package names

| Install name | Console scripts | Role |
| --- | --- | --- |
| `shadowseye` | `shadowseye` | Eye only |
| `gungnir` | `gungnir` | Hunt packs list / brand entry |
| `sentinel-suite` | `sentinel` | Meta → full CLI (doctor, eye, hunt, ui, lab) |
| `sentinel-cli` | `sentinel` | Same CLI without meta package |

## Path / git (recommended today)

```bash
git clone https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/sentinel-suite.git
cd sentinel-suite
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -U pip pytest
pip install -e packages/sentinel_core \
            -e packages/shadowseye \
            -e packages/gungnir \
            -e packages/sentinel_cli \
            -e packages/sentinel_suite
pytest -q
sentinel doctor
```

### pipx from a local path (no PyPI)

```bash
# After clone — inject editable deps or install meta from path:
pipx install ./packages/sentinel_suite --python python3
# Brand-only examples (thin CLIs):
pipx install ./packages/shadowseye
pipx install ./packages/gungnir
```

`pipx install shadowseye` **from PyPI** is the future story — not claimed until publish.

## Doctor (always safe to run)

```bash
sentinel doctor
```

Doctor **PASS** means core Python + `SENTINEL_HOME` + event schema are healthy. Missing **Nmap**, optional **API keys**, or **WSL** only prints degrade guidance — they do **not** fail the product.

- Nmap missing → Naabu-class messaging + Eye stdlib TCP connect (default)
- Optional keys (`SHODAN_API_KEY`, …) → none required for core
- WSL → see [`WSL2.md`](WSL2.md)

## Docker Compose (clean-room UI + engine)

```bash
docker compose up --build
# → http://127.0.0.1:8888  (host loopback only)
docker compose exec suite sentinel doctor
```

Inside the container the UI binds `0.0.0.0` with `--i-understand-lab` so port publishing works; the **host** mapping stays `127.0.0.1:8888`. Labs (Juice Shop / crAPI) stay optional — see lab docs / README.

## Desktop packaging (Tauri) — scaffold / dry-run

Browser remains first-class (`sentinel ui --open` → http://127.0.0.1:8888).

```bash
python scripts/tauri_dry_run.py
python scripts/packaging_dry_run.py   # dmg / msi / AppImage / deb scaffold + blockers
# Full Tauri installers need tauri-cli + platform webview deps on each OS:
#   cargo install tauri-cli --version "^2"
#   cargo tauri build
```

**Do not claim** shipped `.dmg` / `.msi` / `.AppImage` / notarization unless a Release asset exists.
Packaging CI stays under [`ci-pending/tauri.yml`](ci-pending/tauri.yml) while workflow OAuth is HOLD (do not push new workflows).



## One-click-ish paths (truthful)

| Path | Platforms | Notes |
| --- | --- | --- |
| **git + venv + pip -e** (recommended) | Linux / macOS / Windows | Guaranteed. Commands above. |
| **Docker Compose** | Linux / macOS / Windows+Docker | `docker compose up --build` → http://127.0.0.1:8888 |
| **pipx from local path** | same | Still **not** PyPI index install |
| **GitHub Release CLI binary** | Linux x86_64 verified when attached | **UNSIGNED** PyInstaller one-file; verify SHA256 |
| **Windows `.exe`** | Only if Release lists it | Build on Windows via `scripts/build_pyinstaller_windows.ps1`. SmartScreen expected. Prefer WSL2 — see [`WSL2.md`](WSL2.md). |
| **macOS `.app` / `.dmg`** | **Not shipped** from Linux CI | Needs Mac builder + Gatekeeper honesty; stub: `scripts/build_macos_stub.sh` |
| **Linux AppImage (Tauri)** | Blocked until `tauri-cli` + webkit deps | Stub: `scripts/build_appimage_linux.sh` |

Primary install remains **path/git** or **Compose**. Binaries are secondary convenience.

## UI webopen

```bash
sentinel ui --open          # open default browser after bind (loopback)
sentinel ui --no-open       # never open (Compose/CI default)
# Env: SENTINEL_UI_OPEN=1|0 · SENTINEL_NO_OPEN=1 · CI=1 implies no-open unless --open
```

Default policy: open on interactive TTY + loopback bind; off in CI / non-TTY / Docker. Non-loopback binds do **not** auto-open unless you pass `--open` (display URL still prefers `127.0.0.1` for Docker publish).

## Demo / full-run (CLI without relying on GUI)

```bash
# Demo: doctor → optional lab → UI with webopen (does NOT scan random hosts)
sentinel demo
sentinel demo --lab juice-shop --no-open

# Full CLI path against OWNED / in-scope targets only:
sentinel full-run --program myprog --target example.com \
  --scope ~/.sentinel/programs/myprog/scope.txt
# optional: --pack open_redirect --url https://example.com/ --ui
```

`full-run` refuses to start without `--target` and `--scope` / `--i-own-this`. Never points at random internet hosts.

## Optional Release binaries

See GitHub Releases for tagged assets + `SHA256SUMS`. Every binary lacking a vendor signature must be treated as **UNSIGNED**. Packaging ship note: [`PRODUCTIZATION_PACKAGING.md`](PRODUCTIZATION_PACKAGING.md).

```bash
# Linux builder (this repo):
./scripts/build_pyinstaller_linux.sh   # → dist/sentinel-linux-$(uname -m) UNSIGNED
# Windows (on Windows):
#   .\scripts\build_pyinstaller_windows.ps1
# macOS / AppImage:
./scripts/build_macos_stub.sh          # exits 2 — documents blocker
./scripts/build_appimage_linux.sh      # exits 2 unless tauri-cli present
```

## Engine allowlist

`ENGINE_ALLOWLIST` is **empty** — no invented third-party hashes. See [`ENGINES.md`](ENGINES.md).

## Free promise (Phase G0)

No account, no credit card, and no calling home are required for the local suite.
See [`FREE_PROMISE.md`](FREE_PROMISE.md). Telemetry is **OFF** unless you set
`SENTINEL_TELEMETRY=1` (local JSONL stub only — no phone-home in G0).

```bash
sentinel program export <program_id>   # offline zip of ~/.sentinel/programs/<id>/
sentinel telemetry status
```
