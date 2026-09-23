# Install — pip / pipx / path / git / Docker (Phase F)

**Honesty:** PyPI wheels are **not** published yet. Do not invent `pipx install …` success from an index. Use path/git editable installs (or Compose) until Founder publishes.

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

## Desktop packaging (Tauri)

Browser remains first-class (`sentinel ui` → http://127.0.0.1:8888).

```bash
python scripts/tauri_dry_run.py
python scripts/packaging_dry_run.py   # dmg / msi / AppImage / deb scaffold + blockers
# Full installers need tauri-cli + platform webview deps:
#   cargo install tauri-cli --version "^2"
#   cargo tauri build
```

Packaging CI stays under [`ci-pending/tauri.yml`](ci-pending/tauri.yml) while workflow OAuth is HOLD.

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
