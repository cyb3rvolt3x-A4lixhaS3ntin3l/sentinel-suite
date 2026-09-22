# Sentinel Suite

**Authorized attack-surface OSINT that watches (ShadowsEye) + hunt packs that prove (Gungnir) on a shared event graph and scope kernel (`sentinel_core`).**

| | |
| --- | --- |
| **Brand** | Sentinel Suite (umbrella); product names ShadowsEye + Gungnir |
| **Status** | **Phase B slice1 shipped** — Eye L0/L2/L5 lite + interestingness ranker + watch diffs; Phase A core intact. Next: deeper CT / L1 lite / engine hash pins. |
| **Not yet** | Full L1/L3/L4, Hunt Packs UI, coach, Tauri, PyPI publish |

Monorepo: [cyb3rvolt3x-A4lixhaS3ntin3l/sentinel-suite](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/sentinel-suite)

## One-screen install + doctor / eye / hunt

PyPI is **not** published yet. Editable install from clone:

```bash
git clone https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/sentinel-suite.git
cd sentinel-suite
python3 -m venv .venv && source .venv/bin/activate
pip install -U pip pytest
pip install -e packages/sentinel_core \
            -e packages/shadowseye \
            -e packages/gungnir \
            -e packages/sentinel_cli
pytest -q
sentinel doctor
sentinel program init demo
sentinel program import-brief demo ./brief.txt --platform auto
sentinel eye run demo example.com --i-own-this --no-ports
sentinel hunt run demo --title 'lab finding' --host example.com --i-own-this
```

`eye` / `hunt` require `--scope FILE` **or** `--i-own-this` (lab override).

Phase B Eye flags: `--json` (full ranked inventory) · `--watch` (persist diffs) · `--no-tools` (default; engines deferred until allowlist hashes).
```bash
sentinel eye run demo example.com --i-own-this --json --watch --no-tools
```

**Future pipx story (branding only; not published):**

```text
pipx install shadowseye          # Eye only
pipx install gungnir             # Gungnir only
pipx install sentinel-suite      # both + `sentinel` CLI
```

## What Phase A shipped

- **Briefs:** `parse_brief` / `detect_brief_platform` (`auto|h1|bugcrowd|generic|raw`)
- **HTTP hard-kill:** `assert_url_in_scope` / `scoped_request` — host checked before any network
- **Engines:** allowlist-only download under `SENTINEL_HOME/bin/` (sha256; never mutates PATH). Allowlist empty until hashes pinned — see [`docs/ENGINES.md`](docs/ENGINES.md)
- **Bridges:** Eye → DOMAIN/DNS_NAME/IP/OPEN_PORT; Hunt → FINDING/EVIDENCE
- **CLI:** `sentinel doctor` · `program init|import-brief` · `eye run` · `hunt run`

Milestone SHAs: [`docs/SPRINT0.md`](docs/SPRINT0.md)

## Architecture (honest)

- **ShadowsEye (Eye)** — watches attack surface; feeds the graph (interestingness + diffs = Phase B)
- **Gungnir (Hunt)** — proves findings with packs/evidence; does not remap unless asked
- **`sentinel_core`** — event schema v1, SQLite WAL per program under `SENTINEL_HOME` (default `~/.sentinel`), scope kernel (OOS = hard kill), engine pin under `~/.sentinel/bin/`
- Thin **bridges** are **not** ports of the live ShadowsEye/Gungnir CLIs
- **workers/** stub for future Go/Rust hot-path bins
- **Guard SDK / `sentinelagent-guard`** — separate product; **never** touched here

Live public `gungnir` + `ShadowsEye` repos are **thin README mirrors** pointing here. Prefer this monorepo for new suite work.

## Ethics fence

- **Authorized use only** — bug bounty / pentest / your own assets with written permission
- **No malware, no destructive exploit PoCs, no other-customer harm**
- **Guard SDK untouched**
- **No stalking defaults** (username/email OSINT extras stay opt-in later)
- Secrets stay `SECRET_CANDIDATE` until human/Gungnir proves in-scope use
- No invented stars, users, or CVEs in docs

## License

**MIT** (consistency with live ShadowsEye / Gungnir). Founder preference Apache-2.0 — see [`docs/LICENSE_NOTE.md`](docs/LICENSE_NOTE.md).

## Docs

| Doc | Purpose |
| --- | --- |
| [`docs/ENGINES.md`](docs/ENGINES.md) | Allowlist vs deferred engines |
| [`docs/HUMAN-QUEUE.md`](docs/HUMAN-QUEUE.md) | CI OAuth, Apache decision, PyPI, Guard never |
| [`docs/LICENSE_NOTE.md`](docs/LICENSE_NOTE.md) | MIT vs Apache preference |
| [`docs/SPRINT0.md`](docs/SPRINT0.md) | Phase A milestones + SHAs |
| [`docs/SPRINT0_REVIEW.md`](docs/SPRINT0_REVIEW.md) | Short Founder review pointer |

## Layout

```text
packages/sentinel_core   # schema, graph, scope, engines
packages/shadowseye      # Eye bridge + thin runner
packages/gungnir         # Hunt bridge + thin runner + thin correlate
packages/sentinel_cli    # `sentinel` → doctor, program, eye, hunt
docs/                    # ENGINES, HUMAN-QUEUE, LICENSE_NOTE, SPRINT0*
workers/                 # Go later (README only)
tests/                   # suite tests
```

## Maintainers

Product north star (box): `/workspace/deliverables/SENTINEL_SUITE_GODLEVEL_PLAN_2026-09-22.md`  
Founder review packet (box): `/workspace/deliverables/SENTINEL_SUITE_SPRINT0_REVIEW.md`
