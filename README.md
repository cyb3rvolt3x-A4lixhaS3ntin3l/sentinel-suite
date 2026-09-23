# Sentinel Suite

**Authorized attack-surface OSINT that watches (ShadowsEye) + hunt packs that prove (Gungnir) on a shared event graph and scope kernel (`sentinel_core`).**

| | |
| --- | --- |
| **Brand** | Sentinel Suite (umbrella); product names ShadowsEye + Gungnir |
| **Status** | **Phase E2 shipped** — Coach lab-aware + Open Lab catalog (juice-shop · crapi · auth-session) on `sentinel ui` / `sentinel lab`; D0–D4 intact; Phase C frozen (12 packs / tip `d91394b`); Engine hashes **HOLD** (allowlist empty). |
| **Not yet** | Full L1/L3/L4, live third-party cloud-metadata campaigns, PyPI publish; Tauri packaging CI (OAuth HOLD — see docs/ci-pending/tauri.yml) |

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
sentinel lab list
sentinel lab open juice-shop --program lab-juice-shop
# also: sentinel lab open crapi --program lab-crapi
# also: sentinel lab open auth-session --program lab-auth-session
# start Juice Shop (lab-only): docker run --rm -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
sentinel lab attempt lab-juice-shop js-admin-section --note 'tried admin'
sentinel lab hints lab-juice-shop js-admin-section
sentinel ui
# → http://127.0.0.1:8888  (Labs tab = Open Lab) (127.0.0.1 only by default)
# Desktop wrap (optional): start API above, then `cargo tauri dev` (loads same URL)
# Dry-run scaffold: python scripts/tauri_dry_run.py
sentinel program init demo
sentinel program import-brief demo ./brief.txt --platform auto
sentinel eye run demo example.com --i-own-this --no-ports
sentinel hunt run demo --title 'lab finding' --host example.com --i-own-this
sentinel hunt pack list
sentinel hunt pack run ato_oauth_oidc --program demo --i-own-this \
  --url 'https://lab.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://lab.example/cb'
sentinel hunt report demo --pack ato_oauth_oidc -o ./report.md
sentinel hunt pack run bola_idor_bfla --program demo --i-own-this \
  --role-a ./roles/a.json --role-b ./roles/b.json
sentinel hunt report demo --pack bola_idor_bfla -o ./bola-report.md
sentinel hunt pack run business_logic --program demo --i-own-this
sentinel hunt report demo --pack business_logic -o ./bl-report.md
sentinel hunt pack run race_toctou --program demo --i-own-this --i-understand-lab
sentinel hunt pack run race_toctou --program demo --i-own-this --i-understand-lab \
  --max-workers 4 --max-requests 20 --max-duration 5
sentinel hunt report demo --pack race_toctou -o ./race-report.md
sentinel hunt pack run graphql --program demo --i-own-this
sentinel hunt pack run graphql --program demo --i-own-this --role-a ./roles/a.json
sentinel hunt report demo --pack graphql -o ./graphql-report.md
sentinel hunt pack run xss_dom --program demo --i-own-this
sentinel hunt report demo --pack xss_dom -o ./xss-report.md
sentinel hunt pack run csrf_state --program demo --i-own-this
sentinel hunt report demo --pack csrf_state -o ./csrf-report.md
sentinel hunt pack run open_redirect --program demo --i-own-this
sentinel hunt report demo --pack open_redirect -o ./or-report.md
sentinel hunt pack run cache_host --program demo --i-own-this
sentinel hunt report demo --pack cache_host -o ./cache-host-report.md
sentinel hunt pack run jwt_session --program demo --i-own-this
sentinel hunt report demo --pack jwt_session -o ./jwt-session-report.md
sentinel hunt pack run http_desync --program demo --i-own-this
sentinel hunt pack run http_desync --program demo --i-own-this --i-understand-lab
sentinel hunt report demo --pack http_desync -o ./http-desync-report.md
sentinel collaborator serve --program demo
sentinel collaborator serve --program demo --bind 127.0.0.1 --port 8765
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this --listen
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this \
  --collaborator http://127.0.0.1:9999/cb
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this --i-understand-lab
sentinel hunt pack run ssrf_collaborator --program demo --scope ./scope.txt \
  --i-own-this --i-understand-lab --url 'https://staging.example/'
sentinel hunt report demo --pack ssrf_collaborator -o ./ssrf-collaborator-report.md
sentinel hunt confirm-finding demo <finding-id> --status confirmed --note 'lab review' --mark-role a
```

`eye` / `hunt` require `--scope FILE` **or** `--i-own-this` (lab override).
Hunt packs need Role A at `roles/a.json` (`cookies|headers|bearer`) unless `needs_roles=0` (`graphql` / `xss_dom` / `csrf_state` / `open_redirect` / `cache_host` / `jwt_session` / `http_desync` / `ssrf_collaborator` — Role A optional); `bola_idor_bfla` also requires Role B at `roles/b.json`. All pack findings stay `needs_human` / `unverified` until `sentinel hunt confirm-finding` (note required; packs never auto-confirm). `http_desync` / `ssrf_collaborator` beyond pure fixtures also require `--i-understand-lab` (with `--i-own-this`); open-internet needs `--scope` too. `ssrf_collaborator` defaults to a local 127.0.0.1 collaborator mock; `--listen` starts an owned localhost listener (COLLABORATOR_HIT); `--collaborator` must be operator-owned and refuses cloud metadata IPs unless lab fixture mode + `--i-understand-lab`. Public bind (`0.0.0.0`) needs `--i-understand-lab`; no interactsh / outbound scan.

Phase B Eye flags: `--json` · `--watch` · `--no-tools` (default) · `--no-identity` · `--no-reverse-ip` · `--scope-distance N` · `--no-fingerprint` · `--no-http`.
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

## Phase D (local UI)

- Plan: [`docs/PHASE_D_PLAN.md`](docs/PHASE_D_PLAN.md) (full: `/workspace/deliverables/SENTINEL_SUITE_PHASE_D_PLAN.md` on builder box)
- D0 shell: [`docs/PHASE_D_SLICE0.md`](docs/PHASE_D_SLICE0.md) — `sentinel ui` → `http://127.0.0.1:8888`
- D4: [`docs/PHASE_D_SLICE4.md`](docs/PHASE_D_SLICE4.md) — Tauri scaffold + OSINT/Surface/Auth lab/Workbench; Ctrl+K
- D1 polish: [`docs/PHASE_D_SLICE1.md`](docs/PHASE_D_SLICE1.md) — Hunt/Scope/Reports, confirm-finding, optional `ui_auth.json` bcrypt / skip-lab
- D2: [`docs/PHASE_D_SLICE2.md`](docs/PHASE_D_SLICE2.md) — Assets / Changes / Modules
- D3: [`docs/PHASE_D_SLICE3.md`](docs/PHASE_D_SLICE3.md) — Coach + Settings (no LLM; never invents findings)
- E0/E1: [`docs/PHASE_E_SLICE0.md`](docs/PHASE_E_SLICE0.md) · [`docs/PHASE_E_SLICE1.md`](docs/PHASE_E_SLICE1.md) — Open Lab + lab-aware Coach
- Non-goals v1: Burp replacement, team mode, cloud sync, Electron; Tauri optional shell (D4 scaffold)

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
| [`docs/PHASE_C_REVIEW.md`](docs/PHASE_C_REVIEW.md) | Phase C Founder review pointer (IDLE) |
| [`docs/PHASE_B_SLICE2.md`](docs/PHASE_B_SLICE2.md) | Slice2 reality table |
| [`docs/PHASE_B_SLICE3.md`](docs/PHASE_B_SLICE3.md) | Slice3 L5 tech fingerprint |
| [`docs/PHASE_B_SLICE4.md`](docs/PHASE_B_SLICE4.md) | Slice4 deeper L5 + L6 tech diffs |
| [`docs/PHASE_C_SLICE4.md`](docs/PHASE_C_SLICE4.md) | Slice4 business_logic assistant v0 |
| [`docs/PHASE_C_SLICE5.md`](docs/PHASE_C_SLICE5.md) | Slice5 race_toctou hard caps |
| [`docs/PHASE_C_SLICE6.md`](docs/PHASE_C_SLICE6.md) | Slice6 graphql pack v0 |
| [`docs/PHASE_C_SLICE7.md`](docs/PHASE_C_SLICE7.md) | Slice7 xss_dom sink-proof pack v0 |
| [`docs/PHASE_C_SLICE8.md`](docs/PHASE_C_SLICE8.md) | Slice8 csrf_state pack v0 |
| [`docs/PHASE_C_SLICE9.md`](docs/PHASE_C_SLICE9.md) | Slice9 open_redirect pack v0 |
| [`docs/PHASE_C_SLICE10.md`](docs/PHASE_C_SLICE10.md) | Slice10 cache_host pack v0 |
| [`docs/PHASE_C_SLICE11.md`](docs/PHASE_C_SLICE11.md) | Slice11 jwt_session pack v0 |
| [`docs/PHASE_C_SLICE12.md`](docs/PHASE_C_SLICE12.md) | Slice12 http_desync pack v0 |
| [`docs/PHASE_C_SLICE13.md`](docs/PHASE_C_SLICE13.md) | Slice13 confirm-finding + report polish |
| [`docs/PHASE_C_SLICE14.md`](docs/PHASE_C_SLICE14.md) | Slice14 ssrf_collaborator pack v0 |
| [`docs/PHASE_C_SLICE15.md`](docs/PHASE_C_SLICE15.md) | Slice15 owned collaborator listener |
| [`docs/HUNTER_WORKFLOW.md`](docs/HUNTER_WORKFLOW.md) | Short hunter loop: map → pack → confirm → report |
| [`docs/ENGINE_HASH_PROPOSAL.md`](docs/ENGINE_HASH_PROPOSAL.md) | Proposed subfinder/httpx hashes (not allowlisted) |

## Layout

```text
packages/sentinel_core   # schema, graph, scope, engines
packages/shadowseye      # Eye bridge + thin runner
packages/gungnir         # Hunt bridge + thin runner + thin correlate
packages/sentinel_cli    # `sentinel` → doctor, program, eye, hunt, collaborator
docs/                    # ENGINES, HUMAN-QUEUE, LICENSE_NOTE, SPRINT0*
workers/                 # Go later (README only)
tests/                   # suite tests
```

## Maintainers

Product north star (box): `/workspace/deliverables/SENTINEL_SUITE_GODLEVEL_PLAN_2026-09-22.md`  
Founder review packet Sprint 0 (box): `/workspace/deliverables/SENTINEL_SUITE_SPRINT0_REVIEW.md`  
Founder review packet Phase C (box): `/workspace/deliverables/SENTINEL_SUITE_PHASE_C_REVIEW.md`
