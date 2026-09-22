# Sentinel Suite

**Authorized attack-surface OSINT that watches (ShadowsEye) + hunt packs that prove (Gungnir) on a shared event graph and scope kernel (`sentinel_core`).**

Sprint 0 Phase A scaffold — schema, program folders, scope MVP, doctor CLI, thin bridge stubs. Not a full Eye/Hunt product yet.

## Install (PyPI not published yet)

Clone and editable-install until packages are on PyPI:

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
```

**Future pipx story (branding from day one; not published yet):**

```text
pipx install shadowseye          # Eye only
pipx install gungnir             # Gungnir only
pipx install sentinel-suite      # both + `sentinel` CLI
```

## Architecture (prose)

- **ShadowsEye (Eye)** watches the attack surface and feeds the shared event graph (interestingness + diffs first — Phase B).
- **Gungnir (Hunt)** proves findings with hunt packs and evidence; it does not remap the surface unless asked.
- **`sentinel_core`** is the invisible shared library: event schema v1, SQLite WAL graph per program under `SENTINEL_HOME` (default `~/.sentinel`), scope kernel (OOS = hard kill), and engine pin under `~/.sentinel/bin/`.
- Thin **bridge stubs** in this monorepo emit/consume minimal events so days 3–5 have a place to land; they are **not** ports of the live ShadowsEye/Gungnir CLIs.
- **workers/** is a stub for future Go/Rust hot-path binaries. Guard SDK / `sentinelagent-guard` is a separate product and is **never** touched here.

## Ethics fence

- **Authorized use only** — bug bounty / pentest / your own assets with written permission.
- **No malware, no destructive exploit PoCs, no other-customer harm.**
- **Guard SDK / sentinelagent-guard / packages/guard-* are untouched** (separate product line).
- **No stalking defaults** (username/email OSINT extras stay opt-in later, not default).
- Secrets stay `SECRET_CANDIDATE` until human/Gungnir proves in-scope use.
- No invented stars, users, or CVEs in docs.

## License

**MIT** — chosen for consistency with live ShadowsEye and Gungnir packages. Founder preference is Apache-2.0; see [`docs/LICENSE_NOTE.md`](docs/LICENSE_NOTE.md).

## Layout

```text
packages/sentinel_core   # real library (schema, graph, scope, engines)
packages/shadowseye      # thin event-emit stub
packages/gungnir         # thin stub + scope/lab gate
packages/sentinel_cli    # `sentinel` → doctor, program init
workers/                 # Go later (README only)
tests/                   # suite tests
docs/HUMAN-QUEUE.md      # CI OAuth / mirror / license follow-ups
```

## Maintainers

Product plan: `/workspace/deliverables/SENTINEL_SUITE_GODLEVEL_PLAN_2026-09-22.md` (box path) — Sprint 0 / Phase A north star.

Human follow-ups: [`docs/HUMAN-QUEUE.md`](docs/HUMAN-QUEUE.md).
