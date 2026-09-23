# Phase F ship notes (all-at-once)

**Status:** COMPLETE  
**Base:** `8e6a48d` (Phase E, 547 tests) → **565** after Phase F  
**Full plan:** `/workspace/deliverables/SENTINEL_SUITE_PHASE_F_PLAN.md` · pointer [`PHASE_F_PLAN.md`](PHASE_F_PLAN.md)

## Landed

1. Brand packages: `shadowseye` / `gungnir` / `sentinel-suite` console scripts + meta wheel layout
2. `docs/INSTALL.md` — path/git/pipx-from-path; no fake PyPI
3. `docker-compose.yml` + `docker/Dockerfile` — clean-room UI+engine
4. Packaging dry-run: `scripts/packaging_dry_run.py` (+ Tauri targets include `deb`)
5. `sentinel doctor` Phase F extras — Nmap→Naabu-class, optional API keys, WSL
6. `docs/WSL2.md` — Windows truth
7. Tests: `tests/test_phase_f.py`

## Blocked / honest

- Workflow OAuth HOLD → CI stays in `docs/ci-pending/`
- `tauri-cli` often missing → no claimed `.dmg/.msi/.AppImage/.deb` artifacts
- PyPI publish not done

## Intact

- Phase C freeze 12 packs / `ENGINE_ALLOWLIST {}`
- Phase E labs juice-shop · crapi · auth-session
- D0–D4 UI / Tauri scaffold
