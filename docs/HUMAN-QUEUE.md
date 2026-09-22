# HUMAN-QUEUE — Sprint 0 Phase A

Items that need a human (OAuth scope, Founder decision, or later day work). Not blockers for local use of this scaffold.

## Blocked / needs human OAuth

1. **GitHub Actions workflow push — BLOCKED on first ship**
   - `gh` scopes: `gist, read:org, repo` — **no `workflow` scope**.
   - Push of `.github/workflows/ci.yml` was rejected by GitHub (`refusing to allow an OAuth App to create or update workflow ... without workflow scope`).
   - **Action taken:** workflow removed from the pushed commit so the rest of Sprint 0 could ship. Canonical copy kept at `docs/ci-pending/ci.yml`.
   - **Human:** re-auth `gh auth login` (or refresh token) with `workflow` scope, then:
     ```bash
     mkdir -p .github/workflows
     cp docs/ci-pending/ci.yml .github/workflows/ci.yml
     git add .github/workflows/ci.yml && git commit -m "ci: add pytest workflow" && git push
     ```
   - Until then, run tests locally:
     ```bash
     cd sentinel-suite
     python3 -m venv .venv && source .venv/bin/activate
     pip install -U pip pytest
     pip install -e packages/sentinel_core -e packages/shadowseye \
                 -e packages/gungnir -e packages/sentinel_cli
     pytest -q
     sentinel doctor
     ```

## Deferred (not day-1)

2. **Thin README mirrors** on existing public `gungnir` + `ShadowsEye` repos — point at this monorepo. Explicitly **not** part of this ship.
3. **License re-eval** — Founder Apache-2.0 preference vs MIT consistency (see `docs/LICENSE_NOTE.md`).
4. **PyPI publish** — not in Sprint 0; install via editable clone until then.
5. **Guard SDK** — never touch; separate product.
6. **Engine binary download** — Sprint 0 `ensure_engine(..., download=True)` returns `download_deferred` (detect+stamp only; no arbitrary internet fetches). Human/day 6–7 may wire a vetted allowlist download path.

## Days 3–5 landed (this ship)

- Scope kernel: `parse_brief` (h1 / bugcrowd / generic / raw), `detect_brief_platform`, HTTP hard-kill via `http_guard` (`assert_url_in_scope` / `scoped_request`).
- Engine pin: `detect_engine`, `ensure_engine` (download deferred); doctor lists pinned vs detected.
- Eye/Hunt bridges: DNS_NAME / IP / OPEN_PORT / inventory_to_events; EVIDENCE / emit_verified_finding / scoped emit.
- CLI: `sentinel program import-brief <id> <file> [--platform auto|h1|bugcrowd|raw]`.

## Days 6–10 leftovers

- Deeper live module wiring (call inventory emitters from a thin Eye runner; hunt pack → verified finding path).
- Optional vetted engine download allowlist (still no PATH mutation).
- CI workflow push once `workflow` OAuth scope is available.
