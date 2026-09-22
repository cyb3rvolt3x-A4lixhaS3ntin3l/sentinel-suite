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
6. **Engine binary allowlist hashes** — download path is implemented (allowlist-only, sha256, `SENTINEL_HOME/bin` only, no PATH mutation). `ENGINE_ALLOWLIST` is **empty** until a human pins real third-party release hashes. Deferred catalog: subfinder, httpx, naabu, nuclei, dnsx, katana, ffuf — see `docs/ENGINES.md`.

## Days 6–10 landed (this ship)

- Engines: allowlist download path + doctor status (detected / pinned / allowlisted / deferred); `docs/ENGINES.md`.
- Eye: thin `shadowseye.runner` + `sentinel eye run` (stdlib inventory → graph; `--scope` or `--i-own-this`).
- Hunt: thin `gungnir.runner` + `sentinel hunt run` + thin `correlate_findings` (dedupe; no 26-chain theater).
- Honesty: `packages/gungnir/README.md` states bridge + thin runner + thin correlate only.

## Days 11–14 plan (not this ship)

- Residual gungnir honesty / branding pass if needed
- Founder review packet
- Mirror README on live Eye/Hunt repos (human; do not modify those repos from agents without explicit GO)
- CI workflow push once `workflow` OAuth scope is available
