# HUMAN-QUEUE — Sprint 0 Phase A

Items that need a human (OAuth scope, Founder decision, or later work). Not blockers for local use of this scaffold.

## Blocked / needs human OAuth

1. **GitHub Actions workflow push — BLOCKED**
   - `gh` scopes: `gist, read:org, repo` — **no `workflow` scope**.
   - Push of `.github/workflows/ci.yml` was rejected by GitHub (`refusing to allow an OAuth App to create or update workflow ... without workflow scope`).
   - **Action taken:** workflow removed from the pushed tree; canonical copy at `docs/ci-pending/ci.yml`.
   - **Human:** re-auth `gh auth login` with `workflow` scope, then:
     ```bash
     mkdir -p .github/workflows
     cp docs/ci-pending/ci.yml .github/workflows/ci.yml
     git add .github/workflows/ci.yml && git commit -m "ci: add pytest workflow" && git push
     ```
   - Until then, run tests locally (see root README).

## Open Founder decisions

2. **License re-eval** — Founder Apache-2.0 preference vs MIT consistency (see `docs/LICENSE_NOTE.md`).
3. **Engine binary allowlist hashes** — download path implemented; `ENGINE_ALLOWLIST` empty until a human pins third-party release hashes. Deferred catalog: subfinder, httpx, naabu, nuclei, dnsx, katana, ffuf — see `docs/ENGINES.md`.
4. **Phase B GO** — first slice of ShadowsEye that pays (L0–L5 + watch diffs + interestingness)?
5. **Money pack later** — which pack after Eye pays (BOLA/IDOR vs ATO/OAuth)?

## Deferred (not Sprint 0)

6. **PyPI publish** — install via editable clone until then.
7. **Guard SDK** — never touch; separate product.
8. **Tauri / L1–L6 full / Hunt Packs UI / coach / X promo** — later phases.

## Days 11–14 landed (this ship)

- Branding / residual honesty on suite README + package READMEs
- Founder review packet (box deliverables + optional `docs/SPRINT0_REVIEW.md`)
- Thin README mirrors on live `gungnir` + `ShadowsEye` (pointer to monorepo; no code moves/deletes)
- Still **no** `.github/workflows` push

## Days 6–10 (prior)

- Engines allowlist download path + doctor status; `docs/ENGINES.md`
- Eye / Hunt thin runners + honesty docs
