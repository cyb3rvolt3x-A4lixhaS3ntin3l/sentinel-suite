# HUMAN-QUEUE — Sprint 0 Phase A + Phase B slice4

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
3. **Engine binary allowlist hashes** — download path implemented; `ENGINE_ALLOWLIST` empty until Founder pins hashes. **Proposal (not applied):** `/workspace/deliverables/PHASE_B_ENGINE_HASH_PROPOSAL.md` (+ optional `docs/ENGINE_HASH_PROPOSAL.md`). Deferred: subfinder, httpx, naabu, nuclei, dnsx, katana, ffuf — see `docs/ENGINES.md`. Empty allowlist ⇒ Eye `--no-tools` default.
4. ~~**Phase B GO**~~ — **slice1 shipped** (L0 program.yml brain, L2 native+crt.sh stub, L5 http probe lite, interestingness ranker, L6 watch diffs MVP).
5. **Money pack later** — which pack after Eye pays (BOLA/IDOR vs ATO/OAuth)?
6. ~~**Next Phase B slice**~~ — **slice4 shipped** (deeper L5 fingerprints + L6 tech diffs). Engine hashes **HOLD** (Founder via Arisha) — keep ENGINE_ALLOWLIST empty; do not wire `--tools` downloads. Idle for Phase C vs more Eye.

## Deferred (not this ship)

7. **PyPI publish** — install via editable clone until then.
8. **Guard SDK** — never touch; separate product.
9. **Tauri / full L1–L6 / Hunt Packs UI / coach / X promo** — later phases.
10. **External engine tools in Eye** — subfinder/dnsx/httpx deferred until hashes pinned.

## Phase B slice1 landed (this ship)

- L0: `program.yml` fields `name`, `platform`, `allow_count`, `deny_count`, `updated_at`, `layers_enabled`
- L2: native wordlist resolve + injectable `crtsh_query` (honest degrade); tools deferred
- L5: ports + stdlib HTTP probe via `http_guard`; `http[]` + heuristic `tech[]` + TECH events
- Ranker: `interestingness` scores; default sort in `--json`
- L6: `runs/latest.json` + history; `--watch` diffs (added/removed dns/ports/http/tech)
- CLI: `sentinel eye run … --json --watch --no-tools` (default no-tools true)

## Days 11–14 (prior)

- Branding / residual honesty on suite README + package READMEs
- Founder review packet (box deliverables + optional `docs/SPRINT0_REVIEW.md`)
- Thin README mirrors on live `gungnir` + `ShadowsEye` (pointer to monorepo; no code moves/deletes)
- Still **no** `.github/workflows` push


## Phase B slice2 landed (this ship)

- L1: RDAP/MX/SPF (+ ASN stub) low-confidence identity inventory + events; `--no-identity`
- L2: hardened `crtsh_query`; `reverse_ip_neighbours` with hard scope-distance; `--no-reverse-ip` / `--scope-distance`
- Ranker: light MX-only demotion; Watch snapshot may include identity keys
- Engine hash proposal written for Founder vetting — allowlist still empty
