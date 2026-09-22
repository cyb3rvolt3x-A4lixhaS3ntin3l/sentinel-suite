# gungnir (monorepo package)

**Honest status (Phase C slice6):** bridge + thin hunt runner + **Hunt Pack framework** + **`ato_oauth_oidc` v0.2** + **`bola_idor_bfla` v0** (dual-role IDOR/BFLA fixtures).

## What this package IS

- Depends on `sentinel_core`
- Bridge: `emit_finding_event`, `emit_evidence_event`, `emit_verified_finding`
- Scope/lab gate: `require_scope_or_lab(scope_path=None, i_own_this=False)`
- Thin runner (`gungnir.runner.run_hunt` / CLI `sentinel hunt run`)
- Thin correlate (`gungnir.correlate.correlate_findings`)
- **Hunt packs** under `gungnir.packs`:
  - Manifest dataclass: `id`, `class` (`pack_class`), `needs_roles`, `consumes`, `emits`, `noise_class`, `description`
  - Registry discovers packs under `packages/gungnir/src/gungnir/packs/`
  - CLI: `sentinel hunt pack list` · `sentinel hunt pack run <id> --program <id> --scope FILE|--i-own-this`
  - CLI: `sentinel hunt report <program> [--pack PACK] [-o FILE]` — Steps from evidence only
  - **Fail closed** without Role A (and Role B when `needs_roles=2`)
  - Role sessions: lab JSON fixtures `roles/a.json` / `roles/b.json` — `{cookies|headers|bearer}` only; pack reads them, does not steal credentials

### Pack `ato_oauth_oidc` v0.2 — can

- Map login/reset/OAuth/OIDC/SAML/magic-link **candidates** from Eye inventory URLs or `--url` (path/query heuristics)
- Scope-gate via `scope.hard_kill` / `http_guard` before any request
- Emit **candidates** for: missing state / missing PKCE hints / open `redirect_uri` patterns; token leakage patterns in Location/fragment/query (fixtures); password-reset enumeration diffs (fixture-driven, rate-aware messaging)
- **Nonce / PKCE verify stubs** (fixture-driven): presence/format of `nonce`, `code_challenge`, `code_challenge_method`; `confirmed` only when fixture `expect` proves mismatch/absence; otherwise `unverified`
- **Client-type hints** (public vs confidential) from discovery/HTML/JSON fixtures — low confidence labels
- Attach finding-gate checklist: `in_scope`, `reproducible`, `impact`, `evidence_attached`
- Use verification enum: `confirmed|not_reproduced|unverified|skipped` (plus existing bridge aliases)
- Thin **report markdown export** (platform skeleton; Steps from evidence log only — no LLM)
- Optional HTTP only through `scoped_request` (tests use mocks)

### Pack `ato_oauth_oidc` v0.2 — cannot

- Full ATO chain automation
- Live IdP attack / token-theft malware
- BOLA / IDOR (see pack `bola_idor_bfla`)
- LLM-invented Steps to Reproduce / full report factory / coach UI
- nuclei-all / data destruction / lockout-abuse loops

### Pack `graphql` v0 — can

- Treat GraphQL as schema + mutations + ID encoding (not “a URL”)
- Introspection enabled/disabled candidates from fixtures (Role A optional)
- Soft-skip mutation auth-diff with coach when Role A missing; still run other fixtures
- Opaque/global ID enumeration-ish candidates (fixture only)
- Batch/alias **needs_human hints only** (no floods); live-mock hard request caps
- Checklist + honest verification; never auto-VERIFIED
- Report: `sentinel hunt report <program> --pack graphql`

### Pack `graphql` v0 — cannot

- InQL full fork / schema dumps / data exfiltration
- Live third-party GraphQL hammering / alias floods
- Live SSRF collaborator, coach UI, Guard, `--tools`, workflows, X

### Pack `bola_idor_bfla` v0 — can

- Require **Role A + Role B** (`needs_roles=2`); fail closed with coach-style message if either missing
- Horizontal IDOR candidates (A reads B object) from dual-role fixtures
- Vertical / BFLA candidates (A hits admin-ish path) from fixtures
- Sibling method confusion (GET vs DELETE/PUT/PATCH) from fixtures
- Checklist + honest verification; evidence stubs from fixtures only
- Report: `sentinel hunt report <program> --pack bola_idor_bfla`

### Pack `bola_idor_bfla` v0 — cannot

- Live multi-tenant abuse / other-customer probing / data destruction
- Full business-logic assistant, race packs, live collaborator SSRF
- nuclei-all / Guard SDK / workflows

## Role session fixture format

```json
{
  "cookies": {"session": "lab-cookie-value"},
  "headers": {"X-CSRF-Token": "lab"},
  "bearer": "optional-lab-token"
}
```

Place at `~/.sentinel/programs/<id>/roles/a.json` (and `b.json` when required).

## What this package is NOT (yet)

- **Not** coach UI, Tauri, `--tools` engine downloads, Guard SDK
- **Not** desync, workflows, full report factory, race packs, live multi-tenant abuse
- **Not** feature parity with any live/public Gungnir product claims beyond this monorepo

Prefer small honest code over a lying README.
