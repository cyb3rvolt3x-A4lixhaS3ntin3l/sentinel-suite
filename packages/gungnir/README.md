# gungnir (monorepo package)

**Honest status (Phase C slice1):** bridge + thin hunt runner + **Hunt Pack framework MVP** + first money pack **`ato_oauth_oidc` v0**.

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
  - **Fail closed** without Role A (and Role B when `needs_roles=2`)
  - Role sessions: lab JSON fixtures `roles/a.json` / `roles/b.json` — `{cookies|headers|bearer}` only; pack reads them, does not steal credentials

### Pack `ato_oauth_oidc` v0 — can

- Map login/reset/OAuth/OIDC/SAML/magic-link **candidates** from Eye inventory URLs or `--url` (path/query heuristics)
- Scope-gate via `scope.hard_kill` / `http_guard` before any request
- Emit **candidates** for: missing state / missing PKCE hints / open `redirect_uri` patterns; token leakage patterns in Location/fragment/query (fixtures); password-reset enumeration diffs (fixture-driven, rate-aware messaging)
- Attach finding-gate checklist: `in_scope`, `reproducible`, `impact`, `evidence_attached`
- Use verification enum: `confirmed|not_reproduced|unverified|skipped` (plus existing bridge aliases)
- Optional HTTP only through `scoped_request` (tests use mocks)

### Pack `ato_oauth_oidc` v0 — cannot

- Full ATO chain automation
- Live IdP attack / token-theft malware
- BOLA / IDOR (separate pack, deferred)
- Report factory / platform markdown export
- nuclei-all / data destruction / lockout-abuse loops

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
- **Not** BOLA pack, desync, workflows, report factory
- **Not** feature parity with any live/public Gungnir product claims beyond this monorepo

Prefer small honest code over a lying README.
