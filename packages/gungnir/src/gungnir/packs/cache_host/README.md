# Pack `cache_host` v0

Cache deception / Host-header reflection **evidence** with fixture diffs —
staging/lab first. **Not** a live CDN poison weapon.

## Can

- Emit Host / X-Forwarded-Host / X-Forwarded-Scheme reflection candidates when
  fixtures show the reflected value landing in a cacheable body or header
- Emit path-confusion / URL-normalization cache-key mismatch candidates when
  fixtures show differing keys (key A vs B) with a content/header diff
- Emit Cache-Control / Vary weakness **coach hints only** (not auto-confirm)
- Attach checklist + honest `needs_human` / `unverified` verification (never auto-VERIFIED)
- Hard-cap live-mock requests (≤10)
- Run with `needs_roles=0` (no Role A/B required)

## Cannot

- Poison production CDN / live CDN purge-poison tooling / mass Host-header spray
- Emit on bare Host / X-Forwarded-* header name alone (no reflection/key-mismatch evidence → skip)
- Auto-confirm findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X
- Browser farms

Authorized / lab only. Scope via `--scope` or `--i-own-this`.
