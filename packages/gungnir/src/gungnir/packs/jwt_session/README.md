# Pack `jwt_session` v0

Session fixation + weak JWT handling **evidence** from fixtures —
staging/lab first. **Not** a live token-theft toolkit.

## Can

- Emit session-fixation candidates when fixtures show the same session cookie
  before and after login (not rotated)
- Emit JWT weak-handling candidates (alg=none / weak alg / missing exp / kid
  confusion) decoded from **fixture token strings only**
- Emit token-in-query/fragment leakage candidates when fixtures show a JWT in
  the URL query or fragment
- Attach checklist + honest `needs_human` / `unverified` verification (never auto-VERIFIED)
- Hard-cap live-mock requests (≤10)
- Run with `needs_roles=0` (no Role A/B required)
- Coach hints only (rotate session on auth; reject alg=none; put tokens in cookies not query)

## Cannot

- Live IdP hammering / credential stuffing / session-hijack runbooks against real IdPs
- Token exfiltration modules / mint attack payloads for unauthorized use / forge live sessions
- Auto-confirm findings (use `sentinel hunt confirm-finding`)
- Overlap replacement for `ato_oauth_oidc` (OAuth/OIDC pack stays as-is)
- Coach UI, Guard SDK, workflows, X

Authorized / lab only. Scope via `--scope` or `--i-own-this`. Analyze fixture tokens only.
