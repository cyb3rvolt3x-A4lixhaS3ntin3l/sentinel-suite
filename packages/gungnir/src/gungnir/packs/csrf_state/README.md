# Pack `csrf_state` v0

CSRF / state-token candidates with **fixture evidence**, not blind form spray.

## Can

- Emit missing-CSRF candidates on state-changing POST/PUT/DELETE/PATCH when
  fixtures carry an explicit missing-token signal
- Emit unbound / reusable token candidates when fixtures mark
  `session_bound=false` / `reusable=true` / `unbound_marker`
- Emit SameSite=None without Secure (and weak cookie-flag) candidates from
  Set-Cookie fixture strings
- Emit double-submit vs synchronizer-token **coach hints only** (not auto-confirm)
- Attach checklist + honest `needs_human` / `unverified` verification (never auto-VERIFIED)
- Hard-cap live-mock requests (≤10)
- Run with `needs_roles=0` (no Role A/B required)

## Cannot

- Cross-site CSRF farms / browser automation / auto form-flood
- Live mass state-changing spray against random hosts
- Auto-confirm findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X

Authorized / lab only. Scope via `--scope` or `--i-own-this`.
