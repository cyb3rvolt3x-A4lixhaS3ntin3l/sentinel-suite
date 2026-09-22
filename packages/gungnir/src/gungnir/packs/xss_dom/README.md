# Pack `xss_dom` v0

XSS/DOM with **sink proof**, not alert() spam. Evidence or it did not happen.

## Can

- Emit source→sink candidates from fixtures (location / hash / postMessage →
  innerHTML, document.write, eval-ish) with evidence snippets proving a unique
  marker in sink context
- Emit reflected / stored **path stubs** from fixtures only
- Reject alert()-only fixtures that lack sink context
- Attach checklist + honest `needs_human` / `unverified` verification (never auto-VERIFIED)
- Hard-cap live-mock requests (≤10)
- Run with `needs_roles=0` (no Role A/B required)

## Cannot

- Full browser automation farm / Playwright XSS farm
- dalfox binary / `--tools` / dalfox-all live mass scanning
- Auto-confirm findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X

Authorized / lab only. Scope via `--scope` or `--i-own-this`.
