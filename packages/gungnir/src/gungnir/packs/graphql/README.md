# Pack `graphql` v0

GraphQL is **not** “a URL.” Fixture-driven candidates for:

- Introspection enabled / disabled
- Unauth vs auth mutation diffs (Role A **optional** — soft coach if missing)
- Opaque / global ID enumeration-ish signals
- Batch / alias abuse as **needs_human hints only**

## Can

- Run without Role A (introspection / global-id / batch hints still execute)
- Soft-skip mutation checks with coach text when Role A is absent
- Emit checklist + honest `needs_human` / `unverified` verification (never auto-VERIFIED)
- Hard-cap live-mock requests (≤10)

## Cannot

- InQL fork / schema dumps / data exfiltration
- Live third-party GraphQL hammering or alias floods
- Auto-confirm findings

Authorized / lab only.
