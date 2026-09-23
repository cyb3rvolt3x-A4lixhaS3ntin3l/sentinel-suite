# Pack `http_desync` v0

HTTP request desync / smuggling **evidence fixtures** — staging/lab first.
**Not** a production CDN/WAF smuggling weapon. Off by default for open-internet.

## Can

- Emit CL.TE / TE.CL / header-smuggle **candidates** when fixtures show
  differential responses (status/body/header/marker diffs) across ambiguous
  request interpretations
- Run pure fixture mode in CI **without** `--i-understand-lab`
- Prefer `127.0.0.1` / in-process fixture mock (no live smuggle I/O)
- Enforce hard request caps (≤10) on any non-pure-fixture / live-mock path
- Attach checklist + honest `needs_human` verification (never auto-VERIFIED)
- Run with `needs_roles=0` (Role A optional)
- Coach hints only: “desync is lab/staging; production needs written auth + careful coordination”

## Cannot

- Production CDN/WAF smuggling campaigns / live desync weaponization
- DoS / flood / unlimited request spray
- Open-internet targets without `--scope` **and** `--i-own-this` **and** `--i-understand-lab`
- Non-fixture / live-mock paths without **both** `--i-own-this` and `--i-understand-lab`
- Auto-confirm findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X

## Lab gate

| Path | Required flags |
| --- | --- |
| Pure fixtures (built-in or caller differentials, no live URLs/mock) | `--scope` **or** `--i-own-this` (normal pack scope gate only) |
| Beyond fixtures (live URL / opener / live_mock) | **both** `--i-own-this` **and** `--i-understand-lab` |
| Open-internet URL | `--scope` **and** `--i-own-this` **and** `--i-understand-lab` |

Authorized / lab only. Evidence = fixture differentials — not live smuggle crafts.
