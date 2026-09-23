# Pack `ssrf_collaborator` v0

SSRF **collaborator evidence fixtures** — operator-owned collaborator only.
**Not** a cloud-metadata attack kit. **Not** a random-internet SSRF scanner.

## Can

- Emit URL-param / header-injection **candidates** when fixtures show
  collaborator callback markers or outbound URL resolved to the collaborator
- Run pure fixture mode in CI **without** `--i-understand-lab`
- Default collaborator = `127.0.0.1` in-process fixture callback mock
- Optional `--collaborator URL` (operator-owned)
- Enforce hard request caps (≤10) on any non-pure-fixture / live-mock path
- Attach checklist + honest `needs_human` verification (never auto-VERIFIED)
- Run with `needs_roles=0` (Role A optional)
- DNS rebinding **coach hints only** (no live rebind tooling)
- Coach: “ssrf packs are lab-first with an operator-owned collaborator…”

## Cannot

- Live cloud metadata campaigns (169.254.169.254 / metadata.google.internal /
  Azure IMDS / equivalents) against third parties
- Random internet SSRF scanning / host spray
- Open-internet probes without `--scope` **and** `--i-own-this` **and** `--i-understand-lab`
- Non-fixture / live-mock paths without **both** `--i-own-this` and `--i-understand-lab`
- Cloud metadata as `--collaborator` without `--i-understand-lab` **and**
  documented lab fixture mode (`fixtures.lab_fixture_mode`)
- Auto-confirm findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X

## Lab gate

| Path | Required flags |
| --- | --- |
| Pure fixtures (built-in or caller, no live URLs/mock) | `--scope` **or** `--i-own-this` (normal pack scope gate only) |
| Beyond fixtures (live URL / opener / live_mock) | **both** `--i-own-this` **and** `--i-understand-lab` |
| Open-internet URL | `--scope` **and** `--i-own-this` **and** `--i-understand-lab` |
| Cloud metadata collaborator/target | refused by default; only with `--i-understand-lab` **and** `fixtures.lab_fixture_mode` |

Authorized / lab only. Evidence = fixture collaborator markers — not live metadata fetches.
