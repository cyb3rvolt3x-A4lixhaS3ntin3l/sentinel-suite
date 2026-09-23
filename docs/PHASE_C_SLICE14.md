# Phase C slice14 — ssrf_collaborator pack v0

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice14 — ssrf_collaborator pack v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `ssrf_collaborator` v0 | **real (candidates)** | `needs_roles=0` |
| URL-param / header-injection fixtures | **real** | collaborator callback markers only |
| Default collaborator | **real** | local `127.0.0.1` fixture callback mock |
| `--collaborator URL` | **real** | operator-owned; metadata refused by default |
| Metadata refuse | **real** | 169.254.169.254 / metadata.google.internal / Azure IMDS / equivalents |
| Lab dual-flag gate | **real** | beyond fixtures → `--i-own-this` **and** `--i-understand-lab` |
| Open-internet triple gate | **real** | needs `--scope` + ownership + lab flag |
| Hard request caps | **real** | requests≤10 for non-pure-fixture paths |
| DNS rebinding | **coach hints only** | no live rebind tooling |
| Human gate | **real** | findings `needs_human`; never auto-VERIFIED |
| Prior packs + slice13 polish | **intact** | all 11 prior packs + confirm/report |
| race_toctou / http_desync caps | **untouched** | hard maxima unchanged |
| ENGINE_ALLOWLIST | **still {}** | no change |

## Can

- Emit URL-param / header-injection **candidates** when fixtures show collaborator
  callback markers or outbound URL resolved to the collaborator
- Run pure fixture mode in CI **without** `--i-understand-lab`
- Default collaborator = `127.0.0.1` in-process fixture callback mock
- Optional `--collaborator URL` (operator-owned)
- Enforce hard request caps (≤10) on live-mock / non-fixture paths
- Attach finding-gate checklist + honest `needs_human` verification (never auto-VERIFIED)
- DNS rebinding **coach hints only**
- Scope-gate via `--scope` or `--i-own-this`; lab flag is **additional** beyond fixtures

## Cannot

- Live cloud metadata campaigns (169.254.169.254 / metadata.google.internal /
  Azure IMDS / equivalents) against third parties
- Random internet SSRF scanning / host spray
- Open-internet without `--scope` **and** `--i-own-this` **and** `--i-understand-lab`
- Non-fixture paths without **both** ownership and lab acknowledgment flags
- Cloud metadata as `--collaborator` without `--i-understand-lab` **and**
  documented lab fixture mode (`fixtures.lab_fixture_mode`)
- Auto-VERIFIED / confirmed findings (use `sentinel hunt confirm-finding`)
- Live DNS rebind tooling
- Coach UI, Guard SDK, workflows, X
- Raise `race_toctou` / `http_desync` hard caps

## Honesty fence

Authorized **detection scaffolding** only — fixture-driven by default with an
operator-owned collaborator. Evidence = collaborator callback markers in
fixtures — **not** live cloud-metadata fetches or random-internet SSRF spray.
Coach: *ssrf packs are lab-first with an operator-owned collaborator; never
spray cloud metadata or random internet hosts*.

## Lab gate enforcement

| Code path | Behavior |
| --- | --- |
| `ssrf_collaborator.caps.assert_metadata_refused` | Cloud metadata refused unless `--i-understand-lab` **and** `fixtures.lab_fixture_mode` |
| `ssrf_collaborator.caps.assert_collaborator_allowed` | Non-local collaborator requires ownership; metadata path refuses |
| `ssrf_collaborator.caps.assert_lab_dual_flag` | Beyond `fixtures_only` → require `i_own_this` **and** `i_understand_lab` |
| `ssrf_collaborator.caps.assert_target_allowed` | Open-internet → triple gate (scope + ownership + lab); lab-local live → dual flag |
| `ssrf_collaborator.checks.run_checks` | Classifies pure fixtures vs live URLs / `live_mock` / `opener`; raises `PackRunError` on gate fail |
| Fail-closed tests | `test_assert_metadata_refused_fail_closed`, `test_assert_metadata_refused_lab_flag_alone_not_enough`, `test_fail_closed_metadata_collaborator_via_checks`, `test_cli_fail_closed_metadata_collaborator`, `test_fail_closed_open_internet_without_lab_flag`, `test_fail_closed_lab_local_live_without_lab_flag`, `test_fail_closed_live_mock_without_lab_flag`, `test_fail_closed_open_internet_missing_scope`, `test_cli_fail_closed_without_lab_flag_on_live_url` |

## CLI

```bash
sentinel hunt pack list
# Pure fixtures (CI-friendly; no lab flag); default local collaborator:
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this
# Custom operator-owned local collaborator:
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this \
  --collaborator http://127.0.0.1:9999/cb
# Beyond fixtures / acknowledged lab:
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this --i-understand-lab
# Open-internet staging (written auth + coordination):
sentinel hunt pack run ssrf_collaborator --program demo --scope ./scope.txt \
  --i-own-this --i-understand-lab --url 'https://staging.example/'
sentinel hunt report demo --pack ssrf_collaborator -o ./ssrf-collaborator-report.md
```

### Fixture shape (lab)

```json
{
  "ssrf_scenarios": [
    {
      "name": "url-param-callback",
      "kind": "url_param",
      "url": "http://127.0.0.1/lab/ssrf?url=http://127.0.0.1:9/ssrf-callback",
      "collaborator_callback": {
        "received": true,
        "marker": "SSRF_COLLAB_HIT",
        "outbound_url": "http://127.0.0.1:9/ssrf-callback"
      },
      "expect": {"collaborator_hit": true}
    }
  ],
  "header_injection": [],
  "dns_rebind": []
}
```

## Caps

Constants in `gungnir.packs.ssrf_collaborator.caps`: `HARD_MAX_REQUESTS=10` (default 6).
Over-limit → hard fail. Pure fixture runs do not consume the live budget.

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this` to start; lab flag additional beyond fixtures
- Findings never auto-`verified` / `confirmed`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no live cloud-metadata campaigns; no random-internet SSRF scan; no `--tools`; no X
