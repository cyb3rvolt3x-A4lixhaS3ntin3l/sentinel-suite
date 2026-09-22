# Phase C slice7 — xss_dom sink-proof pack v0

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice7 — xss_dom sink-proof pack v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `xss_dom` v0 | **real (candidates)** | `needs_roles=0` |
| Source→sink fixtures | **real** | location/hash/postMessage → DOM sinks |
| Marker-in-sink evidence | **real** | alert()-only fixtures rejected |
| Reflected / stored stubs | **stubs** | fixture path stubs only |
| postMessage | **hints only** | `needs_human` coach hints |
| Live-mock hard caps | **real** | requests≤10 when opener/live_mock used |
| Human gate | **real** | findings `needs_human` / `unverified`; never auto-VERIFIED |
| Prior packs | **intact** | `ato_oauth_oidc` · `bola_idor_bfla` · `business_logic` · `race_toctou` · `graphql` |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do

- Treat XSS/DOM as **source→sink with sink proof**, not alert() spam
- Emit source→sink candidates when a unique marker is observed in a sink context
  (innerHTML / document.write / eval-ish / insertAdjacentHTML / …)
- Emit reflected and stored **path stubs** from fixtures (honest `unverified`
  unless sink proof is also present → `needs_human`)
- Reject alert()-only fixtures that lack sink assignment context
- Emit postMessage origin/sink **needs_human hints only** (no live fuzzing)
- Enforce hard request caps if any live mock / opener is used
- Attach finding-gate checklist + honest verification enum
- Scope-gate via `--scope` or `--i-own-this`

## What the pack cannot do

- Full browser automation farm / headless XSS farm
- dalfox binary / `--tools` / dalfox-all live mass scanning
- Live third-party XSS hammering
- Auto-VERIFIED / confirmed findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X

## Honesty fence

Authorized **detection scaffolding** only — fixture-driven by default. Evidence =
marker in sink context. alert() alone is not proof.

## CLI

```bash
sentinel hunt pack list
sentinel hunt pack run xss_dom --program demo --i-own-this
sentinel hunt pack run xss_dom --program demo --scope ./scope.txt
sentinel hunt report demo --pack xss_dom -o ./xss-report.md
# prior packs still work:
sentinel hunt pack run graphql --program demo --i-own-this
sentinel hunt pack run race_toctou --program demo --i-own-this --i-understand-lab
sentinel hunt pack run business_logic --program demo --i-own-this
sentinel hunt pack run bola_idor_bfla --program demo --i-own-this \
  --role-a ./roles/a.json --role-b ./roles/b.json
sentinel hunt pack run ato_oauth_oidc --program demo --i-own-this \
  --url 'https://lab.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://lab.example/cb'
```

### Fixture shape (lab)

```json
{
  "source_sink": [
    {
      "name": "hash-innerHTML",
      "url": "http://127.0.0.1/app#ssntnlXSS7m4rk",
      "source": {"kind": "location.hash", "value": "#ssntnlXSS7m4rk"},
      "sink": {
        "kind": "innerHTML",
        "snippet": "element.innerHTML = location.hash.slice(1); // -> <div>ssntnlXSS7m4rk</div>"
      },
      "marker": "ssntnlXSS7m4rk",
      "expect": {"marker_in_sink": true}
    }
  ],
  "reflected": [
    {
      "url": "http://127.0.0.1/search?q=ssntnlXSS7m4rk",
      "param": "q",
      "marker": "ssntnlXSS7m4rk",
      "response": {"status": 200, "body": "<b>ssntnlXSS7m4rk</b>"},
      "sink": {"kind": "innerHTML", "snippet": "out.innerHTML = q; // ssntnlXSS7m4rk"},
      "expect": {"reflected": true}
    }
  ],
  "stored": [
    {
      "write_url": "http://127.0.0.1/comments",
      "url": "http://127.0.0.1/comments/1",
      "marker": "ssntnlXSS7m4rk",
      "write_response": {"status": 201},
      "read_response": {"status": 200, "body": "<p>ssntnlXSS7m4rk</p>"},
      "sink": {"kind": "innerHTML", "snippet": "div.innerHTML = comment; // ssntnlXSS7m4rk"},
      "expect": {"stored": true}
    }
  ],
  "postmessage": [
    {"url": "http://127.0.0.1/widget", "origin_check": false}
  ]
}
```

Fixtures are injected in tests via `run_pack(..., fixtures={...})`.

## Caps (live mock only)

Constants in `gungnir.packs.xss_dom.caps`: `HARD_MAX_REQUESTS=10` (default 6).
Over-limit → hard fail. Fixture-only runs do not consume the budget.

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this` to start
- Findings never auto-`verified` / `confirmed`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no dalfox-all; no `--tools`; no X

## Explicit defer

Full browser automation farm; dalfox `--tools`; coach UI; Guard; workflows; X
