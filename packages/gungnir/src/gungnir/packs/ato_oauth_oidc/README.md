# Pack `ato_oauth_oidc` (Phase C slice2 / v0.2)

Defensive hunt pack: OAuth/OIDC/ATO **candidates + evidence stubs**. Lab / authorized bounty use only.

## Can

- Surface heuristics for login / reset / OAuth / OIDC / SAML / magic-link URLs
- Missing `state` / PKCE / suspicious `redirect_uri` candidates
- **Nonce / PKCE verify stubs** (fixture-driven): presence + format of `nonce`, `code_challenge`, `code_challenge_method`
  - `confirmed` **only** when fixture `expect` proves the expected mismatch/absence
  - otherwise honest `unverified`
- **Client-type hints** (public vs confidential) from discovery/HTML/JSON fixtures — **low confidence**
- Token leakage pattern candidates (fixtures / URL fragments; values not stored)
- Password-reset enumeration candidates (known vs unknown fixtures; no lockout loops)
- Thin **report markdown** via `sentinel hunt report <program> [--pack ato_oauth_oidc] [-o FILE]` — Steps from evidence records only (no LLM)

## Cannot

- Full ATO chain automation
- Live IdP abuse / token-theft malware / exploit PoCs
- BOLA / IDOR (see pack `bola_idor_bfla`)
- Guard SDK, workflows, nuclei-all, lockout-abuse loops
- Invent Steps to Reproduce without evidence on the graph

## Fixtures (lab)

```json
{
  "nonce_pkce_verify": [
    {
      "url": "https://lab.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://lab.example/cb",
      "expect": { "pkce_absent": true, "nonce_absent": true }
    }
  ],
  "client_type_hints": [
    {
      "url": "https://lab.example/.well-known/openid-configuration",
      "discovery": { "token_endpoint_auth_methods_supported": ["none"] }
    }
  ]
}
```

`expect` keys: `nonce_absent`, `nonce_format_bad`, `pkce_absent`, `code_challenge_method_bad`, `code_challenge_format_bad`.

MIT. `ENGINE_ALLOWLIST` stays `{}`.
