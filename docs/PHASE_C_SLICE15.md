# Phase C slice15 — owned collaborator listener

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice15 — owned collaborator listener`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| `sentinel collaborator serve` | **real** | stdlib `ThreadingHTTPServer`; default bind `127.0.0.1` |
| `COLLABORATOR_HIT` event type | **real** | method / path / sanitized headers / body snippet |
| Pack `--listen` | **real** | ephemeral loopback URL when `--collaborator` omitted |
| Bind gate | **real** | `0.0.0.0` / `::` refuse without `--i-understand-lab` |
| Listen caps | **real** | duration default 120s (hard ≤300); hits ≤50 fail-closed |
| Metadata refuse | **intact** | slice14 gates unchanged |
| Prior 12 packs + confirm/report | **intact** | |
| race_toctou / http_desync / ssrf request caps | **untouched** | listen caps are additive only |
| ENGINE_ALLOWLIST | **still {}** | no `--tools` |

## Can

- Serve an **operator-owned** collaborator on loopback and log inbound callbacks
  as `COLLABORATOR_HIT` on the program graph
- Use `sentinel hunt pack run ssrf_collaborator --listen` so the pack’s
  collaborator URL points at the local listener when `--collaborator` is omitted
- Keep pure fixture CI path working **without** `--listen`
- Dual-stack `::1` loopback allowed; optional non-loopback bind only with lab flag

## Cannot

- Default public internet listener (`0.0.0.0` / `::` without `--i-understand-lab`)
- interactsh / SaaS collaborator client
- Outbound scanning / random-target SSRF
- Cloud metadata as collaborator (slice14 refuse remains)
- Raise race_toctou / http_desync / ssrf request hard caps
- Guard SDK / workflows / X / PyPI / Tauri

## CLI

```bash
# Owned loopback listener (logs COLLABORATOR_HIT → program graph)
sentinel collaborator serve --program demo
sentinel collaborator serve --program demo --bind 127.0.0.1 --port 8765 \
  --max-duration 120 --max-hits 50

# Pack + local listener URL (when --collaborator omitted)
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this --listen

# Fixtures still work without --listen
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this
```

## Security gates

| Gate | Behavior |
| --- | --- |
| Default bind | `127.0.0.1` only |
| `0.0.0.0` / `::` | Hard refuse unless `--i-understand-lab` |
| Metadata collaborator URL | Still refused (slice14) |
| Max duration | Default 120s; hard max 300s |
| Max hits | ≤50; fail-closed when exceeded |
| Body / headers | Truncated snippet; auth/cookie redacted |
| Outbound scan | None — inbound callback log only |

## Caps

`gungnir.packs.ssrf_collaborator.caps`:  
`DEFAULT_LISTEN_DURATION_S=120`, `HARD_MAX_LISTEN_DURATION_S=300`,  
`DEFAULT_MAX_HITS=HARD_MAX_HITS=50`, `DEFAULT_BIND=127.0.0.1`.

## Fences / HOLD

- ENGINE_ALLOWLIST remains `{}`
- MIT; no workflows; no Guard SDK; no interactsh; no cloud-metadata collaborator
