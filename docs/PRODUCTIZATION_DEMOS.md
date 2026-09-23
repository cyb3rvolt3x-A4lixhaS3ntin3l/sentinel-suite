# Productization demos (Step 1) — pointer

**Status:** DEMOS COMPLETE (2026-09-23 IST) — Founder-owned hosts only. No packaging builds. No README rewrite.

Full evidence packet (commands, real counts, skips, CLI gaps):

`/workspace/deliverables/SENTINEL_SUITE_PRODUCTIZATION_DEMOS.md`

In-repo copies of **real** artifacts (no invented findings):

- [`assets/demos/`](assets/demos/) — briefs, CLI transcripts, Eye JSON, 0-finding reports, zip exports, UI/terminal PNGs
- Video: [`assets/demos/demo_walkthrough.mp4`](assets/demos/demo_walkthrough.mp4) (95s, 589K) — copy also at `/workspace/deliverables/demos/demo_walkthrough.mp4`

## Scope actually run

- `andraxpentester.in` + `www.andraxpentester.in` → program `demo-andrax`
- `sentinelreign.com` + `www.sentinelreign.com` → program `demo-sentinelreign`
- `guard.sentinelreign.com` → **skipped** (fail-closed / Guard-adjacent)

## Honest headline numbers (from the run)

| Program | Eye events | DNS names | HTTP (CLI rows) | Tech | Findings |
| --- | ---: | ---: | ---: | ---: | ---: |
| demo-andrax | 15 | 2 | 4 | 0 | **0** |
| demo-sentinelreign | 17 | 4 | 4 | 1 (cloudflare heuristic) | **0** |

Zeros are real: official packs are fixture-first; live 127.0.0.1 mocks were OOS under `--scope`.

## Next (packaging step — not this commit)

- `sentinel ui --open` / `sentinel full-run` (do not exist today)
- `--scope` and `--i-own-this` are XOR on `eye run`
