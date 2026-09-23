# Productization demos (Step 1) — pointer

**Status:** DEMOS COMPLETE (2026-09-23 IST) — Founder-owned hosts only. README product rewrite shipped (see [`PRODUCTIZATION_README.md`](PRODUCTIZATION_README.md)).

Full evidence packet (commands, real counts, skips, CLI gaps):

`/workspace/deliverables/SENTINEL_SUITE_PRODUCTIZATION_DEMOS.md`

In-repo copies of **real** artifacts (no invented findings):

- [`assets/demos/`](assets/demos/) — briefs, CLI transcripts, Eye JSON, 0-finding reports, zip exports, UI/terminal PNGs
- Video: [`assets/demos/demo_walkthrough.mp4`](assets/demos/demo_walkthrough.mp4) (95s, 589K) — copy also at `/workspace/deliverables/demos/demo_walkthrough.mp4`
- GIF preview: [`assets/demos/demo_preview.gif`](assets/demos/demo_preview.gif) (12s cut of the same mp4)

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

## Notes after later steps

- `sentinel ui --open` / `sentinel demo` / `sentinel full-run` now exist (packaging step).
- `--scope` and `--i-own-this` remain XOR on `eye run`.
- GIF preview `assets/demos/demo_preview.gif` is a 12s cut of the same 95s mp4 (not a new run).
