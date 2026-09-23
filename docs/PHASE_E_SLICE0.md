# Phase E slice0 — Open Lab + Juice Shop

**Goal:** File→Open Lab scaffold; Juice Shop campaign; expected findings; hints after attempt; Coach hooks.

Full can/cannot: `/workspace/deliverables/SENTINEL_SUITE_PHASE_E0_SLICE.md`

## CLI

```bash
sentinel lab list
sentinel lab open juice-shop --program lab-juice-shop
sentinel lab status lab-juice-shop
sentinel lab attempt lab-juice-shop js-admin-section --note 'tried /admin as role A'
sentinel lab hints lab-juice-shop js-admin-section
sentinel ui   # Labs tab → Open Lab
```

## Start Juice Shop (lab-only, loopback)

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
# → http://127.0.0.1:3000
```

CI does **not** require Docker. Expected findings are curriculum objectives — never auto-emitted as FINDING events.

## E0 Can / Cannot

See deliverable. Next: **E1** Coach deepen (lab-aware) — do not implement until GO.
