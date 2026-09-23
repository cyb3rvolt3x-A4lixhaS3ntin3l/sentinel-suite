# Phase E slice2 — crAPI + auth-session + UX polish

**Goal:** Catalog ≥3 labs (juice-shop + crapi + auth-session); shared attempt/hint/complete UX; versioned progress schema; Coach lab kinds reuse E1 (`lab_stage` / `lab_fp_school` / `lab_time_budget`). Still no LLM / no invent / no auto-VERIFIED / no new money packs.

Full can/cannot: `/workspace/deliverables/SENTINEL_SUITE_PHASE_E2_SLICE.md`

## CLI / UI

```bash
sentinel lab list
sentinel lab open juice-shop --program lab-juice-shop
sentinel lab open crapi --program lab-crapi
# if Sentinel UI already on :8888, remap crAPI or UI:
sentinel lab open crapi --program lab-crapi --base-url http://127.0.0.1:8889
sentinel lab open auth-session --program lab-auth-session
sentinel lab attempt lab-crapi crapi-bola-vehicle --note 'role B on vehicle'
sentinel lab hints lab-crapi crapi-bola-vehicle
sentinel lab coach lab-crapi
sentinel ui   # Labs tab — same attempt/hint/complete controls for every lab
```

## Progress schema

`lab_progress.json` (under program dir / `SENTINEL_HOME`):

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` (E2). E0/E1 files without it migrate on load (attempts/completed kept). |
| `lab_id` / `program_id` | Binding identifiers |
| `attempts` | Per-objective attempt records (`count`, `note`, `notes[]`, `hints_unlocked`) |
| `completed` | Human complete marks only (`auto: false`) |
| `updated_at` | ISO timestamp |

## E2 Can / Cannot

See deliverable. Next: **E3** Lab 1 → platform-shaped report exit — do not implement until GO.
