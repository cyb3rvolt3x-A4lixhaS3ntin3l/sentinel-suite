# Phase E slice3 — Lab 1 → platform-shaped report exit

**Goal:** Hunter tutorial done checklist + confirm-finding → Reports export for lab-bound programs. Lab 1 (juice-shop) finishes as `report.md` without leaving the suite story. Still no LLM / no invent / no auto-VERIFIED / no new money packs.

Full can/cannot: `/workspace/deliverables/SENTINEL_SUITE_PHASE_E3_SLICE.md`

## CLI / UI

```bash
sentinel lab open juice-shop --program lab-juice-shop
sentinel lab attempt lab-juice-shop <objective_id> --note '…'
sentinel lab hints lab-juice-shop <objective_id>
sentinel lab attempt lab-juice-shop <objective_id> --complete --note '…'
sentinel hunt confirm-finding lab-juice-shop <id> --status confirmed --note 'lab review'
sentinel lab tutorial lab-juice-shop
sentinel lab report lab-juice-shop -o ./report.md
sentinel ui   # Labs tab — Tutorial card + Export report.md
```

## Tutorial checklist

| Step | Meaning |
| --- | --- |
| `open_lab` | Program bound via Open Lab |
| `attempt` | ≥1 objective attempt recorded |
| `hints` | ≥1 objective hints unlocked |
| `complete` | ≥1 human complete mark |
| `confirm_finding` | ≥1 confirmed/verified FINDING on graph |
| `export_report` | `sentinel lab report` / Labs Export wrote `report.md` |

## Report shape

- Hunter tutorial checklist (honest done/pending)
- Curriculum progress table — **not findings**
- Confirmed findings (Phase C/D1 skeleton; evidence-only Steps)
- `invent_findings: false` · `auto_verified: false` · no LLM

## E3 Can / Cannot

See deliverable. **Phase E COMPLETE** — do not start Phase F in this GO.
