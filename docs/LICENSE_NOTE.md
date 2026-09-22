# License note — Apache preference vs MIT ship

**Decision for this monorepo (Sprint 0 Phase A):** **MIT**

## Why MIT (not Apache-2.0 yet)

- Live public packages being bridged ship under **MIT**:
  - ShadowsEye (`shadowseye-harden` / cyb3rvolt3x-A4lixhaS3ntin3l ShadowsEye)
  - Gungnir (`gungnir-harden` / cyb3rvolt3x-A4lixhaS3ntin3l gungnir)
- Monorepo consistency: one license for `sentinel_core` + thin bridge stubs + CLI avoids dual-license confusion for early adopters and pipx installs later.
- Founder product brief preferred **Apache-2.0** for new core + official modules (patent grant / clearer contribution story).

## Conflict (documented, unresolved at product level)

| Preference | Source | Status |
| --- | --- | --- |
| Apache-2.0 | Founder vision lock / plan §8 Q4 | Preferred for greenfield core |
| MIT | Existing ShadowsEye + Gungnir LICENSE files | Chosen for Sprint 0 ship |

**HUMAN-QUEUE:** Founder may later re-license the monorepo (or core-only) to Apache-2.0 once bridge packages are fully absorbed and live mirror repos are updated. Until then, treat this tree as MIT.

## Guard SDK

Guard SDK / `sentinelagent-guard` / `packages/guard-*` are **out of scope** and untouched. Their licenses are separate product lines.
