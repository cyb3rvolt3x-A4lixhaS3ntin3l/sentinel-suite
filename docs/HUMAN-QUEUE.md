# HUMAN-QUEUE — Sprint 0 Phase A

Items that need a human (OAuth scope, Founder decision, or later day work). Not blockers for local use of this scaffold.

## Blocked / needs human OAuth

1. **GitHub Actions workflow push** — `gh` is authenticated with scopes `gist, read:org, repo` but **no `workflow` scope**. Pushing `.github/workflows/*.yml` may be rejected by GitHub. If rejected:
   - Workflow file may be omitted from the pushed commit or left only locally.
   - Human: re-auth `gh` with `workflow` scope, then add/push `.github/workflows/ci.yml`.
   - Until then, run tests locally: `cd /path/to/sentinel-suite && pip install -e packages/sentinel_core -e packages/shadowseye -e packages/gungnir -e packages/sentinel_cli && pytest -q`

## Deferred (not day-1)

2. **Thin README mirrors** on existing `gungnir` + `ShadowsEye` public repos — point at this monorepo. Explicitly **not** part of this ship.
3. **License re-eval** — Founder Apache-2.0 preference vs MIT consistency (see `docs/LICENSE_NOTE.md`).
4. **PyPI publish** — not in Sprint 0; install via editable clone / pipx from git later.
5. **Guard SDK** — never touch; separate product.

## Local CI until workflow is live

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -U pip pytest
pip install -e packages/sentinel_core -e packages/shadowseye -e packages/gungnir -e packages/sentinel_cli
pytest -q
sentinel doctor
sentinel program init demo
```
