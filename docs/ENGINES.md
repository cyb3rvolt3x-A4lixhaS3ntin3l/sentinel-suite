# Engines — pin, detect, allowlist download

Sprint 0 engine story for `sentinel_core.engines`.

## Principles

1. **Never mutate system PATH.** Binaries land only under `$SENTINEL_HOME/bin/` (default `~/.sentinel/bin/`).
2. **No arbitrary URLs.** `ensure_engine(..., download=True)` fetches **only** names present in `ENGINE_ALLOWLIST` with pinned `{version, url, sha256, filename}`.
3. **sha256 before install.** Download goes to a temp file; hash must match; then rename into `bin/` and `pin_engine`.
4. **Honesty over theater.** If we cannot responsibly pin a third-party release hash, the allowlist stays empty and the engine is **deferred**.

## Status vocabulary (doctor / `list_engine_status`)

| Flag | Meaning |
|------|---------|
| **detected** | Binary found on PATH or under `SENTINEL_HOME/bin/` |
| **pinned** | Entry in `stamps.json` via `pin_engine` |
| **allowlisted** | Name present in `ENGINE_ALLOWLIST` (downloadable) |
| **deferred** | Known useful engine **not** yet hashed into the allowlist |

Doctor exits **0** when core is healthy even if optional engines are missing.

## How download works

```python
from sentinel_core import ensure_engine

# Missing + not allowlisted → clear error status, no network
ensure_engine("subfinder", download=True)
# → {"status": "not_allowlisted", "message": "...", "deferred": True}

# Allowlisted → fetch url, verify sha256, install under SENTINEL_HOME/bin/, pin
ensure_engine("some-vetted-tool", download=True)
# → {"status": "downloaded", "path": "...", "sha256": "...", ...}
```

Unknown / non-allowlisted names are **rejected**. There is no “download anything from this URL” API.

## Allowlist (current)

`ENGINE_ALLOWLIST` starts **empty** in this ship — no invented third-party hashes.

To add an entry later (human/vetted):

```python
# sentinel_core/engine_allowlist.py
ENGINE_ALLOWLIST = {
    "example-tool": {
        "version": "1.2.3",
        "url": "https://example.invalid/releases/example-tool-1.2.3",
        "sha256": "<64 hex chars of the exact artifact>",
        "filename": "example-tool",
    },
}
```

Tests may inject a temporary allowlist via `set_allowlist_for_tests` (test-only helper).

## Deferred engines (until hashed)

These names are catalogued for doctor / docs but **will not download** until allowlisted:

- `subfinder`
- `httpx`
- `naabu`
- `nuclei`
- `dnsx`
- `katana`
- `ffuf`

Until then: place a binary on PATH or copy into `$SENTINEL_HOME/bin/`, then:

```python
from sentinel_core import pin_engine
pin_engine("subfinder", "manual")
```

## Manual pin without download

```bash
cp /path/to/tool "$SENTINEL_HOME/bin/toolname"
python -c "from sentinel_core import pin_engine; pin_engine('toolname', '1.0.0')"
sentinel doctor
```
