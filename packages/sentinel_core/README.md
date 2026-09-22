# sentinel_core

Shared library for **Sentinel Suite**: event schema v1, SQLite WAL graph per program, scope kernel, HTTP hard-kill helper, engine pin under `SENTINEL_HOME`.

This is a **new clean library** — not a port of the legacy Flask `sentinel_core/` tree from ShadowsEye.

## Scope

- `load_scope_text` / `load_scope_file` — raw allow/deny (`!deny`)
- `parse_brief(text, platform=...)` — `auto|h1|bugcrowd|generic|raw`
- `detect_brief_platform(text)`
- `assert_url_in_scope` / `scoped_request` / `prepare_scoped_request` — hard-kill host before fetch

## Engines

- `detect_engine(name)` — PATH + `SENTINEL_HOME/bin`
- `ensure_engine(name, download=...)` — download **deferred** in Sprint 0
- `pin_engine` / `stamp_run` / `list_pinned`

See repo root README for CLI (`sentinel program import-brief`, `sentinel doctor`).
