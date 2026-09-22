"""sentinel CLI — doctor + program init/import-brief (Sprint 0)."""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from pathlib import Path


def cmd_doctor(_: argparse.Namespace) -> int:
    lines: list[str] = []
    ok = True

    # Python
    lines.append(f"python: {sys.version.split()[0]} ({sys.executable})")

    # sentinel_core import
    try:
        import sentinel_core
        from sentinel_core import Event, bin_dir, detect_engine, get_sentinel_home, list_pinned

        lines.append(f"sentinel_core: import OK (v{sentinel_core.__version__})")
    except Exception as exc:  # noqa: BLE001
        ok = False
        lines.append(f"sentinel_core: FAIL ({exc})")
        print("\n".join(lines))
        return 1

    home = get_sentinel_home()
    lines.append(f"SENTINEL_HOME: {home}")

    # writable home
    try:
        home.mkdir(parents=True, exist_ok=True)
        probe = home / ".doctor_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        lines.append("SENTINEL_HOME writable: yes")
    except OSError as exc:
        ok = False
        lines.append(f"SENTINEL_HOME writable: no ({exc})")

    # bin dir
    try:
        b = bin_dir(home)
        entries = [p.name for p in b.iterdir() if p.is_file() and p.name != "stamps.json"]
        if not entries and not list_pinned(home):
            lines.append(f"bin dir: {b} (ok, empty — no pinned engines yet)")
        else:
            lines.append(f"bin dir: {b} (ok)")
    except OSError as exc:
        ok = False
        lines.append(f"bin dir: FAIL ({exc})")

    # Engine pin vs detect
    pinned = list_pinned(home)
    if not pinned:
        lines.append("engines pinned: (none — pin dir empty / no stamps.json entries)")
    else:
        lines.append(f"engines pinned: {', '.join(sorted(pinned))}")
        for name, meta in sorted(pinned.items()):
            det = detect_engine(name, home=home)
            if det:
                lines.append(
                    f"  - {name}: pinned={meta.get('version')} "
                    f"detected={det.get('version') or '?'} @ {det.get('path')}"
                )
            else:
                lines.append(
                    f"  - {name}: pinned={meta.get('version')} "
                    f"detected=(missing on PATH/bin)"
                )
    lines.append(
        "engines download: deferred (Sprint 0 pin is detect+stamp only; "
        "ensure_engine(..., download=True) returns download_deferred)"
    )

    # Event schema smoke
    try:
        Event(type="DOMAIN", source_module="doctor", program_id="doctor")
        lines.append("event schema: ok")
    except Exception as exc:  # noqa: BLE001
        ok = False
        lines.append(f"event schema: FAIL ({exc})")

    status = "PASS" if ok else "FAIL"
    lines.append(f"doctor: {status}")
    print("\n".join(lines))
    return 0 if ok else 1


def cmd_program_init(args: argparse.Namespace) -> int:
    from sentinel_core import create_program, get_sentinel_home

    path = create_program(args.program_id)
    print(f"created program {args.program_id!r} at {path}")
    print(f"SENTINEL_HOME={get_sentinel_home()}")
    return 0


def _update_program_yml(
    yml_path: Path,
    *,
    platform: str,
    allow_count: int,
    deny_count: int,
) -> None:
    """Patch or append platform + scope counts in program.yml (minimal YAML)."""
    text = yml_path.read_text(encoding="utf-8") if yml_path.exists() else ""
    lines = text.splitlines()
    keys = {
        "brief_platform": platform,
        "scope_allow_count": str(allow_count),
        "scope_deny_count": str(deny_count),
    }
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        stripped = line.strip()
        replaced = False
        for key, val in keys.items():
            if stripped.startswith(f"{key}:"):
                out.append(f"{key}: {val}")
                seen.add(key)
                replaced = True
                break
        if not replaced:
            out.append(line)
    for key, val in keys.items():
        if key not in seen:
            out.append(f"{key}: {val}")
    yml_path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")


def cmd_program_import_brief(args: argparse.Namespace) -> int:
    from sentinel_core import (
        create_program,
        detect_brief_platform,
        open_graph,
        parse_brief,
        program_dir,
        scope_to_raw_text,
    )

    brief_path = Path(args.brief_file)
    if not brief_path.is_file():
        print(f"error: brief file not found: {brief_path}", file=sys.stderr)
        return 1

    text = brief_path.read_text(encoding="utf-8")
    platform = args.platform
    detected = detect_brief_platform(text)
    if platform == "auto":
        use_platform = detected
    else:
        use_platform = platform

    scope = parse_brief(text, platform=use_platform)

    # create-or-open program
    root = create_program(args.program_id)
    scope_file = root / "scope.txt"
    scope_file.write_text(scope_to_raw_text(scope), encoding="utf-8")
    _update_program_yml(
        root / "program.yml",
        platform=use_platform,
        allow_count=len(scope.allow),
        deny_count=len(scope.deny),
    )

    # ensure graph exists / opens
    with open_graph(args.program_id):
        pass

    print(f"program: {args.program_id}")
    print(f"path: {program_dir(args.program_id)}")
    print(f"brief: {brief_path}")
    print(f"platform: {use_platform} (detected={detected}, requested={platform})")
    print(f"allow: {len(scope.allow)}  deny: {len(scope.deny)}")
    if scope.allow:
        preview = ", ".join(scope.allow[:8])
        more = "" if len(scope.allow) <= 8 else f" (+{len(scope.allow) - 8} more)"
        print(f"allow preview: {preview}{more}")
    if scope.deny:
        preview = ", ".join(scope.deny[:8])
        more = "" if len(scope.deny) <= 8 else f" (+{len(scope.deny) - 8} more)"
        print(f"deny preview: {preview}{more}")
    print(f"wrote: {scope_file}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel Suite CLI (Sprint 0 scaffold)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("doctor", help="Check SENTINEL_HOME, python, core import, bin, engines")
    d.set_defaults(func=cmd_doctor)

    prog = sub.add_parser("program", help="Program management")
    prog_sub = prog.add_subparsers(dest="program_cmd", required=True)

    init = prog_sub.add_parser("init", help="Create program folder under SENTINEL_HOME")
    init.add_argument("program_id", help="Program id (safe chars)")
    init.set_defaults(func=cmd_program_init)

    imp = prog_sub.add_parser(
        "import-brief",
        help="Parse a program brief into scope.txt + update program.yml",
    )
    imp.add_argument("program_id", help="Program id (created if missing)")
    imp.add_argument("brief_file", help="Path to brief text file")
    imp.add_argument(
        "--platform",
        choices=["auto", "h1", "bugcrowd", "generic", "raw"],
        default="auto",
        help="Brief format (default: auto-detect)",
    )
    imp.set_defaults(func=cmd_program_import_brief)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        if os.environ.get("SENTINEL_DEBUG"):
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
