"""sentinel CLI — doctor + program init stubs (Sprint 0)."""

from __future__ import annotations

import argparse
import os
import sys
import traceback


def cmd_doctor(_: argparse.Namespace) -> int:
    lines: list[str] = []
    ok = True

    # Python
    lines.append(f"python: {sys.version.split()[0]} ({sys.executable})")

    # sentinel_core import
    try:
        import sentinel_core
        from sentinel_core import Event, get_sentinel_home, bin_dir

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
        lines.append(f"bin dir: {b} (ok)")
    except OSError as exc:
        ok = False
        lines.append(f"bin dir: FAIL ({exc})")

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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel Suite CLI (Sprint 0 scaffold)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("doctor", help="Check SENTINEL_HOME, python, core import, bin")
    d.set_defaults(func=cmd_doctor)

    prog = sub.add_parser("program", help="Program management")
    prog_sub = prog.add_subparsers(dest="program_cmd", required=True)
    init = prog_sub.add_parser("init", help="Create program folder under SENTINEL_HOME")
    init.add_argument("program_id", help="Program id (safe chars)")
    init.set_defaults(func=cmd_program_init)

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
