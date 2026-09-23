"""Brand console entry: ``shadowseye`` (thin Eye CLI; prefer ``sentinel eye`` for full suite)."""

from __future__ import annotations

import argparse
import json
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shadowseye",
        description=(
            "ShadowsEye brand CLI (Eye only). Full suite: install sentinel-suite "
            "and use `sentinel eye` / `sentinel doctor`."
        ),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run Eye inventory into a program graph")
    run.add_argument("program_id")
    run.add_argument("domain")
    run.add_argument("--scope", default=None)
    run.add_argument("--i-own-this", action="store_true")
    run.add_argument("--no-ports", action="store_true")
    run.add_argument("--json", action="store_true")
    run.set_defaults(func=_cmd_run)

    ver = sub.add_parser("version", help="Print package version")
    ver.set_defaults(func=_cmd_version)
    return p


def _cmd_version(_: argparse.Namespace) -> int:
    from shadowseye import __version__

    print(f"shadowseye {__version__}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    from shadowseye.runner import run_eye

    try:
        result = run_eye(
            args.program_id,
            [args.domain],
            scope_path=args.scope,
            i_own_this=bool(args.i_own_this),
            scan_ports=not args.no_ports,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        inv = result.get("inventory") or {}
        print(
            f"eye ok program={args.program_id} domain={args.domain} "
            f"dns={len(inv.get('dns_names') or [])} "
            f"ports={len(inv.get('ports') or [])}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
