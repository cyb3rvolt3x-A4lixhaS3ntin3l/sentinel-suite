"""Brand console entry: ``gungnir`` (thin Hunt CLI; prefer ``sentinel hunt`` for full suite)."""

from __future__ import annotations

import argparse
import json
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gungnir",
        description=(
            "Gungnir brand CLI (Hunt packs). Full suite: install sentinel-suite "
            "and use `sentinel hunt` / `sentinel doctor`."
        ),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    packs = sub.add_parser("packs", help="List registered hunt packs")
    packs.set_defaults(func=_cmd_packs)

    ver = sub.add_parser("version", help="Print package version")
    ver.set_defaults(func=_cmd_version)
    return p


def _cmd_version(_: argparse.Namespace) -> int:
    from gungnir import __version__

    print(f"gungnir {__version__}")
    return 0


def _cmd_packs(_: argparse.Namespace) -> int:
    from gungnir.packs import list_pack_manifests

    rows = [m.to_dict() for m in list_pack_manifests()]
    print(json.dumps(rows, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
