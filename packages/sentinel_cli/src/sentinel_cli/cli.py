"""sentinel CLI — doctor, program, eye run, hunt run (Sprint 0)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path


def cmd_doctor(_: argparse.Namespace) -> int:
    lines: list[str] = []
    ok = True

    lines.append(f"python: {sys.version.split()[0]} ({sys.executable})")

    try:
        import sentinel_core
        from sentinel_core import (
            DEFERRED_ENGINES,
            Event,
            bin_dir,
            engine_catalog_summary,
            get_sentinel_home,
            list_engine_status,
            list_pinned,
        )

        lines.append(f"sentinel_core: import OK (v{sentinel_core.__version__})")
    except Exception as exc:  # noqa: BLE001
        ok = False
        lines.append(f"sentinel_core: FAIL ({exc})")
        print("\n".join(lines))
        return 1

    home = get_sentinel_home()
    lines.append(f"SENTINEL_HOME: {home}")

    try:
        home.mkdir(parents=True, exist_ok=True)
        probe = home / ".doctor_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        lines.append("SENTINEL_HOME writable: yes")
    except OSError as exc:
        ok = False
        lines.append(f"SENTINEL_HOME writable: no ({exc})")

    try:
        b = bin_dir(home)
        lines.append(f"bin dir: {b} (ok)")
    except OSError as exc:
        ok = False
        lines.append(f"bin dir: FAIL ({exc})")

    # Engine status: pinned / detected / allowlisted / deferred
    pinned = list_pinned(home)
    rows = list_engine_status(home)
    detected_rows = [r for r in rows if r["detected"]]
    pinned_rows = [r for r in rows if r["pinned"]]
    allowlisted_rows = [r for r in rows if r["allowlisted"]]
    deferred_not_pinned = [
        r for r in rows if r["deferred"] and not r["pinned"] and not r["detected"]
    ]

    if not pinned:
        lines.append("engines pinned: (none)")
    else:
        lines.append(f"engines pinned: {', '.join(sorted(pinned))}")
        for name, meta in sorted(pinned.items()):
            lines.append(f"  - {name}: version={meta.get('version')} path={meta.get('path')}")

    if detected_rows:
        lines.append("engines detected (PATH/bin):")
        for r in detected_rows:
            lines.append(
                f"  - {r['name']}: version={r.get('detected_version') or '?'} "
                f"@ {r.get('detected_path')}"
            )
    else:
        lines.append("engines detected: (none of common/deferred/pinned found)")

    if allowlisted_rows:
        lines.append(
            "engines allowlisted (downloadable): "
            + ", ".join(r["name"] for r in allowlisted_rows)
        )
        for r in allowlisted_rows:
            if not r["pinned"]:
                lines.append(
                    f"  - {r['name']}: allowlisted but not pinned "
                    "(ensure_engine(..., download=True) can fetch)"
                )
    else:
        lines.append(
            "engines allowlisted: (empty — no vetted hashes yet; see docs/ENGINES.md)"
        )

    if deferred_not_pinned:
        names = ", ".join(r["name"] for r in deferred_not_pinned[:12])
        more = (
            f" (+{len(deferred_not_pinned) - 12} more)"
            if len(deferred_not_pinned) > 12
            else ""
        )
        lines.append(f"engines deferred (not hashed): {names}{more}")
    else:
        lines.append(
            f"engines deferred catalog: {', '.join(DEFERRED_ENGINES)} "
            "(listed until hashed into allowlist)"
        )

    catalog = engine_catalog_summary()
    lines.append(
        "engines download: allowlist-only under SENTINEL_HOME/bin "
        f"(allowlisted={catalog['allowlisted'] or '[]'}; never mutates PATH)"
    )
    lines.append(
        "note: missing optional engines do not fail doctor in Sprint 0"
    )

    try:
        Event(type="DOMAIN", source_module="doctor", program_id="doctor")
        lines.append("event schema: ok")
    except Exception as exc:  # noqa: BLE001
        ok = False
        lines.append(f"event schema: FAIL ({exc})")

    # Optional package imports (eye/hunt)
    for pkg in ("shadowseye", "gungnir"):
        try:
            mod = __import__(pkg)
            lines.append(f"{pkg}: import OK (v{getattr(mod, '__version__', '?')})")
        except Exception as exc:  # noqa: BLE001
            lines.append(f"{pkg}: not importable ({exc}) — optional for core doctor")

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
    program_id: str,
    *,
    platform: str,
    allow_count: int,
    deny_count: int,
    name: str | None = None,
) -> None:
    """L0 Program brain: name, platform, allow/deny counts, updated_at, layers."""
    from datetime import datetime, timezone

    from sentinel_core import update_program_yml_fields

    update_program_yml_fields(
        program_id,
        name=name or program_id,
        platform=platform,
        allow_count=allow_count,
        deny_count=deny_count,
        updated_at=datetime.now(timezone.utc).isoformat(),
        layers_enabled=["L0"],
    )


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

    root = create_program(args.program_id)
    scope_file = root / "scope.txt"
    scope_file.write_text(scope_to_raw_text(scope), encoding="utf-8")
    _update_program_yml(
        args.program_id,
        platform=use_platform,
        allow_count=len(scope.allow),
        deny_count=len(scope.deny),
        name=args.program_id,
    )

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


def _add_scope_gate_flags(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group(required=False)
    g.add_argument(
        "--scope",
        dest="scope_path",
        default=None,
        help="Path to scope.txt (allow/deny). Required unless --i-own-this.",
    )
    g.add_argument(
        "--i-own-this",
        dest="i_own_this",
        action="store_true",
        help="Lab override: acknowledge you own/authorized the targets.",
    )


def cmd_eye_run(args: argparse.Namespace) -> int:
    from shadowseye.runner import run_eye

    if not args.scope_path and not args.i_own_this:
        print(
            "error: eye run requires --scope PATH or --i-own-this",
            file=sys.stderr,
        )
        return 2

    ports = None
    if args.ports:
        ports = [int(x.strip()) for x in args.ports.split(",") if x.strip()]

    no_tools = True if getattr(args, "no_tools", True) else False
    if getattr(args, "tools", False):
        no_tools = False

    result = run_eye(
        args.program_id,
        args.domains,
        scope_path=args.scope_path,
        i_own_this=args.i_own_this,
        wordlist_path=args.wordlist,
        ports=ports,
        resolve=not args.no_resolve,
        scan_ports=not args.no_ports,
        port_host_override=args.port_host,
        no_tools=no_tools,
        crtsh=not getattr(args, "no_crtsh", False),
        http_probe=not getattr(args, "no_http", False),
        fingerprint=(
            not getattr(args, "no_http", False)
            and not getattr(args, "no_fingerprint", False)
        ),
        watch=bool(getattr(args, "watch", False)),
        rank=True,
        identity=not getattr(args, "no_identity", False),
        reverse_ip=not getattr(args, "no_reverse_ip", False),
        scope_distance=int(getattr(args, "scope_distance", 1) or 1),
    )
    inv = result["inventory"]
    if getattr(args, "json_full", False):
        payload = {
            "program_id": result["program_id"],
            "event_count": result["event_count"],
            "scoped": result["scoped"],
            "no_tools": result.get("no_tools", True),
            "layers": result.get("layers"),
            "inventory": {
                "domains": inv.get("domains"),
                "dns_names": inv.get("dns_names"),
                "ips": inv.get("ips"),
                "ports": inv.get("ports"),
                "http": inv.get("http"),
                "tech": inv.get("tech") or [],
                "identity": inv.get("identity") or [],
                "sources": inv.get("sources") or [],
                "ranked": inv.get("ranked") or [],
                "notes": inv.get("notes") or [],
            },
        }
        if "watch" in result:
            payload["watch"] = result["watch"]
    else:
        payload = {
            "program_id": result["program_id"],
            "event_count": result["event_count"],
            "scoped": result["scoped"],
            "domains": inv.get("domains"),
            "dns_names": len(inv.get("dns_names") or []),
            "ips": len(inv.get("ips") or []),
            "ports": inv.get("ports"),
            "http": len(inv.get("http") or []),
            "identity": len(inv.get("identity") or []),
            "sources": inv.get("sources") or [],
            "ranked_top": (inv.get("ranked") or [])[:5],
        }
        if "watch" in result:
            payload["watch"] = {
                "first_run": result["watch"]["diffs"].get("first_run"),
                "snapshot_ts": result["watch"].get("snapshot_ts"),
                "dns_added": result["watch"]["diffs"]["dns_names"].get("added"),
                "ports_added": result["watch"]["diffs"]["ports"].get("added"),
            }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_hunt_run(args: argparse.Namespace) -> int:
    from gungnir.runner import run_hunt

    if not args.scope_path and not args.i_own_this:
        print(
            "error: hunt run requires --scope PATH or --i-own-this",
            file=sys.stderr,
        )
        return 2

    result = run_hunt(
        args.program_id,
        scope_path=args.scope_path,
        i_own_this=args.i_own_this,
        title=args.title,
        host=args.host,
        findings_file=args.findings,
        correlate=not args.no_correlate,
        evidence_summary=args.evidence,
    )
    print(json.dumps(
        {
            "program_id": result["program_id"],
            "findings_emitted": result["findings_emitted"],
            "correlated": result["correlated"],
            "scoped": result["scoped"],
            "events": result["events"],
        },
        indent=2,
    ))
    return 0



def cmd_hunt_pack_list(_: argparse.Namespace) -> int:
    from gungnir.packs import list_pack_manifests

    packs = list_pack_manifests()
    if not packs:
        print("no hunt packs registered")
        return 0
    rows = []
    for m in packs:
        rows.append(
            {
                "id": m.id,
                "class": m.pack_class,
                "needs_roles": m.needs_roles,
                "noise_class": m.noise_class,
                "version": m.version,
                "description": m.description,
                "consumes": list(m.consumes),
                "emits": list(m.emits),
            }
        )
    print(json.dumps({"packs": rows, "count": len(rows)}, indent=2))
    return 0


def cmd_hunt_pack_run(args: argparse.Namespace) -> int:
    from gungnir.packs import PackRunError, run_pack
    from sentinel_core import ScopeDenied

    if not args.scope_path and not args.i_own_this:
        print(
            "error: hunt pack run requires --scope PATH or --i-own-this",
            file=sys.stderr,
        )
        return 2

    try:
        result = run_pack(
            args.pack_id,
            args.program_id,
            scope_path=args.scope_path,
            i_own_this=args.i_own_this,
            urls=list(args.urls or []),
            role_a_path=args.role_a_path,
            role_b_path=args.role_b_path,
            max_workers=getattr(args, "max_workers", None),
            max_requests=getattr(args, "max_requests", None),
            max_duration=getattr(args, "max_duration", None),
            i_understand_lab=bool(getattr(args, "i_understand_lab", False)),
        )
    except PackRunError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(exc.exit_code)
    except ScopeDenied as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "program_id": result["program_id"],
                "pack_id": result["pack_id"],
                "pack_class": result["pack_class"],
                "surface_candidates": result["surface_candidates"],
                "findings_emitted": result["findings_emitted"],
                "flows_emitted": result.get("flows_emitted", 0),
                "steps_emitted": result.get("steps_emitted", 0),
                "roles_loaded": result["roles_loaded"],
                "scoped": result["scoped"],
                "events": result["events"],
                "flows": result.get("flows") or [],
                "steps": result.get("steps") or [],
                "hints": result.get("hints") or [],
                "pack_notes": result.get("pack_notes") or [],
                "caps": result.get("caps"),
                "observations": result.get("observations") or [],
            },
            indent=2,
        )
    )
    return 0



def cmd_hunt_report(args: argparse.Namespace) -> int:
    """Thin markdown report from graph findings + evidence (no LLM steps)."""
    from gungnir.packs.report import export_report

    result = export_report(
        args.program_id,
        pack_id=args.pack_id,
        output=args.output,
    )
    if args.output:
        print(
            json.dumps(
                {
                    "program_id": result["program_id"],
                    "pack_id": result["pack_id"],
                    "findings": result["findings"],
                    "output": result["output"],
                },
                indent=2,
            )
        )
    else:
        print(result["markdown"])
    return 0



def cmd_hunt_confirm_finding(args: argparse.Namespace) -> int:
    """Explicit human confirm of a FINDING (never auto-VERIFIED by packs)."""
    from gungnir.packs import ConfirmError, confirm_finding

    try:
        result = confirm_finding(
            args.program_id,
            args.finding_id,
            status=args.status,
            note=args.note,
            mark_role=args.mark_role,
        )
    except ConfirmError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(exc.exit_code)

    print(json.dumps(result, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel Suite CLI (Phase C slice5)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("doctor", help="Check SENTINEL_HOME, python, core, engines")
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

    eye = sub.add_parser("eye", help="ShadowsEye L0/L1/L2/L5 + fingerprint/watch/ranker")
    eye_sub = eye.add_subparsers(dest="eye_cmd", required=True)
    eye_run = eye_sub.add_parser(
        "run",
        help="Gather thin inventory and emit into program graph",
    )
    eye_run.add_argument("program_id", help="Program id (created if missing)")
    eye_run.add_argument(
        "domains",
        nargs="+",
        help="Target domain(s) — authorized assets only",
    )
    _add_scope_gate_flags(eye_run)
    eye_run.add_argument(
        "--wordlist",
        default=None,
        help="Optional subdomain wordlist (tiny default if omitted)",
    )
    eye_run.add_argument(
        "--ports",
        default=None,
        help="Comma-separated ports to probe (default: 80,443)",
    )
    eye_run.add_argument(
        "--no-resolve",
        action="store_true",
        help="Skip DNS resolution (lab)",
    )
    eye_run.add_argument(
        "--no-ports",
        action="store_true",
        help="Skip port probes",
    )
    eye_run.add_argument(
        "--port-host",
        default=None,
        help="Override host for port probes (e.g. 127.0.0.1 in tests)",
    )
    eye_run.add_argument(
        "--json",
        dest="json_full",
        action="store_true",
        help="Emit full inventory JSON sorted by interestingness",
    )
    eye_run.add_argument(
        "--watch",
        action="store_true",
        help="Persist runs/latest.json and emit added/removed diffs",
    )
    eye_run.add_argument(
        "--no-tools",
        dest="no_tools",
        action="store_true",
        default=True,
        help="Skip external engines (default True until allowlist hashes ready)",
    )
    eye_run.add_argument(
        "--tools",
        dest="tools",
        action="store_true",
        help="Opt-in external engines when allowlisted under SENTINEL_HOME/bin",
    )
    eye_run.add_argument(
        "--no-crtsh",
        action="store_true",
        help="Skip crt.sh CT stub",
    )
    eye_run.add_argument(
        "--no-http",
        action="store_true",
        help="Skip L5 HTTP probes (also skips tech fingerprint)",
    )
    eye_run.add_argument(
        "--no-fingerprint",
        action="store_true",
        help="Skip L5 tech fingerprint heuristics (default on when HTTP runs)",
    )
    eye_run.add_argument(
        "--fingerprint",
        dest="fingerprint_explicit",
        action="store_true",
        help="Explicitly enable tech fingerprint (default when HTTP is on)",
    )

    eye_run.add_argument(
        "--no-identity",
        action="store_true",
        help="Skip L1 identity lite (RDAP/MX/SPF); default is on",
    )
    eye_run.add_argument(
        "--no-reverse-ip",
        action="store_true",
        help="Skip reverse-IP neighbour discovery",
    )
    eye_run.add_argument(
        "--scope-distance",
        type=int,
        default=1,
        help="Max scope-distance for reverse-IP neighbours (default 1)",
    )

    eye_run.set_defaults(func=cmd_eye_run)

    hunt = sub.add_parser("hunt", help="Gungnir findings + hunt packs")
    hunt_sub = hunt.add_subparsers(dest="hunt_cmd", required=True)
    hunt_run = hunt_sub.add_parser(
        "run",
        help="Emit verified findings into program graph",
    )
    hunt_run.add_argument("program_id", help="Program id (created if missing)")
    _add_scope_gate_flags(hunt_run)
    hunt_run.add_argument("--title", default=None, help="Demo finding title")
    hunt_run.add_argument("--host", default=None, help="Finding host (for scope gate)")
    hunt_run.add_argument(
        "--findings",
        default=None,
        help="JSON file with finding object(s) or {findings: [...]}",
    )
    hunt_run.add_argument(
        "--evidence",
        default=None,
        help="Optional evidence summary linked to each finding",
    )
    hunt_run.add_argument(
        "--no-correlate",
        action="store_true",
        help="Skip thin correlate_findings dedupe",
    )
    hunt_run.set_defaults(func=cmd_hunt_run)

    hunt_pack = hunt_sub.add_parser("pack", help="Hunt packs (Phase C)")
    pack_sub = hunt_pack.add_subparsers(dest="pack_cmd", required=True)

    pack_list = pack_sub.add_parser("list", help="List registered hunt packs")
    pack_list.set_defaults(func=cmd_hunt_pack_list)

    pack_run = pack_sub.add_parser(
        "run",
        help="Run a hunt pack (fail-closed on missing roles / scope)",
    )
    pack_run.add_argument(
        "pack_id",
        help=(
            "Pack id (e.g. http_desync | jwt_session | csrf_state | xss_dom | graphql | race_toctou | business_logic | bola_idor_bfla | ato_oauth_oidc)"
        ),
    )
    pack_run.add_argument(
        "--program",
        dest="program_id",
        required=True,
        help="Program id under SENTINEL_HOME",
    )
    # Independent (not mutually exclusive): race_toctou / http_desync open-internet
    # needs --scope and --i-own-this plus --i-understand-lab. http_desync also
    # requires both ownership+lab flags for any non-pure-fixture path.
    pack_run.add_argument(
        "--scope",
        dest="scope_path",
        default=None,
        help="Path to scope.txt (allow/deny). Required unless --i-own-this.",
    )
    pack_run.add_argument(
        "--i-own-this",
        dest="i_own_this",
        action="store_true",
        help="Lab override: acknowledge you own/authorized the targets.",
    )
    pack_run.add_argument(
        "--url",
        dest="urls",
        action="append",
        default=[],
        help="Auth/OAuth/race surface URL (repeatable); else Eye inventory",
    )
    pack_run.add_argument(
        "--role-a",
        dest="role_a_path",
        default=None,
        help="Path to Role A session JSON (default: program/roles/a.json)",
    )
    pack_run.add_argument(
        "--role-b",
        dest="role_b_path",
        default=None,
        help="Path to Role B session JSON (default: program/roles/b.json)",
    )
    pack_run.add_argument(
        "--max-workers",
        dest="max_workers",
        type=int,
        default=None,
        help="race_toctou: concurrent workers (hard max 4; over-limit hard-fails)",
    )
    pack_run.add_argument(
        "--max-requests",
        dest="max_requests",
        type=int,
        default=None,
        help="Pack request budget (race_toctou hard max 20; http_desync/csrf_state/xss_dom/graphql/jwt_session/cache_host hard max 10; over-limit hard-fails)",
    )
    pack_run.add_argument(
        "--max-duration",
        dest="max_duration",
        type=float,
        default=None,
        help="race_toctou: max duration seconds (hard max 5; over-limit hard-fails)",
    )
    pack_run.add_argument(
        "--i-understand-lab",
        dest="i_understand_lab",
        action="store_true",
        help=(
            "Lab acknowledgment for race_toctou / http_desync: required with "
            "--i-own-this for http_desync beyond pure fixtures; open-internet "
            "also needs --scope. race_toctou open-internet needs --scope AND "
            "--i-own-this. Does NOT raise hard caps."
        ),
    )
    pack_run.set_defaults(func=cmd_hunt_pack_run)

    hunt_report = hunt_sub.add_parser(
        "report",
        help=(
            "Export thin platform-shaped markdown for pack findings "
            "(Steps from evidence records only — no LLM)"
        ),
    )
    hunt_report.add_argument("program_id", help="Program id under SENTINEL_HOME")
    hunt_report.add_argument(
        "--pack",
        dest="pack_id",
        default=None,
        help="Filter findings by pack id (e.g. http_desync | jwt_session | csrf_state | xss_dom | graphql | race_toctou | business_logic | bola_idor_bfla | ato_oauth_oidc)",
    )
    hunt_report.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        help="Write markdown to FILE (default: stdout)",
    )
    hunt_report.set_defaults(func=cmd_hunt_report)


    hunt_confirm = hunt_sub.add_parser(
        "confirm-finding",
        help=(
            "Human gate: explicitly mark a FINDING confirmed/verified "
            "(packs never auto-VERIFIED)"
        ),
    )
    hunt_confirm.add_argument("program_id", help="Program id under SENTINEL_HOME")
    hunt_confirm.add_argument(
        "finding_id",
        help="FINDING event id from the program graph",
    )
    hunt_confirm.add_argument(
        "--status",
        default="confirmed",
        choices=[
            "confirmed",
            "verified",
            "needs_human",
            "unverified",
            "not_reproduced",
            "skipped",
        ],
        help="Verification status to set (default: confirmed)",
    )
    hunt_confirm.add_argument(
        "--note",
        default=None,
        help="Optional human review note stored on the finding payload",
    )
    hunt_confirm.add_argument(
        "--mark-role",
        dest="mark_role",
        default=None,
        help="Optional role label that performed the confirm (e.g. a)",
    )
    hunt_confirm.set_defaults(func=cmd_hunt_confirm_finding)


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
