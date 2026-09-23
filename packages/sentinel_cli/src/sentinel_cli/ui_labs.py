"""Phase E0 — Open Lab: curriculum labs (Juice Shop), attempts, hints-after-attempt.

Labs are curricula, not hunt packs. Never invent FINDING events or auto-VERIFIED.
Hints stay locked until the operator records an attempt for that objective.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel_core import create_program, program_dir, update_program_yml_fields

LAB_FILE = "lab.json"
PROGRESS_FILE = "lab_progress.json"

# Default Juice Shop bind (intentional vuln app — local docker only).
JUICE_SHOP_DEFAULT_BASE = "http://127.0.0.1:3000"

JUICE_SHOP_START_DOCS = """# Start OWASP Juice Shop (lab-only)

Default target: http://127.0.0.1:3000 (loopback).

## Docker (recommended)

```bash
docker run --rm -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
# open http://127.0.0.1:3000
# stop: docker stop juice-shop
```

## Notes

- Lab-only intentional vulnerable app. Do **not** point packs at real/third-party targets.
- Sentinel Suite never auto-emits FINDING events from this curriculum.
- Pack runs still need --i-own-this (and --i-understand-lab where Phase C requires it).
- Confirm findings with a human note before any report claim (never auto-VERIFIED).
"""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hint_ladder(*bodies: str) -> list[dict[str, str]]:
    return [{"level": i + 1, "body": b} for i, b in enumerate(bodies)]


def _juice_shop_objectives() -> list[dict[str, Any]]:
    """Curriculum objectives — titles only; not discovered vulnerabilities."""
    return [
        {
            "id": "js-score-board",
            "title": "Locate the Score Board (recon)",
            "category": "recon",
            "difficulty": "starters",
            "suggested_packs": [],
            "summary": (
                "Curriculum: discover how Juice Shop exposes challenge progress. "
                "Not a vulnerability claim — recon objective only."
            ),
            "hints": _hint_ladder(
                "Recon first: list interesting paths from the SPA / robots / client bundles "
                "before guessing admin URLs.",
                "Many Juice Shop builds hide a score-board route from the main nav — "
                "search client-side routes or common path names.",
                "Try paths related to score-board / challenges once you have a candidate URL "
                "in scope (127.0.0.1 / localhost only).",
            ),
        },
        {
            "id": "js-admin-section",
            "title": "Broken access control — Administration Section",
            "category": "access_control",
            "difficulty": "starters",
            "suggested_packs": ["bola_idor_bfla", "business_logic"],
            "summary": (
                "Curriculum: practice object/role access methodology against a local "
                "admin surface. Suggested packs are methodology only — packs never "
                "auto-VERIFIED."
            ),
            "hints": _hint_ladder(
                "Map auth surfaces and role sessions first (Auth lab / roles/a.json). "
                "Access-control bugs need two perspectives.",
                "Look for administration routes that appear in the client but should "
                "require elevated role — check responses as anonymous vs logged-in.",
                "If you get a different status/body across roles on the same object path, "
                "record evidence via a gated pack run (bola_idor_bfla) — still needs_human.",
            ),
        },
        {
            "id": "js-dom-xss-search",
            "title": "DOM XSS — search / reflected sink practice",
            "category": "xss",
            "difficulty": "starters",
            "suggested_packs": ["xss_dom"],
            "summary": (
                "Curriculum: practice DOM sink identification on local search UI. "
                "Reflection alone is not XSS — see Coach FP school."
            ),
            "hints": _hint_ladder(
                "FP school: reflection ≠ XSS. Identify a sink (innerHTML / location / …) "
                "before claiming impact.",
                "Juice Shop search UIs often reflect query text into the DOM — inspect "
                "where the marker lands.",
                "Use xss_dom pack methodology against http://127.0.0.1:3000 with "
                "--i-own-this; findings stay needs_human until confirm-finding.",
            ),
        },
        {
            "id": "js-jwt-auth",
            "title": "JWT / session weakness practice",
            "category": "auth",
            "difficulty": "intermediate",
            "suggested_packs": ["jwt_session", "ato_oauth_oidc"],
            "summary": (
                "Curriculum: inspect JWTs issued by local Juice Shop login. "
                "Unsigned/weak alg claims require evidence — never invent tokens."
            ),
            "hints": _hint_ladder(
                "Capture a real session token from lab login (Auth lab vault display) — "
                "do not invent tokens in reports.",
                "Decode header/payload locally; look for alg / role claims. Weak-alg "
                "checks belong in jwt_session methodology.",
                "Run jwt_session with --i-own-this against the lab base URL; confirm "
                "with a human note before report wording.",
            ),
        },
        {
            "id": "js-open-redirect",
            "title": "Open redirect practice",
            "category": "redirect",
            "difficulty": "starters",
            "suggested_packs": ["open_redirect"],
            "summary": (
                "Curriculum: find redirect parameters that accept off-site URLs. "
                "Impact needs a chain story — redirect alone is often informative."
            ),
            "hints": _hint_ladder(
                "Hunt redirect/to/returnUrl-style parameters on login and checkout flows.",
                "Confirm the Location / client navigation actually follows an attacker "
                "URL you control (lab-only).",
                "open_redirect pack is methodology for cataloging candidates — "
                "confirm-finding before platform report language.",
            ),
        },
    ]


def lab_catalog() -> list[dict[str, Any]]:
    """Static lab catalog (E0: Juice Shop only)."""
    return [
        {
            "lab_id": "juice-shop",
            "name": "OWASP Juice Shop — Lab 1",
            "version": "e0",
            "kind": "intentional_vuln_app",
            "default_program_id": "lab-juice-shop",
            "default_base_url": JUICE_SHOP_DEFAULT_BASE,
            "default_hosts": ["127.0.0.1", "localhost"],
            "default_port": 3000,
            "objective_count": len(_juice_shop_objectives()),
            "objectives": _juice_shop_objectives(),
            "start_docs": JUICE_SHOP_START_DOCS,
            "disclaimer": (
                "Curriculum lab. Expected findings are learning objectives, not "
                "auto-emitted graph FINDING events. Loopback defaults only."
            ),
        }
    ]


def get_lab_def(lab_id: str) -> dict[str, Any]:
    for lab in lab_catalog():
        if lab["lab_id"] == lab_id:
            return lab
    raise FileNotFoundError(
        f"unknown lab_id {lab_id!r}; run: sentinel lab list"
    )


def labs_payload() -> dict[str, Any]:
    labs = lab_catalog()
    return {
        "labs": [
            {
                "lab_id": L["lab_id"],
                "name": L["name"],
                "version": L["version"],
                "kind": L["kind"],
                "default_program_id": L["default_program_id"],
                "default_base_url": L["default_base_url"],
                "objective_count": L["objective_count"],
                "disclaimer": L["disclaimer"],
            }
            for L in labs
        ],
        "count": len(labs),
        "phase": "E1",
        "note": (
            "Open Lab creates/binds a program with lab.json + loopback scope. "
            "Does not start Docker; see start_docs on lab detail / open result."
        ),
    }


def _lab_path(program_id: str) -> Path:
    return program_dir(program_id) / LAB_FILE


def _progress_path(program_id: str) -> Path:
    return program_dir(program_id) / PROGRESS_FILE


def load_lab_binding(program_id: str) -> dict[str, Any] | None:
    path = _lab_path(program_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def load_progress(program_id: str) -> dict[str, Any]:
    path = _progress_path(program_id)
    if not path.is_file():
        return {"attempts": {}, "completed": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"attempts": {}, "completed": {}}
    if not isinstance(data, dict):
        return {"attempts": {}, "completed": {}}
    attempts = data.get("attempts") if isinstance(data.get("attempts"), dict) else {}
    completed = data.get("completed") if isinstance(data.get("completed"), dict) else {}
    return {"attempts": attempts, "completed": completed}


def save_progress(program_id: str, progress: dict[str, Any]) -> None:
    root = program_dir(program_id)
    if not root.is_dir():
        raise FileNotFoundError(
            f"program {program_id!r} not found; open a lab first"
        )
    path = _progress_path(program_id)
    payload = {
        "attempts": progress.get("attempts") or {},
        "completed": progress.get("completed") or {},
        "updated_at": _utcnow_iso(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_scope_for_lab(root: Path, hosts: list[str], port: int) -> None:
    lines = [
        "# Sentinel Suite lab scope — loopback intentional vuln app only",
        "# Deny everything else by not listing it; packs still need ownership flags.",
    ]
    for h in hosts:
        lines.append(h)
        if port:
            lines.append(f"{h}:{port}")
    scope = root / "scope.txt"
    scope.write_text("\n".join(lines) + "\n", encoding="utf-8")


def open_lab(
    lab_id: str,
    *,
    program_id: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    """
    Create/bind a program to a lab curriculum.

    Writes lab.json + lab_progress.json + loopback scope. Does not start Docker
    and does not emit FINDING events.
    """
    lab = get_lab_def(lab_id)
    pid = (program_id or lab["default_program_id"]).strip()
    if not pid:
        raise ValueError("program_id required")

    root = create_program(pid)
    url = (base_url or lab["default_base_url"]).rstrip("/")
    hosts = list(lab.get("default_hosts") or ["127.0.0.1", "localhost"])
    port = int(lab.get("default_port") or 3000)
    _write_scope_for_lab(root, hosts, port)

    binding = {
        "lab_id": lab["lab_id"],
        "name": lab["name"],
        "program_id": pid,
        "base_url": url,
        "hosts": hosts,
        "port": port,
        "opened_at": _utcnow_iso(),
        "phase": "E1",
        "invent_findings": False,
        "auto_verified": False,
    }
    (_lab_path(pid)).write_text(
        json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not _progress_path(pid).is_file():
        save_progress(pid, {"attempts": {}, "completed": {}})

    (root / "LAB_START.md").write_text(lab["start_docs"], encoding="utf-8")

    update_program_yml_fields(
        pid,
        name=lab["name"],
        platform="lab",
        extra={"lab_id": lab["lab_id"], "lab_base_url": url},
    )

    return lab_status_payload(pid)


def _objective_by_id(lab: dict[str, Any], objective_id: str) -> dict[str, Any]:
    for obj in lab.get("objectives") or []:
        if obj.get("id") == objective_id:
            return obj
    raise FileNotFoundError(
        f"unknown objective_id {objective_id!r} for lab {lab.get('lab_id')!r}"
    )


def record_attempt(
    program_id: str,
    objective_id: str,
    *,
    note: str | None = None,
) -> dict[str, Any]:
    """Record an attempt; unlocks hints for that objective. No FINDING emission."""
    binding = load_lab_binding(program_id)
    if not binding:
        raise FileNotFoundError(
            f"program {program_id!r} is not an open lab; run: sentinel lab open …"
        )
    lab = get_lab_def(str(binding["lab_id"]))
    _objective_by_id(lab, objective_id)

    progress = load_progress(program_id)
    attempts = dict(progress.get("attempts") or {})
    prev = attempts.get(objective_id) if isinstance(attempts.get(objective_id), dict) else {}
    count = int(prev.get("count") or 0) + 1
    entry = {
        "objective_id": objective_id,
        "attempted_at": _utcnow_iso(),
        "count": count,
        "note": (note or "").strip() or None,
        "hints_unlocked": True,
    }
    attempts[objective_id] = entry
    progress["attempts"] = attempts
    save_progress(program_id, progress)
    return lab_status_payload(program_id)


def mark_objective_complete(
    program_id: str,
    objective_id: str,
    *,
    note: str | None = None,
) -> dict[str, Any]:
    """Explicit human complete mark only — never auto from pack output."""
    binding = load_lab_binding(program_id)
    if not binding:
        raise FileNotFoundError(
            f"program {program_id!r} is not an open lab"
        )
    lab = get_lab_def(str(binding["lab_id"]))
    _objective_by_id(lab, objective_id)
    progress = load_progress(program_id)
    completed = dict(progress.get("completed") or {})
    completed[objective_id] = {
        "objective_id": objective_id,
        "completed_at": _utcnow_iso(),
        "note": (note or "").strip() or None,
        "auto": False,
    }
    progress["completed"] = completed
    # Completing implies attempt (hints unlocked)
    attempts = dict(progress.get("attempts") or {})
    if objective_id not in attempts:
        attempts[objective_id] = {
            "objective_id": objective_id,
            "attempted_at": _utcnow_iso(),
            "count": 1,
            "note": "auto-recorded on human complete",
            "hints_unlocked": True,
        }
        progress["attempts"] = attempts
    save_progress(program_id, progress)
    return lab_status_payload(program_id)


def hints_for_objective(program_id: str, objective_id: str) -> dict[str, Any]:
    binding = load_lab_binding(program_id)
    if not binding:
        raise FileNotFoundError(
            f"program {program_id!r} is not an open lab"
        )
    lab = get_lab_def(str(binding["lab_id"]))
    obj = _objective_by_id(lab, objective_id)
    progress = load_progress(program_id)
    attempt = (progress.get("attempts") or {}).get(objective_id)
    unlocked = bool(isinstance(attempt, dict) and attempt.get("hints_unlocked"))
    hints = list(obj.get("hints") or [])
    return {
        "program_id": program_id,
        "lab_id": binding["lab_id"],
        "objective_id": objective_id,
        "title": obj.get("title"),
        "unlocked": unlocked,
        "hints": hints if unlocked else [],
        "hint_count": len(hints),
        "locked_message": (
            None
            if unlocked
            else (
                "Hints locked until you record an attempt "
                f"(sentinel lab attempt {program_id} {objective_id})."
            )
        ),
        "attempt": attempt if isinstance(attempt, dict) else None,
    }


def lab_status_payload(program_id: str) -> dict[str, Any]:
    root = program_dir(program_id)
    if not root.is_dir():
        raise FileNotFoundError(
            f"program {program_id!r} not found; run: sentinel lab open …"
        )
    binding = load_lab_binding(program_id)
    if not binding:
        raise FileNotFoundError(
            f"program {program_id!r} has no lab.json — not an open lab"
        )
    lab = get_lab_def(str(binding["lab_id"]))
    progress = load_progress(program_id)
    attempts = progress.get("attempts") or {}
    completed = progress.get("completed") or {}

    objectives_out: list[dict[str, Any]] = []
    for obj in lab.get("objectives") or []:
        oid = str(obj["id"])
        att = attempts.get(oid) if isinstance(attempts.get(oid), dict) else None
        comp = completed.get(oid) if isinstance(completed.get(oid), dict) else None
        unlocked = bool(att and att.get("hints_unlocked"))
        objectives_out.append(
            {
                "id": oid,
                "title": obj.get("title"),
                "category": obj.get("category"),
                "difficulty": obj.get("difficulty"),
                "suggested_packs": list(obj.get("suggested_packs") or []),
                "summary": obj.get("summary"),
                "attempted": att is not None,
                "hints_unlocked": unlocked,
                "hint_count": len(obj.get("hints") or []),
                "completed": comp is not None,
                "attempt": att,
                "complete_meta": comp,
                # Never include hint bodies here when locked — use hints endpoint
                "hints_preview": (
                    list(obj.get("hints") or []) if unlocked else []
                ),
            }
        )

    attempted_n = sum(1 for o in objectives_out if o["attempted"])
    unlocked_n = sum(1 for o in objectives_out if o["hints_unlocked"])
    completed_n = sum(1 for o in objectives_out if o["completed"])

    return {
        "program_id": program_id,
        "lab_id": binding["lab_id"],
        "name": binding.get("name") or lab["name"],
        "base_url": binding.get("base_url") or lab["default_base_url"],
        "hosts": binding.get("hosts") or lab.get("default_hosts"),
        "port": binding.get("port") or lab.get("default_port"),
        "opened_at": binding.get("opened_at"),
        "start_docs": lab["start_docs"],
        "start_docs_path": str(root / "LAB_START.md"),
        "objectives": objectives_out,
        "counts": {
            "objectives": len(objectives_out),
            "attempted": attempted_n,
            "hints_unlocked": unlocked_n,
            "completed": completed_n,
        },
        "disclaimer": lab["disclaimer"],
        "invent_findings": False,
        "auto_verified": False,
        "llm": False,
        "phase": "E1",
        "how_to_open": {
            "cli": f"sentinel lab open {binding['lab_id']} --program {program_id}",
            "ui": "Labs tab → select juice-shop → Open Lab",
            "api": "POST /api/labs/open {\"lab_id\":\"juice-shop\",\"program_id\":…}",
        },
    }


# Hours open / attempt totals before lab time-budget nudge (gentle).
LAB_TIME_BUDGET_HOURS = 2.0
LAB_TIME_BUDGET_ATTEMPT_TOTAL = 4


def _parse_iso_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (TypeError, ValueError):
        return None


def _lab_stage_name(counts: dict[str, Any], objectives: list[dict[str, Any]]) -> str:
    """
    Map open-lab progress → stage label.

    map      — no attempts yet (start app / recon)
    attempt  — some attempts, still locked objectives remaining
    hint     — all attempted objectives unlocked; no human completes yet
    complete — at least one human complete; may still have remaining
    """
    attempted = int(counts.get("attempted") or 0)
    completed = int(counts.get("completed") or 0)
    if completed > 0:
        return "complete"
    if attempted == 0:
        return "map"
    locked_remaining = sum(1 for o in objectives if not o.get("hints_unlocked"))
    if locked_remaining > 0:
        return "attempt"
    return "hint"


def generate_lab_coach_hints(program_id: str) -> list[dict[str, Any]]:
    """
    Coach hooks for an open lab — methodology only; never claims vulns exist.

    Phase E1 kinds: lab_stage (map|attempt|hint|complete), lab_fp_school,
    lab_time_budget — driven from lab_progress.json + binding opened_at.
    """
    binding = load_lab_binding(program_id)
    if not binding:
        return []
    try:
        status = lab_status_payload(program_id)
    except FileNotFoundError:
        return []

    hints: list[dict[str, Any]] = []
    counts = dict(status.get("counts") or {})
    objectives = list(status.get("objectives") or [])
    stage = _lab_stage_name(counts, objectives)

    stage_advice = {
        "map": (
            "Stage=map — no attempts recorded yet. Start Juice Shop on loopback "
            "(LAB_START.md), recon the SPA, then record an attempt on an objective "
            "to unlock hints. Do not invent FINDING events from curriculum titles."
        ),
        "attempt": (
            "Stage=attempt — you have recorded tries; some objective hints may still "
            "be locked. Record `sentinel lab attempt` (or Labs tab) per objective "
            "before reading the hint ladder. Attempt ≠ verified finding."
        ),
        "hint": (
            "Stage=hint — hints unlocked via attempts, but no human completes yet. "
            "Use methodology hints + gated packs on the lab base URL; mark complete "
            "yourself when you believe the curriculum objective is done (never auto)."
        ),
        "complete": (
            "Stage=complete — at least one objective has a human complete mark. "
            "Continue remaining objectives; confirm real FINDING events with a note "
            "before report wording. Still no auto-VERIFIED."
        ),
    }
    hints.append(
        {
            "id": f"lab-stage-{stage}",
            "kind": "lab_stage",
            "title": f"Lab stage — {stage} · {status.get('name')}",
            "body": (
                f"Program {program_id!r} bound to lab {status.get('lab_id')!r} "
                f"@ {status.get('base_url')}. "
                f"Progress: attempted={counts.get('attempted', 0)}/"
                f"{counts.get('objectives', 0)}, "
                f"hints_unlocked={counts.get('hints_unlocked', 0)}, "
                f"completed={counts.get('completed', 0)} (human mark only).\n"
                + stage_advice.get(stage, stage_advice["map"])
            ),
            "evidence_counts": {
                **counts,
                "lab_stage": stage,
                "lab_id": status.get("lab_id"),
            },
            "lab_stage": stage,
        }
    )

    locked = [o for o in objectives if not o.get("hints_unlocked")]
    if locked:
        sample = locked[0]
        hints.append(
            {
                "id": "lab-hint-locked",
                "kind": "lab_hint_gate",
                "title": "Lab hints locked until attempt",
                "body": (
                    f"{len(locked)} objective(s) still have locked hints. "
                    f"Example: {sample.get('id')} — {sample.get('title')}. "
                    f"Record an attempt (Labs tab or "
                    f"`sentinel lab attempt {program_id} {sample.get('id')}`) "
                    f"to unlock progressive hints. Attempt ≠ verified finding."
                ),
                "evidence_counts": {
                    "locked_objectives": len(locked),
                    "example_id": sample.get("id"),
                },
            }
        )
    else:
        hints.append(
            {
                "id": "lab-hints-all-unlocked",
                "kind": "lab_hint_gate",
                "title": "All lab hints unlocked",
                "body": (
                    "You unlocked hints for every Lab 1 objective via attempts. "
                    "Next: gated pack runs on the lab base URL, human confirm-finding, "
                    "then Reports export (E3 exit path). Still no auto-VERIFIED."
                ),
                "evidence_counts": dict(counts),
            }
        )

    unfinished = [o for o in objectives if not o.get("completed")]
    if unfinished:
        nxt = unfinished[0]
        packs = ", ".join(nxt.get("suggested_packs") or []) or "(recon / manual)"
        hints.append(
            {
                "id": "lab-next-objective",
                "kind": "lab_next",
                "title": f"Next lab objective — {nxt.get('id')}",
                "body": (
                    f"{nxt.get('title')} [{nxt.get('category')}]. "
                    f"Suggested packs (methodology only): {packs}. "
                    f"This is a curriculum pointer — not a claim the bug exists."
                ),
                "evidence_counts": {
                    "objective_id": nxt.get("id"),
                    "remaining": len(unfinished),
                },
            }
        )

    # --- lab_fp_school: attempts without complete → contextual FP tips ---
    stuck = [
        o for o in objectives if o.get("attempted") and not o.get("completed")
    ]
    if stuck:
        lines = [
            "Lab FP school (methodology only — not claims these bugs exist here):",
            "· Reflection in Juice Shop search ≠ XSS until you name a sink + context.",
            "· Hitting /administration as role A ≠ broken access control until you "
            "compare status/body across roles on the same object.",
            "· JWT decode ≠ weak-alg impact until jwt_session evidence is confirmed.",
            "· Open redirect candidate ≠ reportable until navigation follows your URL.",
            "· Curriculum titles are learning goals — never auto-emitted FINDING events.",
        ]
        samples: list[str] = []
        for o in stuck[:3]:
            cat = o.get("category") or "general"
            samples.append(f"{o.get('id')}[{cat}]")
            if cat == "xss":
                lines.append(
                    f"· On {o.get('id')}: treat search reflection as a sink hunt, "
                    f"not a verified XSS (see suggested xss_dom methodology)."
                )
            elif cat in ("access_control", "access"):
                lines.append(
                    f"· On {o.get('id')}: 403/200 alone is not BOLA — need role A/B "
                    f"object access evidence before confirm-finding."
                )
            elif cat == "auth":
                lines.append(
                    f"· On {o.get('id')}: capture a real lab token; do not invent "
                    f"JWTs in notes or reports."
                )
            elif cat == "redirect":
                lines.append(
                    f"· On {o.get('id')}: prove Location/client nav follows an "
                    f"attacker URL you control (lab-only) before impact language."
                )
            elif cat == "recon":
                lines.append(
                    f"· On {o.get('id')}: recon objectives have no FINDING claim — "
                    f"mark complete only when you personally found the surface."
                )
        lines.append(
            f"Stuck (attempted, not human-complete): {', '.join(samples)}. "
            f"Coach never invents extras."
        )
        hints.append(
            {
                "id": "lab-fp-school",
                "kind": "lab_fp_school",
                "title": "Lab FP school — Juice Shop context",
                "body": "\n".join(lines),
                "evidence_counts": {
                    "stuck_objectives": len(stuck),
                    "attempted": counts.get("attempted", 0),
                    "completed": counts.get("completed", 0),
                    "sample_ids": [o.get("id") for o in stuck[:5]],
                },
            }
        )

    # --- lab_time_budget: many attempts / long open without completes ---
    progress = load_progress(program_id)
    attempt_total = 0
    for att in (progress.get("attempts") or {}).values():
        if isinstance(att, dict):
            attempt_total += int(att.get("count") or 1)
        else:
            attempt_total += 1
    opened_at = binding.get("opened_at") or status.get("opened_at")
    opened_dt = _parse_iso_ts(opened_at)
    age_h = None
    if opened_dt is not None:
        age_h = round(
            (datetime.now(timezone.utc) - opened_dt).total_seconds() / 3600.0, 2
        )
    completed_n = int(counts.get("completed") or 0)
    many_attempts = (
        attempt_total >= LAB_TIME_BUDGET_ATTEMPT_TOTAL and completed_n == 0
    )
    long_open = (
        age_h is not None
        and float(age_h) >= float(LAB_TIME_BUDGET_HOURS)
        and completed_n == 0
        and int(counts.get("attempted") or 0) >= 1
    )
    if many_attempts or long_open:
        reasons = []
        if many_attempts:
            reasons.append(
                f"attempt_events={attempt_total} "
                f"(≥{LAB_TIME_BUDGET_ATTEMPT_TOTAL}) with 0 human completes"
            )
        if long_open:
            reasons.append(
                f"lab open ~{age_h}h "
                f"(≥{LAB_TIME_BUDGET_HOURS}h) with attempts but 0 completes"
            )
        hints.append(
            {
                "id": "lab-time-budget",
                "kind": "lab_time_budget",
                "title": "Lab time-budget — pause & reassess",
                "body": (
                    "Gentle reminder (not a fail): "
                    + "; ".join(reasons)
                    + ". "
                    "Reassess: unlock remaining hints, run one gated pack on "
                    f"{status.get('base_url')}, or mark a completed objective "
                    "yourself when the curriculum step is honestly done. "
                    "Do not grind endless attempts without a human complete mark. "
                    "Coach never auto-completes or invents findings."
                ),
                "evidence_counts": {
                    "attempt_total": attempt_total,
                    "lab_open_age_hours": age_h,
                    "lab_time_budget_hours": LAB_TIME_BUDGET_HOURS,
                    "lab_time_budget_attempt_total": LAB_TIME_BUDGET_ATTEMPT_TOTAL,
                    "completed": completed_n,
                    "attempted": counts.get("attempted", 0),
                    "opened_at": opened_at,
                },
            }
        )

    return hints



def open_lab_action(body: dict[str, Any]) -> dict[str, Any]:
    lab_id = str(body.get("lab_id") or "").strip()
    if not lab_id:
        raise ValueError("lab_id required")
    program_id = body.get("program_id")
    base_url = body.get("base_url")
    return open_lab(
        lab_id,
        program_id=str(program_id).strip() if program_id else None,
        base_url=str(base_url).strip() if base_url else None,
    )


def attempt_lab_action(program_id: str, body: dict[str, Any]) -> dict[str, Any]:
    oid = str(body.get("objective_id") or body.get("id") or "").strip()
    if not oid:
        raise ValueError("objective_id required")
    note = body.get("note")
    complete = bool(body.get("complete"))
    if complete:
        return mark_objective_complete(
            program_id, oid, note=str(note) if note else None
        )
    return record_attempt(program_id, oid, note=str(note) if note else None)


__all__ = [
    "JUICE_SHOP_DEFAULT_BASE",
    "JUICE_SHOP_START_DOCS",
    "LAB_TIME_BUDGET_ATTEMPT_TOTAL",
    "LAB_TIME_BUDGET_HOURS",
    "attempt_lab_action",
    "generate_lab_coach_hints",
    "get_lab_def",
    "hints_for_objective",
    "lab_catalog",
    "lab_status_payload",
    "labs_payload",
    "load_lab_binding",
    "mark_objective_complete",
    "open_lab",
    "open_lab_action",
    "record_attempt",
]
