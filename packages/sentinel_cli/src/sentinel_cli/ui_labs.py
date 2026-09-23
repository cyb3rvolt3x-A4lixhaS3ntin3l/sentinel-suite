"""Phase E3 — Open Lab curricula + Lab 1 tutorial → platform-shaped report exit.

Labs are curricula, not hunt packs. Never invent FINDING events or auto-VERIFIED.
Hints stay locked until the operator records an attempt for that objective.
Progress is versioned JSON (schema_version) under the program dir.
E3: hunter tutorial checklist + confirm-finding → Reports export for lab programs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel_core import create_program, program_dir, update_program_yml_fields

LAB_FILE = "lab.json"
PROGRESS_FILE = "lab_progress.json"
PROGRESS_SCHEMA_VERSION = 1

# Default Juice Shop bind (intentional vuln app — local docker only).
JUICE_SHOP_DEFAULT_BASE = "http://127.0.0.1:3000"
CRAPI_DEFAULT_BASE = "http://127.0.0.1:8888"
AUTH_SESSION_DEFAULT_BASE = "http://127.0.0.1:3000"

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

CRAPI_START_DOCS = """# Start OWASP crAPI (lab-only)

Default target: http://127.0.0.1:8888 (loopback web UI / API gateway).

**Conflict note:** Sentinel UI also defaults to `127.0.0.1:8888`. When both run,
start Sentinel UI on another loopback port, e.g. `sentinel ui --bind 127.0.0.1:8787`.

## Docker Compose (documented upstream)

Clone / follow OWASP crAPI deploy docs, then bind to loopback only. Example pattern:

```bash
# From an OWASP/crAPI checkout (lab machine only):
# docker compose -f deploy/docker/docker-compose.yml up -d
# Ensure published ports are 127.0.0.1:<host>:… — never 0.0.0.0 for lab defaults.
# Web/API often lands on http://127.0.0.1:8888
```

If you remap the web port (recommended when Sentinel UI uses 8888):

```bash
# Example remap — adjust to your compose file service name/ports:
# -p 127.0.0.1:8889:80   → then open lab with --base-url http://127.0.0.1:8889
```

```bash
sentinel lab open crapi --program lab-crapi
# or with remap:
sentinel lab open crapi --program lab-crapi --base-url http://127.0.0.1:8889
```

## Notes

- Lab-only intentional vulnerable API. No real/third-party targets.
- Curriculum objectives ≠ FINDING events. No auto-VERIFIED.
- Suggested packs are methodology pointers only (bola_idor_bfla, jwt_session, graphql, …).
"""

AUTH_SESSION_START_DOCS = """# Auth / session / role curriculum (lab-only)

Default practice target: http://127.0.0.1:3000 (reuse local Juice Shop or another
intentional loopback app you own). This lab teaches **session + role methodology**
using Sentinel Auth lab fixtures — it does **not** invent credentials.

## Role fixtures (required for pack methodology)

Under the opened program directory:

```text
roles/a.json
roles/b.json
```

Minimal fixture shape (lab-only; never paste production secrets):

```json
{
  "cookies": {},
  "headers": {},
  "bearer": null
}
```

Fill cookies / headers / bearer from a **local** login you performed yourself.
Auth tab → Auth lab shows vault metadata + redacted replay stub (no silent live).

## Optional: start Juice Shop as the practice app

```bash
docker run --rm -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

## Notes

- Compare anonymous vs role A vs role B on the **same** object path before any BOLA claim.
- Session/JWT objectives need a real lab token — never invent tokens in notes/reports.
- Pack runs still need --i-own-this; confirm-finding before report wording.
- Curriculum only — no auto-emitted FINDING events, no auto-VERIFIED.
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


def _crapi_objectives() -> list[dict[str, Any]]:
    """crAPI curriculum — API/BOLA/JWT/GraphQL methodology (not discovered bugs)."""
    return [
        {
            "id": "crapi-recon-api",
            "title": "Map crAPI surfaces (recon)",
            "category": "recon",
            "difficulty": "starters",
            "suggested_packs": [],
            "summary": (
                "Curriculum: inventory identity / community / workshop API routes on "
                "loopback crAPI. Recon only — not a vulnerability claim."
            ),
            "hints": _hint_ladder(
                "Start from the local web UI; note which API hosts/ports your compose "
                "exposes on 127.0.0.1 only.",
                "Enumerate documented identity, vehicle, and community endpoints from "
                "client traffic or OpenAPI-ish hints — stay on loopback.",
                "Record interesting object IDs you own in lab notes before any "
                "cross-user access attempts.",
            ),
        },
        {
            "id": "crapi-bola-vehicle",
            "title": "BOLA / IDOR — vehicle or order object practice",
            "category": "access_control",
            "difficulty": "intermediate",
            "suggested_packs": ["bola_idor_bfla"],
            "summary": (
                "Curriculum: practice object-level access with two lab roles against "
                "vehicle/order-style resources. Methodology only — never auto-VERIFIED."
            ),
            "hints": _hint_ladder(
                "Create or capture two lab identities (roles/a.json + roles/b.json) "
                "from local crAPI sign-up/login — never invent tokens.",
                "Request the same object id as role A and role B; compare status and "
                "body. One 200 alone is not BOLA.",
                "Use bola_idor_bfla methodology with --i-own-this on the lab base URL; "
                "confirm-finding with a human note before report language.",
            ),
        },
        {
            "id": "crapi-jwt-identity",
            "title": "JWT / identity token practice",
            "category": "auth",
            "difficulty": "intermediate",
            "suggested_packs": ["jwt_session", "ato_oauth_oidc"],
            "summary": (
                "Curriculum: inspect identity tokens issued by local crAPI. "
                "Weak-alg / claim misuse needs evidence — never invent JWTs."
            ),
            "hints": _hint_ladder(
                "Log in locally and capture a real Authorization bearer into the "
                "Auth lab vault (display is redacted).",
                "Decode header/payload offline; note alg, sub/role, and expiry. "
                "Do not claim impact from decode alone.",
                "jwt_session pack methodology against loopback — findings stay "
                "needs_human until confirm-finding.",
            ),
        },
        {
            "id": "crapi-graphql",
            "title": "GraphQL enumeration / authz practice",
            "category": "graphql",
            "difficulty": "intermediate",
            "suggested_packs": ["graphql"],
            "summary": (
                "Curriculum: practice GraphQL discovery and authz checks on local "
                "crAPI GraphQL (if exposed). Introspection ≠ vuln by itself."
            ),
            "hints": _hint_ladder(
                "Locate a GraphQL endpoint from local client traffic or docs — "
                "loopback only.",
                "FP school: introspection enabled is often informative, not "
                "automatically a reportable finding without impact.",
                "graphql pack methodology with optional --role-a; human confirm "
                "before platform wording.",
            ),
        },
        {
            "id": "crapi-business-logic",
            "title": "Business-logic / workflow practice",
            "category": "business_logic",
            "difficulty": "intermediate",
            "suggested_packs": ["business_logic", "race_toctou"],
            "summary": (
                "Curriculum: exercise multi-step workshop/community flows for "
                "state / price / quantity style mistakes — methodology only."
            ),
            "hints": _hint_ladder(
                "Map a multi-step flow (request → approve → pay / contact) on "
                "loopback before mutating anything.",
                "Change one parameter at a time; compare authorized vs "
                "unauthorized role outcomes.",
                "business_logic / race_toctou packs are methodology helpers — "
                "still need --i-own-this / lab flags and human confirm.",
            ),
        },
    ]


def _auth_session_objectives() -> list[dict[str, Any]]:
    """Auth/session/role curriculum — fixtures + cross-role methodology."""
    return [
        {
            "id": "as-role-fixtures",
            "title": "Place Auth lab role fixtures (A/B)",
            "category": "recon",
            "difficulty": "starters",
            "suggested_packs": [],
            "summary": (
                "Curriculum: create roles/a.json and roles/b.json under the program "
                "from a local login you performed. Never invent production secrets."
            ),
            "hints": _hint_ladder(
                "Open the program dir; create roles/ if missing. Auth lab never "
                "fabricates credentials.",
                "After local login, copy cookies / bearer into a.json (role A). "
                "Repeat with a second lab user for b.json.",
                "Check Auth tab → Auth lab: usable=true, redacted replay stub — "
                "still no silent live requests.",
            ),
        },
        {
            "id": "as-anon-vs-role",
            "title": "Anonymous vs role A on the same object",
            "category": "access_control",
            "difficulty": "starters",
            "suggested_packs": ["bola_idor_bfla"],
            "summary": (
                "Curriculum: compare unauthenticated vs role-A responses for one "
                "object path on the loopback practice app."
            ),
            "hints": _hint_ladder(
                "Pick one object URL on 127.0.0.1. Request once with no session, "
                "once with role A headers/cookies.",
                "Note status + body differences. 401/403 vs 200 is a clue, not "
                "yet a proven broken-access finding.",
                "Record an evidence note; optional bola_idor_bfla methodology "
                "still needs_human confirmation.",
            ),
        },
        {
            "id": "as-role-a-vs-b",
            "title": "Role A vs role B object access (BOLA practice)",
            "category": "access_control",
            "difficulty": "intermediate",
            "suggested_packs": ["bola_idor_bfla"],
            "summary": (
                "Curriculum: same object id with two lab roles. Cross-user read/"
                "write evidence required before any BOLA claim."
            ),
            "hints": _hint_ladder(
                "Both fixtures must be usable (Auth lab). Swap only the auth "
                "material — keep path/query identical.",
                "If role B can read/modify role A's object, capture both "
                "responses as evidence (lab-only).",
                "Run bola_idor_bfla with --role-a/--role-b and --i-own-this; "
                "confirm-finding before report language.",
            ),
        },
        {
            "id": "as-session-cookie",
            "title": "Session cookie / flag methodology",
            "category": "auth",
            "difficulty": "starters",
            "suggested_packs": ["jwt_session"],
            "summary": (
                "Curriculum: inspect lab session cookies (Secure/HttpOnly/SameSite "
                "flags) from a local login — informative vs impact needs a story."
            ),
            "hints": _hint_ladder(
                "Capture Set-Cookie from local login (DevTools / Auth vault). "
                "Do not invent cookie values in reports.",
                "Check flags and scope. Missing flags alone are often "
                "informational without a theft/impact chain.",
                "Document methodology; use jwt_session only if the app issues "
                "JWTs — still human confirm.",
            ),
        },
        {
            "id": "as-jwt-vs-session",
            "title": "JWT vs cookie session practice",
            "category": "auth",
            "difficulty": "intermediate",
            "suggested_packs": ["jwt_session", "ato_oauth_oidc"],
            "summary": (
                "Curriculum: identify whether the practice app uses JWT bearer, "
                "cookie session, or both — then apply the matching methodology."
            ),
            "hints": _hint_ladder(
                "From Auth lab vault: bearer present? cookie session present? "
                "Both? Record what you actually captured.",
                "Decode JWTs offline only. Cookie sessions: focus on fixation / "
                "logout / concurrent session methodology notes.",
                "Suggested packs are pointers — gated runs need --i-own-this; "
                "never auto-VERIFIED.",
            ),
        },
    ]


def lab_catalog() -> list[dict[str, Any]]:
    """Static lab catalog (E2: Juice Shop + crAPI + auth-session)."""
    return [
        {
            "lab_id": "juice-shop",
            "name": "OWASP Juice Shop — Lab 1",
            "version": "e2",
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
        },
        {
            "lab_id": "crapi",
            "name": "OWASP crAPI — API / BOLA lab",
            "version": "e2",
            "kind": "intentional_vuln_app",
            "default_program_id": "lab-crapi",
            "default_base_url": CRAPI_DEFAULT_BASE,
            "default_hosts": ["127.0.0.1", "localhost"],
            "default_port": 8888,
            "objective_count": len(_crapi_objectives()),
            "objectives": _crapi_objectives(),
            "start_docs": CRAPI_START_DOCS,
            "disclaimer": (
                "Curriculum lab (crAPI). Objectives are learning goals, not "
                "auto-emitted FINDING events. Loopback defaults only. Remap port "
                "if Sentinel UI already uses :8888."
            ),
        },
        {
            "lab_id": "auth-session",
            "name": "Auth / session / role curriculum",
            "version": "e2",
            "kind": "auth_session_curriculum",
            "default_program_id": "lab-auth-session",
            "default_base_url": AUTH_SESSION_DEFAULT_BASE,
            "default_hosts": ["127.0.0.1", "localhost"],
            "default_port": 3000,
            "objective_count": len(_auth_session_objectives()),
            "objectives": _auth_session_objectives(),
            "start_docs": AUTH_SESSION_START_DOCS,
            "disclaimer": (
                "Curriculum lab (auth/session/roles). Uses operator-supplied "
                "roles/*.json fixtures + loopback practice app. Never invents "
                "credentials or FINDING events."
            ),
        },
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
                "default_port": L.get("default_port"),
                "objective_count": L["objective_count"],
                "disclaimer": L["disclaimer"],
                "start_docs": L["start_docs"],
            }
            for L in labs
        ],
        "count": len(labs),
        "phase": "E3",
        "progress_schema_version": PROGRESS_SCHEMA_VERSION,
        "note": (
            "Open Lab creates/binds a program with lab.json + versioned "
            "lab_progress.json + loopback scope. Does not start Docker; see "
            "start_docs on lab detail / open result. Shared attempt/hint UX "
            "works for all catalog labs. E3: Lab 1 tutorial → confirm-finding "
            "→ platform-shaped report.md exit (sentinel lab tutorial / report)."
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


def empty_progress(
    *,
    lab_id: str | None = None,
    program_id: str | None = None,
) -> dict[str, Any]:
    """Canonical empty progress document (schema_version current)."""
    return {
        "schema_version": PROGRESS_SCHEMA_VERSION,
        "lab_id": lab_id,
        "program_id": program_id,
        "attempts": {},
        "completed": {},
        "report_exports": [],
        "updated_at": None,
    }


def migrate_progress(
    data: Any,
    *,
    lab_id: str | None = None,
    program_id: str | None = None,
) -> dict[str, Any]:
    """
    Normalize E0/E1 progress (no schema_version) → current schema.

    Never drops attempts/completed. Never invents completes.
    """
    if not isinstance(data, dict):
        return empty_progress(lab_id=lab_id, program_id=program_id)
    attempts = data.get("attempts") if isinstance(data.get("attempts"), dict) else {}
    completed = data.get("completed") if isinstance(data.get("completed"), dict) else {}
    # scrub non-dict entries
    clean_attempts: dict[str, Any] = {}
    for k, v in attempts.items():
        if isinstance(v, dict):
            clean_attempts[str(k)] = v
    clean_completed: dict[str, Any] = {}
    for k, v in completed.items():
        if isinstance(v, dict):
            clean_completed[str(k)] = v
    exports_raw = data.get("report_exports")
    clean_exports: list[Any] = []
    if isinstance(exports_raw, list):
        for item in exports_raw:
            if isinstance(item, dict):
                clean_exports.append(item)
    return {
        "schema_version": PROGRESS_SCHEMA_VERSION,
        "lab_id": data.get("lab_id") or lab_id,
        "program_id": data.get("program_id") or program_id,
        "attempts": clean_attempts,
        "completed": clean_completed,
        "report_exports": clean_exports,
        "updated_at": data.get("updated_at"),
    }


def load_progress(program_id: str) -> dict[str, Any]:
    path = _progress_path(program_id)
    binding = load_lab_binding(program_id)
    lab_id = str(binding["lab_id"]) if binding and binding.get("lab_id") else None
    if not path.is_file():
        return empty_progress(lab_id=lab_id, program_id=program_id)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_progress(lab_id=lab_id, program_id=program_id)
    migrated = migrate_progress(data, lab_id=lab_id, program_id=program_id)
    # Persist migration when file lacked schema_version (stable upgrade, no data loss)
    if not isinstance(data, dict) or data.get("schema_version") != PROGRESS_SCHEMA_VERSION:
        try:
            save_progress(program_id, migrated)
        except FileNotFoundError:
            pass
    return migrated


def save_progress(program_id: str, progress: dict[str, Any]) -> None:
    root = program_dir(program_id)
    if not root.is_dir():
        raise FileNotFoundError(
            f"program {program_id!r} not found; open a lab first"
        )
    binding = load_lab_binding(program_id)
    lab_id = None
    if binding and binding.get("lab_id"):
        lab_id = str(binding["lab_id"])
    elif progress.get("lab_id"):
        lab_id = str(progress["lab_id"])
    normalized = migrate_progress(
        progress, lab_id=lab_id, program_id=program_id
    )
    normalized["updated_at"] = _utcnow_iso()
    path = _progress_path(program_id)
    path.write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


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

    Writes lab.json + versioned lab_progress.json + loopback scope. Does not
    start Docker and does not emit FINDING events.
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
        "phase": "E3",
        "progress_schema_version": PROGRESS_SCHEMA_VERSION,
        "invent_findings": False,
        "auto_verified": False,
    }
    (_lab_path(pid)).write_text(
        json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not _progress_path(pid).is_file():
        save_progress(
            pid,
            empty_progress(lab_id=lab["lab_id"], program_id=pid),
        )
    else:
        # Re-open: migrate existing progress in place; keep attempts/completed
        load_progress(pid)

    (root / "LAB_START.md").write_text(lab["start_docs"], encoding="utf-8")

    # auth-session: ensure roles/ dir exists with README pointer (no fake creds)
    if lab["lab_id"] == "auth-session":
        roles_dir = root / "roles"
        roles_dir.mkdir(exist_ok=True)
        readme = roles_dir / "README.md"
        if not readme.is_file():
            readme.write_text(
                "# Lab role fixtures\n\n"
                "Place `a.json` and `b.json` from a **local** login.\n"
                "Never commit production secrets. Auth lab never fabricates credentials.\n",
                encoding="utf-8",
            )

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
    note_text = (note or "").strip() or None
    notes = list(prev.get("notes") or []) if isinstance(prev.get("notes"), list) else []
    if note_text:
        notes.append({"at": _utcnow_iso(), "body": note_text})
    entry = {
        "objective_id": objective_id,
        "attempted_at": _utcnow_iso(),
        "count": count,
        "note": note_text or prev.get("note"),
        "notes": notes[-20:],  # cap history
        "hints_unlocked": True,
    }
    attempts[objective_id] = entry
    progress["attempts"] = attempts
    progress["lab_id"] = binding["lab_id"]
    progress["program_id"] = program_id
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
            "notes": [],
            "hints_unlocked": True,
        }
        progress["attempts"] = attempts
    progress["lab_id"] = binding["lab_id"]
    progress["program_id"] = program_id
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
        "progress_schema_version": progress.get("schema_version"),
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
    lab_id = binding["lab_id"]

    payload = {
        "program_id": program_id,
        "lab_id": lab_id,
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
        "progress": {
            "schema_version": progress.get("schema_version"),
            "updated_at": progress.get("updated_at"),
            "lab_id": progress.get("lab_id") or lab_id,
            "program_id": progress.get("program_id") or program_id,
            "report_exports": list(progress.get("report_exports") or []),
        },
        "progress_schema_version": PROGRESS_SCHEMA_VERSION,
        "disclaimer": lab["disclaimer"],
        "invent_findings": False,
        "auto_verified": False,
        "llm": False,
        "phase": "E3",
        "how_to_open": {
            "cli": f"sentinel lab open {lab_id} --program {program_id}",
            "ui": f"Labs tab → select {lab_id} → Open Lab",
            "api": (
                f'POST /api/labs/open {{"lab_id":"{lab_id}",'
                f'"program_id":"{program_id}"}}'
            ),
        },
        "how_to_exit": {
            "cli": (
                f"sentinel lab tutorial {program_id} && "
                f"sentinel hunt confirm-finding {program_id} <id> "
                f"--status confirmed --note '…' && "
                f"sentinel lab report {program_id} -o ./report.md"
            ),
            "ui": (
                "Labs → attempt/hints/complete → Confirm tab → "
                "Labs tutorial Export report.md (or Reports tab)"
            ),
        },
    }
    # Attach tutorial checklist (E3) without re-entering status recursion
    payload["tutorial"] = tutorial_checklist(
        program_id, status_snapshot=payload
    )
    return payload


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

    Phase E1/E2 kinds: lab_stage (map|attempt|hint|complete), lab_fp_school,
    lab_time_budget — driven from lab_progress.json + binding opened_at.
    Works for any lab-bound program (juice-shop / crapi / auth-session).
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
    lab_name = status.get("name") or status.get("lab_id") or "lab"
    lab_id = status.get("lab_id")

    stage_advice = {
        "map": (
            f"Stage=map — no attempts recorded yet. Start the lab app on loopback "
            f"(LAB_START.md for {lab_id}), recon, then record an attempt on an "
            f"objective to unlock hints. Do not invent FINDING events from "
            f"curriculum titles."
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
            "Next Lab 1 exit: confirm real FINDING events with a note, then "
            "`sentinel lab report` / Labs Export report.md (E3). Still no auto-VERIFIED."
        ),
    }
    hints.append(
        {
            "id": f"lab-stage-{stage}",
            "kind": "lab_stage",
            "title": f"Lab stage — {stage} · {lab_name}",
            "body": (
                f"Program {program_id!r} bound to lab {lab_id!r} "
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
                "lab_id": lab_id,
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
                    f"You unlocked hints for every {lab_name} objective via attempts. "
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
            f"Lab FP school for {lab_name} (methodology only — not claims these bugs exist here):",
            "· Reflection / echo in UI ≠ XSS until you name a sink + context.",
            "· Hitting an admin or object route as role A ≠ broken access control until you "
            "compare status/body across roles on the same object.",
            "· JWT decode ≠ weak-alg impact until jwt_session evidence is confirmed.",
            "· Open redirect candidate ≠ reportable until navigation follows your URL.",
            "· GraphQL introspection ≠ vuln by itself without an authz/impact story.",
            "· Curriculum titles are learning goals — never auto-emitted FINDING events.",
        ]
        samples: list[str] = []
        for o in stuck[:3]:
            cat = o.get("category") or "general"
            samples.append(f"{o.get('id')}[{cat}]")
            if cat == "xss":
                lines.append(
                    f"· On {o.get('id')}: treat reflection as a sink hunt, "
                    f"not a verified XSS (see suggested xss_dom methodology)."
                )
            elif cat in ("access_control", "access"):
                lines.append(
                    f"· On {o.get('id')}: 403/200 alone is not BOLA — need role A/B "
                    f"object access evidence before confirm-finding."
                )
            elif cat == "auth":
                lines.append(
                    f"· On {o.get('id')}: capture a real lab token/cookie; do not invent "
                    f"JWTs or sessions in notes or reports."
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
            elif cat == "graphql":
                lines.append(
                    f"· On {o.get('id')}: introspection/listing is often informative; "
                    f"pair with authz checks before report wording."
                )
            elif cat == "business_logic":
                lines.append(
                    f"· On {o.get('id')}: one odd price/qty response ≠ proven logic bug — "
                    f"need a reproducible multi-step story."
                )
        lines.append(
            f"Stuck (attempted, not human-complete): {', '.join(samples)}. "
            f"Coach never invents extras."
        )
        hints.append(
            {
                "id": "lab-fp-school",
                "kind": "lab_fp_school",
                "title": f"Lab FP school — {lab_name}",
                "body": "\n".join(lines),
                "evidence_counts": {
                    "stuck_objectives": len(stuck),
                    "attempted": counts.get("attempted", 0),
                    "completed": counts.get("completed", 0),
                    "sample_ids": [o.get("id") for o in stuck[:5]],
                    "lab_id": lab_id,
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
                    "lab_id": lab_id,
                },
            }
        )

    return hints


# --- Phase E3: hunter tutorial "done" checklist + lab report exit -------------

TUTORIAL_STEPS: tuple[dict[str, str], ...] = (
    {
        "id": "open_lab",
        "title": "Open Lab",
        "detail": "Bind a program via sentinel lab open / Labs → Open Lab",
    },
    {
        "id": "attempt",
        "title": "Attempt ≥1 objective",
        "detail": "Record an attempt (unlocks hints) — attempt ≠ verified finding",
    },
    {
        "id": "hints",
        "title": "Unlock hints",
        "detail": "View hint ladder after attempt (Labs / sentinel lab hints)",
    },
    {
        "id": "complete",
        "title": "Human complete ≥1 objective",
        "detail": "Mark complete yourself — never auto from pack output",
    },
    {
        "id": "confirm_finding",
        "title": "confirm-finding ≥1 FINDING",
        "detail": (
            "Human confirm a real graph FINDING with a note "
            "(sentinel hunt confirm-finding / Confirm tab) — never auto-VERIFIED"
        ),
    },
    {
        "id": "export_report",
        "title": "Export report.md",
        "detail": (
            "Platform-shaped markdown via sentinel lab report / Labs Export / Reports"
        ),
    },
)


def _confirmed_finding_rows(program_id: str) -> list[dict[str, Any]]:
    """Confirmed/verified FINDING rows only (human gate). Never invents."""
    from gungnir.packs.confirm import list_findings

    confirmed: list[dict[str, Any]] = []
    for row in list_findings(program_id, status="all"):
        ver = str(row.get("verification") or "").lower()
        if ver in ("confirmed", "verified") or row.get("human_confirmed"):
            confirmed.append(row)
    return confirmed


def tutorial_checklist(
    program_id: str,
    *,
    status_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Hunter tutorial "done" checklist for an open lab (Lab 1 exit story).

    Done criteria (all must be true):
      open → attempt → hints unlocked → human complete ≥1 →
      confirm-finding ≥1 → report.md export recorded.
    """
    if status_snapshot is None:
        binding = load_lab_binding(program_id)
        if not binding:
            raise FileNotFoundError(
                f"program {program_id!r} is not an open lab"
            )
        lab = get_lab_def(str(binding["lab_id"]))
        progress = load_progress(program_id)
        attempts = progress.get("attempts") or {}
        completed = progress.get("completed") or {}
        objectives = list(lab.get("objectives") or [])
        attempted_n = sum(1 for o in objectives if str(o["id"]) in attempts)
        unlocked_n = sum(
            1
            for o in objectives
            if isinstance(attempts.get(str(o["id"])), dict)
            and attempts[str(o["id"])].get("hints_unlocked")
        )
        completed_n = sum(1 for o in objectives if str(o["id"]) in completed)
        exports = list(progress.get("report_exports") or [])
        lab_id = binding["lab_id"]
        name = binding.get("name") or lab["name"]
    else:
        counts = dict(status_snapshot.get("counts") or {})
        attempted_n = int(counts.get("attempted") or 0)
        unlocked_n = int(counts.get("hints_unlocked") or 0)
        completed_n = int(counts.get("completed") or 0)
        prog = dict(status_snapshot.get("progress") or {})
        exports = list(prog.get("report_exports") or [])
        if not exports:
            exports = list(load_progress(program_id).get("report_exports") or [])
        lab_id = status_snapshot.get("lab_id")
        name = status_snapshot.get("name") or lab_id

    confirmed_rows = _confirmed_finding_rows(program_id)
    confirmed_n = len(confirmed_rows)
    exported_n = len(exports)

    done_map = {
        "open_lab": True,
        "attempt": attempted_n >= 1,
        "hints": unlocked_n >= 1,
        "complete": completed_n >= 1,
        "confirm_finding": confirmed_n >= 1,
        "export_report": exported_n >= 1,
    }

    steps_out: list[dict[str, Any]] = []
    for step in TUTORIAL_STEPS:
        sid = step["id"]
        steps_out.append({**step, "done": bool(done_map.get(sid))})

    all_done = all(s["done"] for s in steps_out)
    next_step = next((s for s in steps_out if not s["done"]), None)

    return {
        "program_id": program_id,
        "lab_id": lab_id,
        "name": name,
        "lab1_exit": lab_id == "juice-shop",
        "steps": steps_out,
        "done_count": sum(1 for s in steps_out if s["done"]),
        "total": len(steps_out),
        "complete": all_done,
        "next_step": next_step,
        "counts": {
            "attempted": attempted_n,
            "hints_unlocked": unlocked_n,
            "completed": completed_n,
            "confirmed_findings": confirmed_n,
            "report_exports": exported_n,
        },
        "confirmed_finding_ids": [r.get("id") for r in confirmed_rows],
        "report_exports": exports,
        "invent_findings": False,
        "auto_verified": False,
        "llm": False,
        "phase": "E3",
        "story": (
            "Open Lab → attempt → hints → human complete ≥1 objective → "
            "confirm-finding (human note) → export report.md. "
            "Curriculum titles are learning goals, not FINDING events."
        ),
        "cli": {
            "tutorial": f"sentinel lab tutorial {program_id}",
            "confirm": (
                f"sentinel hunt confirm-finding {program_id} <finding-id> "
                f"--status confirmed --note 'reproduced on lab'"
            ),
            "report": f"sentinel lab report {program_id} -o ./report.md",
        },
        "ui": {
            "labs": "Labs tab — Open / Attempt / Hints / Complete + Tutorial card",
            "confirm": "Confirm tab — submit confirm-finding with note",
            "report": "Labs → Export report.md (or Reports tab download)",
        },
    }


def _render_curriculum_section(status: dict[str, Any]) -> str:
    """Honest curriculum progress block — never claims vulns exist."""
    lines = [
        "## Curriculum progress (not findings)",
        "",
        (
            "_Learning objectives only. Titles below are curriculum pointers — "
            "they are **not** auto-emitted FINDING events and do **not** imply "
            "a verified vulnerability._"
        ),
        "",
        f"- Lab: `{status.get('lab_id')}` ({status.get('name')})",
        f"- Base URL: `{status.get('base_url')}`",
        (
            f"- Progress: attempted={status.get('counts', {}).get('attempted', 0)}/"
            f"{status.get('counts', {}).get('objectives', 0)}; "
            f"hints_unlocked={status.get('counts', {}).get('hints_unlocked', 0)}; "
            f"completed={status.get('counts', {}).get('completed', 0)} "
            f"(human mark only)"
        ),
        "",
        "| Objective | Category | Attempted | Hints | Human complete |",
        "| --- | --- | --- | --- | --- |",
    ]
    for o in status.get("objectives") or []:
        lines.append(
            f"| `{o.get('id')}` — {o.get('title') or ''} | "
            f"{o.get('category') or ''} | "
            f"{'yes' if o.get('attempted') else 'no'} | "
            f"{'yes' if o.get('hints_unlocked') else 'locked'} | "
            f"{'yes' if o.get('completed') else 'no'} |"
        )
    lines.append("")
    return "\n".join(lines)


def _render_tutorial_section(tutorial: dict[str, Any]) -> str:
    lines = [
        "## Hunter tutorial checklist (Lab 1 exit)",
        "",
        f"Complete: **{'YES' if tutorial.get('complete') else 'NO'}** "
        f"({tutorial.get('done_count')}/{tutorial.get('total')})",
        "",
    ]
    for s in tutorial.get("steps") or []:
        mark = "[x]" if s.get("done") else "[ ]"
        lines.append(f"- {mark} **{s.get('title')}** — {s.get('detail')}")
    lines.append("")
    lines.append(
        "_Fences: human confirm only; never auto-VERIFIED; never invent findings; "
        "report findings come only from the graph after confirm-finding._"
    )
    lines.append("")
    return "\n".join(lines)


def render_lab_report_markdown(
    program_id: str,
    *,
    confirmed_only: bool = True,
) -> str:
    """
    Platform-shaped lab exit report: tutorial + curriculum + findings.

    Findings section reuses Phase C graph evidence only.
    When ``confirmed_only``, unconfirmed FINDING events are omitted.
    """
    from gungnir.packs.report import collect_pack_findings

    status = lab_status_payload(program_id)
    tutorial = status.get("tutorial") or tutorial_checklist(
        program_id, status_snapshot=status
    )

    parts: list[str] = [
        f"# Lab exit report — `{program_id}`",
        "",
        f"Lab: `{status.get('lab_id')}` · phase E3 · platform-shaped skeleton",
        "",
        (
            "This report is the **suite story exit** for Open Lab "
            "(confirm-finding → Reports). Steps/Impact come from stored "
            "evidence + checklist only — **no LLM invent**."
        ),
        "",
        f"- invent_findings: `{False}`",
        f"- auto_verified: `{False}`",
        f"- llm: `{False}`",
        "",
        "---",
        "",
        _render_tutorial_section(tutorial),
        "---",
        "",
        _render_curriculum_section(status),
        "---",
        "",
        "## Confirmed findings (graph)",
        "",
    ]

    rows = collect_pack_findings(program_id, pack_id=None)
    if confirmed_only:
        filtered = []
        for row in rows:
            finding = row["finding"]
            payload = getattr(finding, "payload", None) or {}
            ver = str(
                payload.get("verification")
                or payload.get("verification_status")
                or "unverified"
            ).lower()
            if ver in ("confirmed", "verified") or payload.get("human_confirmed"):
                filtered.append(row)
        rows = filtered

    if not rows:
        parts.append(
            "_No confirmed FINDING events yet. Run a gated pack on the lab "
            "base URL (fixtures / ownership flags), then "
            f"`sentinel hunt confirm-finding {program_id} <id> "
            "--status confirmed --note '…'`, then re-export._"
        )
        parts.append("")
        if not confirmed_only:
            parts.append(
                "_Tip: use `--all-findings` to include needs_human rows "
                "(still not invented)._"
            )
            parts.append("")
    else:
        label = "confirmed only" if confirmed_only else "all graph findings"
        parts.append(f"Findings included: **{len(rows)}** ({label})")
        parts.append("")
        for i, row in enumerate(rows):
            parts.append(row["markdown"])
            if i < len(rows) - 1:
                parts.append("---")
                parts.append("")

    parts.extend(
        [
            "---",
            "",
            (
                "_Remediation / Impact narrative placeholders — fill for real "
                "platform submission. Lab curriculum complete ≠ bug bounty claim._"
            ),
            "",
        ]
    )
    return "\n".join(parts)


def export_lab_report(
    program_id: str,
    *,
    output: str | Path | None = None,
    confirmed_only: bool = True,
) -> dict[str, Any]:
    """
    Export lab platform-shaped report.md and record tutorial export step.

    Reuses D1/Phase C report skeleton for findings; curriculum + tutorial
    sections are honestly labeled (not FINDING invent).
    """
    binding = load_lab_binding(program_id)
    if not binding:
        raise FileNotFoundError(
            f"program {program_id!r} is not an open lab; "
            f"run: sentinel lab open juice-shop --program {program_id}"
        )

    md = render_lab_report_markdown(program_id, confirmed_only=confirmed_only)
    if output is not None:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(md, encoding="utf-8")
        written = str(path.resolve())
    else:
        path = program_dir(program_id) / "report.md"
        path.write_text(md, encoding="utf-8")
        written = str(path.resolve())

    progress = load_progress(program_id)
    exports = list(progress.get("report_exports") or [])
    exports.append(
        {
            "at": _utcnow_iso(),
            "path": written,
            "confirmed_only": bool(confirmed_only),
            "source": "lab_report",
        }
    )
    progress["report_exports"] = exports
    progress["lab_id"] = binding.get("lab_id")
    progress["program_id"] = program_id
    save_progress(program_id, progress)

    tutorial = tutorial_checklist(program_id)
    confirmed_n = int((tutorial.get("counts") or {}).get("confirmed_findings") or 0)

    return {
        "ok": True,
        "program_id": program_id,
        "lab_id": binding.get("lab_id"),
        "output": written,
        "confirmed_only": bool(confirmed_only),
        "confirmed_findings": confirmed_n,
        "tutorial_complete": bool(tutorial.get("complete")),
        "tutorial": tutorial,
        "markdown": md,
        "invent_findings": False,
        "auto_verified": False,
        "phase": "E3",
    }


def export_lab_report_action(
    program_id: str, body: dict[str, Any] | None = None
) -> dict[str, Any]:
    body = body or {}
    output = body.get("output")
    confirmed_only = body.get("confirmed_only")
    if confirmed_only is None:
        confirmed_only = not bool(body.get("all_findings"))
    return export_lab_report(
        program_id,
        output=str(output) if output else None,
        confirmed_only=bool(confirmed_only),
    )


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
    "AUTH_SESSION_DEFAULT_BASE",
    "AUTH_SESSION_START_DOCS",
    "CRAPI_DEFAULT_BASE",
    "CRAPI_START_DOCS",
    "JUICE_SHOP_DEFAULT_BASE",
    "JUICE_SHOP_START_DOCS",
    "LAB_TIME_BUDGET_ATTEMPT_TOTAL",
    "LAB_TIME_BUDGET_HOURS",
    "PROGRESS_SCHEMA_VERSION",
    "TUTORIAL_STEPS",
    "attempt_lab_action",
    "empty_progress",
    "export_lab_report",
    "export_lab_report_action",
    "generate_lab_coach_hints",
    "get_lab_def",
    "hints_for_objective",
    "lab_catalog",
    "lab_status_payload",
    "labs_payload",
    "load_lab_binding",
    "load_progress",
    "mark_objective_complete",
    "migrate_progress",
    "open_lab",
    "open_lab_action",
    "record_attempt",
    "render_lab_report_markdown",
    "save_progress",
    "tutorial_checklist",
]
