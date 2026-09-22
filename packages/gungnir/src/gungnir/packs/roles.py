"""Role session fixtures — lab JSON under program dir (roles/a.json, roles/b.json).

Format (lab fixtures only; pack never steals credentials)::

    {
      "cookies": {"session": "..."},
      "headers": {"X-Custom": "..."},
      "bearer": "optional-token"
    }

At least one of cookies / headers / bearer should be present for a usable Role A.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel_core import program_dir


class RoleSessionError(Exception):
    """Missing or unusable role session for a hunt pack."""


@dataclass
class RoleSession:
    """In-memory role session from a lab fixture file."""

    role: str
    path: Path
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    bearer: str | None = None

    def as_request_headers(self) -> dict[str, str]:
        """Merge headers + optional Authorization + Cookie for scoped requests."""
        out = dict(self.headers)
        if self.bearer:
            out.setdefault("Authorization", f"Bearer {self.bearer}")
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            if "Cookie" in out and out["Cookie"]:
                out["Cookie"] = out["Cookie"].rstrip("; ") + "; " + cookie_str
            else:
                out["Cookie"] = cookie_str
        return out

    def is_usable(self) -> bool:
        return bool(self.cookies or self.headers or self.bearer)


def role_session_path(program_id: str, role: str, home: Path | None = None) -> Path:
    """Path to roles/<role>.json under the program directory."""
    letter = role.strip().lower()
    if letter not in ("a", "b", "role_a", "role_b"):
        raise RoleSessionError(f"unknown role label: {role!r} (expected a|b)")
    if letter.startswith("role_"):
        letter = letter[-1]
    return program_dir(program_id, home) / "roles" / f"{letter}.json"


def load_role_session(
    program_id: str,
    role: str = "a",
    *,
    home: Path | None = None,
    path: str | Path | None = None,
) -> RoleSession:
    """
    Load a role session JSON fixture. Does not network; does not steal creds.

    Raises RoleSessionError if file missing or empty of auth material.
    """
    p = Path(path) if path else role_session_path(program_id, role, home)
    if not p.is_file():
        raise RoleSessionError(
            f"Role {role.upper()} session not found at {p}. "
            f"Create a lab fixture JSON with cookies|headers|bearer "
            f"(see packages/gungnir/README.md). "
            f"OAuth/ATO packs fail closed without Role A"
            f"{' (and Role B)' if role.lower().endswith('b') or role.lower() == 'b' else ''}."
        )
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RoleSessionError(f"invalid role session JSON at {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise RoleSessionError(f"role session must be a JSON object at {p}")

    cookies = data.get("cookies") or {}
    headers = data.get("headers") or {}
    bearer = data.get("bearer")
    if cookies is not None and not isinstance(cookies, dict):
        raise RoleSessionError("cookies must be an object")
    if headers is not None and not isinstance(headers, dict):
        raise RoleSessionError("headers must be an object")
    if bearer is not None and not isinstance(bearer, str):
        raise RoleSessionError("bearer must be a string or null")

    session = RoleSession(
        role=role.strip().lower()[-1] if role else "a",
        path=p,
        cookies={str(k): str(v) for k, v in dict(cookies or {}).items()},
        headers={str(k): str(v) for k, v in dict(headers or {}).items()},
        bearer=bearer.strip() if isinstance(bearer, str) and bearer.strip() else None,
    )
    if not session.is_usable():
        raise RoleSessionError(
            f"Role {session.role.upper()} session at {p} has no cookies|headers|bearer. "
            "Packs fail closed until a usable lab fixture is present."
        )
    return session


def coach_missing_roles_message(*, needs_roles: int, missing: list[str]) -> str:
    """Coach-style (text) error when required role sessions are absent."""
    if needs_roles <= 0:
        need = "no roles required (optional Role A)"
    elif needs_roles == 1:
        need = "Role A"
    else:
        need = "Role A and Role B"
    miss = ", ".join(m.upper() for m in missing)
    return (
        f"Hunt pack fail-closed: needs {need} session fixture(s). "
        f"Missing: Role {miss}. "
        f"Place lab-only JSON at roles/a.json"
        f"{' and roles/b.json' if needs_roles == 2 else ''} "
        f"under the program directory with keys cookies|headers|bearer. "
        f"This pack will not start without authenticated role context "
        f"(authorized / lab use only — no credential theft)."
    )


def coach_optional_role_a_missing_graphql() -> str:
    """Soft coach when GraphQL mutation checks skip due to missing Role A."""
    return (
        "graphql pack: Role A session missing — mutation auth-diff checks "
        "skipped (soft). Introspection / global-id / batch-hint fixtures still "
        "run. Place lab-only roles/a.json with cookies|headers|bearer to enable "
        "unauth-vs-auth mutation compares. Authorized / lab use only."
    )
