"""Phase D1 — optional local UI auth (bcrypt under SENTINEL_HOME/ui_auth.json).

Loopback bind remains the primary fence. Password mode gates mutating API routes.
Skip-for-lab writes a marker and trusts loopback (single-operator lab).
"""

from __future__ import annotations

import json
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel_core import get_sentinel_home

AUTH_FILENAME = "ui_auth.json"
MODE_PASSWORD = "password"
MODE_SKIP_LAB = "skip_lab"

# In-process session tokens (single UI server process).
_sessions: dict[str, dict[str, Any]] = {}
_sessions_lock = threading.Lock()


class UIAuthError(Exception):
    """Auth refused / misconfigured."""

    def __init__(self, message: str, *, status: int = 401, code: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code or "auth_error"


def auth_file_path(home: Path | None = None) -> Path:
    return (home or get_sentinel_home()) / AUTH_FILENAME


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_auth_config(home: Path | None = None) -> dict[str, Any] | None:
    path = auth_file_path(home)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def auth_status(home: Path | None = None) -> dict[str, Any]:
    cfg = load_auth_config(home)
    if cfg is None:
        return {
            "configured": False,
            "mode": None,
            "need_first_run": True,
            "mutating_requires_auth": True,
            "message": "First-run: set a local password or skip for lab.",
        }
    mode = str(cfg.get("mode") or "").strip()
    if mode == MODE_PASSWORD and cfg.get("bcrypt_hash"):
        return {
            "configured": True,
            "mode": MODE_PASSWORD,
            "need_first_run": False,
            "mutating_requires_auth": True,
            "created_at": cfg.get("created_at"),
        }
    if mode == MODE_SKIP_LAB:
        return {
            "configured": True,
            "mode": MODE_SKIP_LAB,
            "need_first_run": False,
            "mutating_requires_auth": False,
            "skipped_at": cfg.get("skipped_at") or cfg.get("created_at"),
            "message": "Lab skip marker present — loopback trust; mutating open.",
        }
    return {
        "configured": False,
        "mode": mode or None,
        "need_first_run": True,
        "mutating_requires_auth": True,
        "message": "ui_auth.json present but incomplete — re-run first-run setup.",
    }


def _hash_password(password: str) -> str:
    try:
        import bcrypt
    except ImportError as exc:  # pragma: no cover
        raise UIAuthError(
            "bcrypt package required for UI password mode "
            "(pip install bcrypt)",
            status=500,
            code="bcrypt_missing",
        ) from exc
    raw = password.encode("utf-8")
    if len(raw) > 72:
        raise UIAuthError("password too long (bcrypt max 72 bytes)", status=400)
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=12)).decode("ascii")


def _verify_password(password: str, hashed: str) -> bool:
    try:
        import bcrypt
    except ImportError:
        return False
    try:
        return bool(
            bcrypt.checkpw(password.encode("utf-8"), hashed.encode("ascii"))
        )
    except (ValueError, TypeError):
        return False


def setup_auth(
    *,
    action: str,
    password: str | None = None,
    home: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """
    First-run: action=set_password|skip_lab.

    Refuses if already configured unless force=True (tests / explicit reset).
    """
    path = auth_file_path(home)
    existing = load_auth_config(home)
    if existing and not force:
        mode = existing.get("mode")
        if mode in (MODE_PASSWORD, MODE_SKIP_LAB):
            raise UIAuthError(
                "UI auth already configured "
                f"(mode={mode}). Delete {path.name} to reset.",
                status=409,
                code="already_configured",
            )

    act = (action or "").strip().lower()
    path.parent.mkdir(parents=True, exist_ok=True)

    if act in ("skip", "skip_lab", "skip-for-lab"):
        payload = {
            "mode": MODE_SKIP_LAB,
            "skipped_at": _utcnow(),
            "created_at": _utcnow(),
            "note": "Lab skip — loopback remains the primary fence.",
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return {"ok": True, "mode": MODE_SKIP_LAB, "path": str(path)}

    if act in ("set_password", "password", "set-password"):
        pw = password or ""
        if len(pw) < 8:
            raise UIAuthError(
                "password must be at least 8 characters",
                status=400,
                code="weak_password",
            )
        hashed = _hash_password(pw)
        payload = {
            "mode": MODE_PASSWORD,
            "bcrypt_hash": hashed,
            "created_at": _utcnow(),
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return {"ok": True, "mode": MODE_PASSWORD, "path": str(path)}

    raise UIAuthError(
        "action must be set_password or skip_lab",
        status=400,
        code="bad_action",
    )


def login(password: str, *, home: Path | None = None) -> dict[str, Any]:
    cfg = load_auth_config(home)
    if not cfg or cfg.get("mode") != MODE_PASSWORD or not cfg.get("bcrypt_hash"):
        raise UIAuthError(
            "password login not available (configure password mode first)",
            status=400,
            code="login_unavailable",
        )
    if not _verify_password(password or "", str(cfg["bcrypt_hash"])):
        raise UIAuthError("invalid password", status=401, code="bad_password")
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions[token] = {"created_at": _utcnow()}
    return {"ok": True, "token": token, "token_type": "Bearer"}


def logout(token: str | None) -> dict[str, Any]:
    if token:
        with _sessions_lock:
            _sessions.pop(token, None)
    return {"ok": True}


def clear_sessions() -> None:
    """Test helper."""
    with _sessions_lock:
        _sessions.clear()


def extract_bearer(headers: Any) -> str | None:
    """Pull token from Authorization: Bearer or X-Sentinel-UI-Token."""
    if headers is None:
        return None
    get = getattr(headers, "get", None)
    if get is None and isinstance(headers, dict):
        get = headers.get
    if get is None:
        return None
    custom = get("X-Sentinel-UI-Token") or get("x-sentinel-ui-token")
    if custom and str(custom).strip():
        return str(custom).strip()
    auth = get("Authorization") or get("authorization") or ""
    auth_s = str(auth).strip()
    if auth_s.lower().startswith("bearer "):
        return auth_s[7:].strip() or None
    return None


def session_valid(token: str | None) -> bool:
    if not token:
        return False
    with _sessions_lock:
        return token in _sessions


def require_mutating_auth(headers: Any, *, home: Path | None = None) -> None:
    """
    Enforce mutating-route policy.

    Raises UIAuthError when blocked.
    """
    status = auth_status(home)
    if status.get("need_first_run"):
        raise UIAuthError(
            "UI first-run required: POST /api/auth/setup "
            "with action=set_password|skip_lab before mutating routes",
            status=401,
            code="need_first_run",
        )
    if not status.get("mutating_requires_auth"):
        return  # skip_lab
    token = extract_bearer(headers)
    if not session_valid(token):
        raise UIAuthError(
            "authentication required for mutating UI routes "
            "(POST /api/auth/login)",
            status=401,
            code="auth_required",
        )


__all__ = [
    "AUTH_FILENAME",
    "MODE_PASSWORD",
    "MODE_SKIP_LAB",
    "UIAuthError",
    "auth_file_path",
    "auth_status",
    "clear_sessions",
    "extract_bearer",
    "load_auth_config",
    "login",
    "logout",
    "require_mutating_auth",
    "session_valid",
    "setup_auth",
]
