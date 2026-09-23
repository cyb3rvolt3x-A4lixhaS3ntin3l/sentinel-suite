"""Hard request caps for csrf_state pack live-mock paths.

Fixture-only runs do not consume the budget. Any live/opener mock path must
respect HARD_MAX_REQUESTS (non-overridable). No cross-site CSRF farms / flood.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

HARD_MAX_REQUESTS = 10
DEFAULT_REQUESTS = 6

LAB_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

COACH_CAPS = (
    "csrf_state pack hard request cap: max requests≤{requests} when any live "
    "mock is used. Fixture-only runs are uncapped by this gate. "
    "Authorized / lab only — no live mass CSRF spray; no form flood."
)


class CsrfStateCapExceededError(Exception):
    """Live-mock request budget exceeded or invalid cap."""

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class CsrfStateCaps:
    max_requests: int
    i_understand_lab: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_requests": self.max_requests,
            "hard_max_requests": HARD_MAX_REQUESTS,
            "i_understand_lab": self.i_understand_lab,
        }


@dataclass
class RequestBudget:
    """Sequential budget for live mock requests."""

    max_requests: int
    used: int = 0
    rejected: int = 0

    def try_acquire(self) -> bool:
        if self.used >= self.max_requests:
            self.rejected += 1
            return False
        self.used += 1
        return True


def resolve_caps(
    *,
    max_requests: Any = None,
    i_understand_lab: bool = False,
) -> CsrfStateCaps:
    if max_requests is None:
        r = DEFAULT_REQUESTS
    else:
        try:
            r = int(max_requests)
        except (TypeError, ValueError) as exc:
            raise CsrfStateCapExceededError(
                f"csrf_state invalid max_requests={max_requests!r}. "
                + COACH_CAPS.format(requests=HARD_MAX_REQUESTS),
                exit_code=2,
            ) from exc
    if r < 1:
        raise CsrfStateCapExceededError(
            f"csrf_state max_requests must be ≥1 (got {r}). "
            + COACH_CAPS.format(requests=HARD_MAX_REQUESTS),
            exit_code=2,
        )
    if r > HARD_MAX_REQUESTS:
        raise CsrfStateCapExceededError(
            COACH_CAPS.format(requests=HARD_MAX_REQUESTS)
            + f" (got max_requests={r})",
            exit_code=2,
        )
    return CsrfStateCaps(max_requests=r, i_understand_lab=bool(i_understand_lab))


def host_of(url_or_host: str) -> str:
    raw = (url_or_host or "").strip()
    if not raw:
        return ""
    if "://" not in raw and "/" not in raw:
        return raw.split(":")[0].strip().lower().rstrip(".")
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    return (parsed.hostname or "").strip().lower().rstrip(".")


def is_lab_local_host(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if h in LAB_LOCAL_HOSTS:
        return True
    if h.startswith("127."):
        return True
    return False


__all__ = [
    "HARD_MAX_REQUESTS",
    "DEFAULT_REQUESTS",
    "LAB_LOCAL_HOSTS",
    "COACH_CAPS",
    "CsrfStateCapExceededError",
    "CsrfStateCaps",
    "RequestBudget",
    "resolve_caps",
    "host_of",
    "is_lab_local_host",
]
