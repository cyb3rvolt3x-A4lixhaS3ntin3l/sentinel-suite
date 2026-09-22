"""Hard caps for race_toctou — non-overridable above maxima.

Authorized lab/detection scaffolding only. Not a DoS weapon.
Even with ``--i-understand-lab``, requested values above HARD_MAX_* hard-fail
(never silently raise the ceiling).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

# Absolute maxima — prefer never exceed; CLI over-limit → hard fail.
HARD_MAX_WORKERS = 4
HARD_MAX_REQUESTS = 20
HARD_MAX_DURATION_S = 5.0

# Safe defaults (fixture / lab-first).
DEFAULT_WORKERS = 2
DEFAULT_REQUESTS = 8
DEFAULT_DURATION_S = 2.0

LAB_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

COACH_LAB_FIRST = (
    "race packs are lab-first; production programs need written "
    "authorization + rate limits"
)

COACH_CAP_EXCEEDED = (
    "race_toctou hard cap exceeded — max workers≤{workers}, "
    "max requests≤{requests}, max duration≤{duration}s. "
    + COACH_LAB_FIRST
)

COACH_OPEN_INTERNET = (
    "race_toctou refuses open-internet targets without "
    "--scope AND --i-own-this AND --i-understand-lab. "
    + COACH_LAB_FIRST
)


class CapExceededError(Exception):
    """Requested race caps above hard maxima (or open-internet gate failed)."""

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class RaceCaps:
    workers: int
    max_requests: int
    max_duration_s: float
    i_understand_lab: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "workers": self.workers,
            "max_requests": self.max_requests,
            "max_duration_s": self.max_duration_s,
            "i_understand_lab": self.i_understand_lab,
            "hard_max_workers": HARD_MAX_WORKERS,
            "hard_max_requests": HARD_MAX_REQUESTS,
            "hard_max_duration_s": HARD_MAX_DURATION_S,
        }


def _as_int(value: Any, default: int, *, label: str) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise CapExceededError(
            f"race_toctou invalid {label}={value!r}; must be an integer. "
            f"{COACH_LAB_FIRST}",
            exit_code=2,
        ) from exc


def _as_float(value: Any, default: float, *, label: str) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise CapExceededError(
            f"race_toctou invalid {label}={value!r}; must be a number. "
            f"{COACH_LAB_FIRST}",
            exit_code=2,
        ) from exc


def resolve_caps(
    *,
    workers: Any = None,
    max_requests: Any = None,
    max_duration: Any = None,
    i_understand_lab: bool = False,
) -> RaceCaps:
    """
    Resolve race caps. Values above HARD_MAX_* always hard-fail.

    ``i_understand_lab`` does **not** raise the ceiling — it only unlocks
    non-fixture / open-internet targeting when combined with scope gates.
    """
    w = _as_int(workers, DEFAULT_WORKERS, label="workers")
    r = _as_int(max_requests, DEFAULT_REQUESTS, label="max_requests")
    d = _as_float(max_duration, DEFAULT_DURATION_S, label="max_duration")

    if w < 1 or r < 1 or d <= 0:
        raise CapExceededError(
            f"race_toctou caps must be positive "
            f"(workers={w}, max_requests={r}, max_duration={d}). "
            f"{COACH_LAB_FIRST}",
            exit_code=2,
        )

    if w > HARD_MAX_WORKERS or r > HARD_MAX_REQUESTS or d > HARD_MAX_DURATION_S:
        raise CapExceededError(
            COACH_CAP_EXCEEDED.format(
                workers=HARD_MAX_WORKERS,
                requests=HARD_MAX_REQUESTS,
                duration=HARD_MAX_DURATION_S,
            )
            + f" (got workers={w}, max_requests={r}, max_duration={d})",
            exit_code=2,
        )

    return RaceCaps(
        workers=w,
        max_requests=r,
        max_duration_s=d,
        i_understand_lab=bool(i_understand_lab),
    )


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
    # Loopback IPv4 range 127.0.0.0/8
    if h.startswith("127."):
        return True
    return False


def assert_target_allowed(
    url_or_host: str | None,
    *,
    scope_present: bool,
    i_own_this: bool,
    i_understand_lab: bool,
    fixtures_only: bool,
) -> None:
    """
    Gate live targets for race_toctou.

    - Fixture-only runs always OK (no live host).
    - Lab-local (127.0.0.1 / localhost) needs scope OR i_own_this (normal gate).
    - Open internet needs --scope AND --i-own-this AND --i-understand-lab.
    """
    if fixtures_only or not url_or_host:
        return
    host = host_of(url_or_host)
    if not host:
        raise CapExceededError(
            f"race_toctou: empty/invalid target host. {COACH_LAB_FIRST}",
            exit_code=2,
        )
    if is_lab_local_host(host):
        if not (scope_present or i_own_this):
            raise CapExceededError(
                f"race_toctou lab-local target requires --scope or --i-own-this. "
                f"{COACH_LAB_FIRST}",
                exit_code=2,
            )
        return
    # Open internet — triple gate
    if not (scope_present and i_own_this and i_understand_lab):
        raise CapExceededError(COACH_OPEN_INTERNET, exit_code=2)


__all__ = [
    "HARD_MAX_WORKERS",
    "HARD_MAX_REQUESTS",
    "HARD_MAX_DURATION_S",
    "DEFAULT_WORKERS",
    "DEFAULT_REQUESTS",
    "DEFAULT_DURATION_S",
    "LAB_LOCAL_HOSTS",
    "COACH_LAB_FIRST",
    "COACH_CAP_EXCEEDED",
    "COACH_OPEN_INTERNET",
    "CapExceededError",
    "RaceCaps",
    "resolve_caps",
    "host_of",
    "is_lab_local_host",
    "assert_target_allowed",
]
