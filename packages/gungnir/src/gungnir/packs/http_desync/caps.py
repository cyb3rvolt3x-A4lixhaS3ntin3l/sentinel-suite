"""Hard caps + lab dual-flag gate for http_desync pack.

Authorized lab / staging evidence scaffolding only. Not a production
smuggling weapon. Even with ``--i-understand-lab``, requested values above
HARD_MAX_REQUESTS hard-fail (never silently raise the ceiling).

Lab gate spirit (mirrors race_toctou, stricter for this pack):
- Pure fixtures → OK without lab flag (CI-friendly).
- Anything beyond pure fixtures requires BOTH ``--i-own-this`` AND
  ``--i-understand-lab``.
- Open-internet targets additionally require ``--scope`` (triple gate with
  ownership + lab acknowledgment). Default refuse open-internet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

HARD_MAX_REQUESTS = 10
DEFAULT_REQUESTS = 6

LAB_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

COACH_LAB_FIRST = (
    "desync is lab/staging; production needs written auth + careful coordination"
)

COACH_CAP_EXCEEDED = (
    "http_desync hard request cap exceeded — max requests≤{requests}. "
    + COACH_LAB_FIRST
)

COACH_OPEN_INTERNET = (
    "http_desync refuses open-internet targets without "
    "--scope AND --i-own-this AND --i-understand-lab. "
    + COACH_LAB_FIRST
)

COACH_NON_FIXTURE_LAB = (
    "http_desync non-fixture / live-mock path requires BOTH "
    "--i-own-this AND --i-understand-lab. "
    + COACH_LAB_FIRST
)


class CapExceededError(Exception):
    """Requested caps above hard maxima, or lab / open-internet gate failed."""

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class DesyncCaps:
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
    """Sequential budget for non-pure-fixture / live-mock request paths."""

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
) -> DesyncCaps:
    """
    Resolve request caps. Values above HARD_MAX_REQUESTS always hard-fail.

    ``i_understand_lab`` does **not** raise the ceiling — it only unlocks
    non-fixture / open-internet targeting when combined with ownership flags.
    """
    if max_requests is None:
        r = DEFAULT_REQUESTS
    else:
        try:
            r = int(max_requests)
        except (TypeError, ValueError) as exc:
            raise CapExceededError(
                f"http_desync invalid max_requests={max_requests!r}. "
                + COACH_CAP_EXCEEDED.format(requests=HARD_MAX_REQUESTS),
                exit_code=2,
            ) from exc
    if r < 1:
        raise CapExceededError(
            f"http_desync max_requests must be ≥1 (got {r}). "
            + COACH_LAB_FIRST,
            exit_code=2,
        )
    if r > HARD_MAX_REQUESTS:
        raise CapExceededError(
            COACH_CAP_EXCEEDED.format(requests=HARD_MAX_REQUESTS)
            + f" (got max_requests={r})",
            exit_code=2,
        )
    return DesyncCaps(max_requests=r, i_understand_lab=bool(i_understand_lab))


def host_of(url_or_host: str) -> str:
    raw = (url_or_host or "").strip()
    if not raw:
        return ""
    if "://" not in raw and "/" not in raw and not raw.startswith("//"):
        return raw.split(":")[0].strip().lower().rstrip(".")
    if raw.startswith("//"):
        parsed = urlparse("https:" + raw)
        return (parsed.hostname or "").strip().lower().rstrip(".")
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    return (parsed.hostname or "").strip().lower().rstrip(".")


def is_lab_local_host(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if h in LAB_LOCAL_HOSTS:
        return True
    if h.startswith("127."):
        return True
    return False


def assert_lab_dual_flag(
    *,
    i_own_this: bool,
    i_understand_lab: bool,
    fixtures_only: bool,
) -> None:
    """Beyond pure fixtures → require BOTH ownership and lab acknowledgment."""
    if fixtures_only:
        return
    if not (i_own_this and i_understand_lab):
        raise CapExceededError(COACH_NON_FIXTURE_LAB, exit_code=2)


def assert_target_allowed(
    url_or_host: str | None,
    *,
    scope_present: bool,
    i_own_this: bool,
    i_understand_lab: bool,
    fixtures_only: bool,
) -> None:
    """
    Gate live targets for http_desync.

    - Fixture-only runs always OK (no live host).
    - Beyond fixtures: BOTH --i-own-this AND --i-understand-lab.
    - Lab-local (127.0.0.1 / localhost): dual flag above.
    - Open internet: --scope AND --i-own-this AND --i-understand-lab
      (default refuse).
    """
    if fixtures_only or not url_or_host:
        return
    assert_lab_dual_flag(
        i_own_this=i_own_this,
        i_understand_lab=i_understand_lab,
        fixtures_only=False,
    )
    host = host_of(url_or_host)
    if not host:
        raise CapExceededError(
            f"http_desync: empty/invalid target host. {COACH_LAB_FIRST}",
            exit_code=2,
        )
    if is_lab_local_host(host):
        return
    # Open internet — triple gate (default refuse)
    if not (scope_present and i_own_this and i_understand_lab):
        raise CapExceededError(COACH_OPEN_INTERNET, exit_code=2)


__all__ = [
    "HARD_MAX_REQUESTS",
    "DEFAULT_REQUESTS",
    "LAB_LOCAL_HOSTS",
    "COACH_LAB_FIRST",
    "COACH_CAP_EXCEEDED",
    "COACH_OPEN_INTERNET",
    "COACH_NON_FIXTURE_LAB",
    "CapExceededError",
    "DesyncCaps",
    "RequestBudget",
    "resolve_caps",
    "host_of",
    "is_lab_local_host",
    "assert_lab_dual_flag",
    "assert_target_allowed",
]
