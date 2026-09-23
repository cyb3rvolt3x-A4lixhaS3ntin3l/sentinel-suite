"""Hard caps + collaborator / metadata gates for ssrf_collaborator.

Authorized lab / owned-collaborator evidence scaffolding only.
NOT a cloud-metadata attack kit. NOT a random-internet SSRF scanner.

Even with ``--i-understand-lab``, values above HARD_MAX_REQUESTS hard-fail.

Gate spirit (mirrors http_desync / race_toctou):
- Pure fixtures → OK without lab flag. Default collaborator = 127.0.0.1 mock.
- ``--collaborator URL`` must be operator-owned. Cloud metadata refused unless
  BOTH ``--i-understand-lab`` AND fixtures.lab_fixture_mode.
- Beyond pure fixtures → BOTH ``--i-own-this`` AND ``--i-understand-lab``.
- Open-internet SSRF probes → ``--scope`` + ``--i-own-this`` + ``--i-understand-lab``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

HARD_MAX_REQUESTS = 10
DEFAULT_REQUESTS = 6
DEFAULT_COLLABORATOR = "http://127.0.0.1:9/ssrf-callback"

LAB_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

CLOUD_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "169.254.169.253",
        "metadata.google.internal",
        "metadata.google.com",
        "metadata",
        "instance-data",
        "100.100.100.200",
    }
)
_LINK_LOCAL_PREFIXES = ("169.254.",)

COACH_LAB_FIRST = (
    "ssrf packs are lab-first with an operator-owned collaborator; "
    "never spray cloud metadata or random internet hosts"
)
COACH_CAP_EXCEEDED = (
    "ssrf_collaborator hard request cap exceeded — max requests≤{requests}. "
    + COACH_LAB_FIRST
)
COACH_OPEN_INTERNET = (
    "ssrf_collaborator refuses open-internet SSRF probes without "
    "--scope AND --i-own-this AND --i-understand-lab. "
    + COACH_LAB_FIRST
)
COACH_NON_FIXTURE_LAB = (
    "ssrf_collaborator non-fixture / live-mock path requires BOTH "
    "--i-own-this AND --i-understand-lab. "
    + COACH_LAB_FIRST
)
COACH_METADATA_REFUSED = (
    "ssrf_collaborator refuses cloud metadata collaborator/target "
    "(169.254.169.254 / metadata.google.internal / Azure IMDS / equivalents). "
    "Not a cloud-metadata attack kit. Only allowed with --i-understand-lab "
    "AND documented lab fixture mode (fixtures.lab_fixture_mode). "
    + COACH_LAB_FIRST
)
COACH_COLLABORATOR_OWNED = (
    "ssrf_collaborator --collaborator must be operator-owned "
    "(default: local 127.0.0.1 fixture callback). "
    + COACH_LAB_FIRST
)


class CapExceededError(Exception):
    """Caps above hard maxima, or collaborator / lab gate failed."""

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class SsrfCaps:
    max_requests: int
    i_understand_lab: bool
    collaborator: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_requests": self.max_requests,
            "hard_max_requests": HARD_MAX_REQUESTS,
            "i_understand_lab": self.i_understand_lab,
            "collaborator": self.collaborator,
            "default_collaborator": DEFAULT_COLLABORATOR,
        }


@dataclass
class RequestBudget:
    """Sequential budget for non-pure-fixture / live-mock paths."""

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
    collaborator: str | None = None,
) -> SsrfCaps:
    if max_requests is None:
        r = DEFAULT_REQUESTS
    else:
        try:
            r = int(max_requests)
        except (TypeError, ValueError) as exc:
            raise CapExceededError(
                f"ssrf_collaborator invalid max_requests={max_requests!r}. "
                + COACH_CAP_EXCEEDED.format(requests=HARD_MAX_REQUESTS),
                exit_code=2,
            ) from exc
    if r < 1:
        raise CapExceededError(
            f"ssrf_collaborator max_requests must be ≥1 (got {r}). "
            + COACH_LAB_FIRST,
            exit_code=2,
        )
    if r > HARD_MAX_REQUESTS:
        raise CapExceededError(
            COACH_CAP_EXCEEDED.format(requests=HARD_MAX_REQUESTS)
            + f" (got max_requests={r})",
            exit_code=2,
        )
    collab = (collaborator or DEFAULT_COLLABORATOR).strip() or DEFAULT_COLLABORATOR
    return SsrfCaps(
        max_requests=r,
        i_understand_lab=bool(i_understand_lab),
        collaborator=collab,
    )


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
    return h.startswith("127.")


def is_cloud_metadata_target(url_or_host: str | None) -> bool:
    if not url_or_host:
        return False
    host = host_of(url_or_host)
    if not host:
        raw = url_or_host.strip().lower()
        return "169.254.169.254" in raw or "metadata.google.internal" in raw
    if host in CLOUD_METADATA_HOSTS:
        return True
    return any(host.startswith(p) for p in _LINK_LOCAL_PREFIXES)


def assert_metadata_refused(
    url_or_host: str | None,
    *,
    i_understand_lab: bool,
    lab_fixture_mode: bool,
) -> None:
    if not url_or_host or not is_cloud_metadata_target(url_or_host):
        return
    if i_understand_lab and lab_fixture_mode:
        return
    raise CapExceededError(COACH_METADATA_REFUSED, exit_code=2)


def assert_collaborator_allowed(
    collaborator: str | None,
    *,
    i_own_this: bool,
    i_understand_lab: bool,
    lab_fixture_mode: bool,
    fixtures_only: bool,
) -> None:
    if not collaborator:
        return
    assert_metadata_refused(
        collaborator,
        i_understand_lab=i_understand_lab,
        lab_fixture_mode=lab_fixture_mode,
    )
    host = host_of(collaborator)
    if not host:
        raise CapExceededError(
            f"ssrf_collaborator: empty/invalid collaborator host. "
            f"{COACH_COLLABORATOR_OWNED}",
            exit_code=2,
        )
    if is_lab_local_host(host):
        return
    if not i_own_this:
        raise CapExceededError(COACH_COLLABORATOR_OWNED, exit_code=2)
    if fixtures_only:
        return
    if not (i_own_this and i_understand_lab):
        raise CapExceededError(COACH_NON_FIXTURE_LAB, exit_code=2)


def assert_lab_dual_flag(
    *,
    i_own_this: bool,
    i_understand_lab: bool,
    fixtures_only: bool,
) -> None:
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
    lab_fixture_mode: bool = False,
) -> None:
    if fixtures_only or not url_or_host:
        return
    assert_metadata_refused(
        url_or_host,
        i_understand_lab=i_understand_lab,
        lab_fixture_mode=lab_fixture_mode,
    )
    assert_lab_dual_flag(
        i_own_this=i_own_this,
        i_understand_lab=i_understand_lab,
        fixtures_only=False,
    )
    host = host_of(url_or_host)
    if not host:
        raise CapExceededError(
            f"ssrf_collaborator: empty/invalid target host. {COACH_LAB_FIRST}",
            exit_code=2,
        )
    if is_lab_local_host(host):
        return
    if not (scope_present and i_own_this and i_understand_lab):
        raise CapExceededError(COACH_OPEN_INTERNET, exit_code=2)


__all__ = [
    "HARD_MAX_REQUESTS",
    "DEFAULT_REQUESTS",
    "DEFAULT_COLLABORATOR",
    "LAB_LOCAL_HOSTS",
    "CLOUD_METADATA_HOSTS",
    "COACH_LAB_FIRST",
    "COACH_CAP_EXCEEDED",
    "COACH_OPEN_INTERNET",
    "COACH_NON_FIXTURE_LAB",
    "COACH_METADATA_REFUSED",
    "COACH_COLLABORATOR_OWNED",
    "CapExceededError",
    "SsrfCaps",
    "RequestBudget",
    "resolve_caps",
    "host_of",
    "is_lab_local_host",
    "is_cloud_metadata_target",
    "assert_metadata_refused",
    "assert_collaborator_allowed",
    "assert_lab_dual_flag",
    "assert_target_allowed",
]
