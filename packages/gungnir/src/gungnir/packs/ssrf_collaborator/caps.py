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
    "COACH_BIND_NON_LOOPBACK",
    "COACH_LISTEN_DURATION",
    "COACH_LISTEN_HITS",
    "COACH_NO_OUTBOUND_SCAN",
    "DEFAULT_BIND",
    "DEFAULT_PORT",
    "DEFAULT_CALLBACK_PATH",
    "DEFAULT_LISTEN_DURATION_S",
    "HARD_MAX_LISTEN_DURATION_S",
    "DEFAULT_MAX_HITS",
    "HARD_MAX_HITS",
    "BODY_SNIPPET_MAX",
    "CapExceededError",
    "SsrfCaps",
    "ListenCaps",
    "RequestBudget",
    "resolve_caps",
    "resolve_listen_caps",
    "host_of",
    "is_lab_local_host",
    "is_loopback_bind",
    "is_cloud_metadata_target",
    "assert_metadata_refused",
    "assert_collaborator_allowed",
    "assert_lab_dual_flag",
    "assert_target_allowed",
    "assert_bind_allowed",
    "collaborator_url_for_listen",
]


# --- Phase C slice15: owned collaborator listener caps ---

DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_CALLBACK_PATH = "/ssrf-callback"
DEFAULT_LISTEN_DURATION_S = 120.0
HARD_MAX_LISTEN_DURATION_S = 300.0
DEFAULT_MAX_HITS = 50
HARD_MAX_HITS = 50
BODY_SNIPPET_MAX = 256

# Non-loopback binds that always need --i-understand-lab
_WILDCARD_BINDS = frozenset({"0.0.0.0", "::", "*", "[::]"})

COACH_BIND_NON_LOOPBACK = (
    "ssrf_collaborator listener refuses non-loopback bind "
    "(0.0.0.0 / :: / public interfaces) without --i-understand-lab. "
    "Default bind is 127.0.0.1 only. Public internet listener is NOT default. "
    "Never use cloud metadata as collaborator. No outbound scanning. "
    + COACH_LAB_FIRST
)
COACH_LISTEN_DURATION = (
    "ssrf_collaborator listener hard max duration exceeded — "
    f"max duration≤{HARD_MAX_LISTEN_DURATION_S:g}s. "
    + COACH_LAB_FIRST
)
COACH_LISTEN_HITS = (
    "ssrf_collaborator listener hard max hits exceeded — "
    f"max hits≤{HARD_MAX_HITS}. Fail-closed. "
    + COACH_LAB_FIRST
)
COACH_NO_OUTBOUND_SCAN = (
    "Owned collaborator listener only — no outbound scanning, "
    "no interactsh SaaS, no random-target SSRF, no cloud-metadata collaborator."
)


@dataclass(frozen=True)
class ListenCaps:
    bind: str
    port: int
    max_duration_s: float
    max_hits: int
    i_understand_lab: bool
    callback_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "bind": self.bind,
            "port": self.port,
            "max_duration_s": self.max_duration_s,
            "hard_max_duration_s": HARD_MAX_LISTEN_DURATION_S,
            "max_hits": self.max_hits,
            "hard_max_hits": HARD_MAX_HITS,
            "i_understand_lab": self.i_understand_lab,
            "callback_path": self.callback_path,
            "default_bind": DEFAULT_BIND,
        }


def is_loopback_bind(bind: str | None) -> bool:
    """True for 127.0.0.1 / localhost / ::1 / 127.* only (not 0.0.0.0 / ::)."""
    import ipaddress

    raw = (bind or "").strip().lower()
    if not raw:
        return False
    if raw in _WILDCARD_BINDS:
        return False
    if raw in LAB_LOCAL_HOSTS or raw.startswith("127."):
        return True
    # Strip brackets for IPv6 literals like [::1]
    host = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        addr = ipaddress.ip_address(host)
        return bool(addr.is_loopback)
    except ValueError:
        return False


def assert_bind_allowed(
    bind: str | None,
    *,
    i_understand_lab: bool,
) -> str:
    """Refuse non-loopback binds unless --i-understand-lab. Returns normalized bind."""
    b = (bind or DEFAULT_BIND).strip() or DEFAULT_BIND
    if is_loopback_bind(b):
        return b
    if not i_understand_lab:
        raise CapExceededError(COACH_BIND_NON_LOOPBACK, exit_code=2)
    return b


def resolve_listen_caps(
    *,
    bind: str | None = None,
    port: Any = None,
    max_duration: Any = None,
    max_hits: Any = None,
    i_understand_lab: bool = False,
    callback_path: str | None = None,
) -> ListenCaps:
    """Resolve listener caps; over-limit / non-loopback without lab → CapExceededError."""
    b = assert_bind_allowed(bind, i_understand_lab=i_understand_lab)

    if port is None:
        p = DEFAULT_PORT
    else:
        try:
            p = int(port)
        except (TypeError, ValueError) as exc:
            raise CapExceededError(
                f"ssrf_collaborator invalid listen port={port!r}. "
                + COACH_LAB_FIRST,
                exit_code=2,
            ) from exc
    if p < 0 or p > 65535:
        raise CapExceededError(
            f"ssrf_collaborator listen port must be 0..65535 (got {p}). "
            + COACH_LAB_FIRST,
            exit_code=2,
        )

    if max_duration is None:
        d = DEFAULT_LISTEN_DURATION_S
    else:
        try:
            d = float(max_duration)
        except (TypeError, ValueError) as exc:
            raise CapExceededError(
                f"ssrf_collaborator invalid max_duration={max_duration!r}. "
                + COACH_LISTEN_DURATION,
                exit_code=2,
            ) from exc
    if d <= 0:
        raise CapExceededError(
            f"ssrf_collaborator max_duration must be >0 (got {d}). "
            + COACH_LAB_FIRST,
            exit_code=2,
        )
    if d > HARD_MAX_LISTEN_DURATION_S:
        raise CapExceededError(
            COACH_LISTEN_DURATION + f" (got max_duration={d})",
            exit_code=2,
        )

    if max_hits is None:
        h = DEFAULT_MAX_HITS
    else:
        try:
            h = int(max_hits)
        except (TypeError, ValueError) as exc:
            raise CapExceededError(
                f"ssrf_collaborator invalid max_hits={max_hits!r}. "
                + COACH_LISTEN_HITS,
                exit_code=2,
            ) from exc
    if h < 1:
        raise CapExceededError(
            f"ssrf_collaborator max_hits must be ≥1 (got {h}). "
            + COACH_LAB_FIRST,
            exit_code=2,
        )
    if h > HARD_MAX_HITS:
        raise CapExceededError(
            COACH_LISTEN_HITS + f" (got max_hits={h})",
            exit_code=2,
        )

    path = (callback_path or DEFAULT_CALLBACK_PATH).strip() or DEFAULT_CALLBACK_PATH
    if not path.startswith("/"):
        path = "/" + path

    return ListenCaps(
        bind=b,
        port=p,
        max_duration_s=d,
        max_hits=h,
        i_understand_lab=bool(i_understand_lab),
        callback_path=path,
    )


def collaborator_url_for_listen(caps: ListenCaps, *, host_override: str | None = None) -> str:
    """Build collaborator callback URL for a listen bind (loopback-safe display)."""
    host = host_override or caps.bind
    if host == "0.0.0.0":
        # Lab wildcard bind: advertise via 127.0.0.1 for local clients
        host = "127.0.0.1"
    if host == "::":
        host = "::1"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = caps.port
    return f"http://{host}:{port}{caps.callback_path}"
