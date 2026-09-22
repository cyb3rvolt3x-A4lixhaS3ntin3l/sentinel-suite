"""HTTP hard-kill wrapper — assert URL host in scope before any network."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sentinel_core.scope import Scope, ScopeDenied


def host_from_url(url: str) -> str:
    """Extract hostname from a URL (or bare host). Raises ValueError if empty."""
    raw = (url or "").strip()
    if not raw:
        raise ValueError("empty url")
    # Bare host without scheme
    if "://" not in raw and "/" not in raw:
        host = raw.split(":")[0].strip().lower().rstrip(".")
        if not host:
            raise ValueError(f"no host in url: {url!r}")
        return host
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError(f"no host in url: {url!r}")
    return host


def assert_url_in_scope(scope: Scope, url: str) -> str:
    """
    Hard-kill check for a URL: extract host, call scope.hard_kill(host).

    Returns the normalized host on success. Raises ScopeDenied for OOS.
    Unit tests can call this without any network.
    """
    host = host_from_url(url)
    scope.hard_kill(host)
    return host


@dataclass
class PreparedScopedRequest:
    """Prepared request after scope hard-kill (no network yet)."""

    method: str
    url: str
    host: str
    headers: dict[str, str]
    data: bytes | None = None


def prepare_scoped_request(
    scope: Scope,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> PreparedScopedRequest:
    """Validate scope then return a prepared request object (no fetch)."""
    host = assert_url_in_scope(scope, url)
    return PreparedScopedRequest(
        method=method.upper(),
        url=url,
        host=host,
        headers=dict(headers or {}),
        data=data,
    )


def scoped_request(
    scope: Scope,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = 15.0,
    opener: Callable[..., Any] | None = None,
) -> Any:
    """
    Hard-kill host, then optionally perform the request via stdlib urlopen.

    ``opener`` defaults to urllib.request.urlopen. Tests should pass a fake
    opener (or use assert_url_in_scope / prepare_scoped_request) so OOS never
    reaches the network.
    """
    prepared = prepare_scoped_request(
        scope, method, url, headers=headers, data=data
    )
    req = Request(
        prepared.url,
        data=prepared.data,
        headers=prepared.headers,
        method=prepared.method,
    )
    open_fn = opener or urlopen
    return open_fn(req, timeout=timeout)


# Alias used by bridges
ScopedSession = prepare_scoped_request

__all__ = [
    "PreparedScopedRequest",
    "ScopedSession",
    "assert_url_in_scope",
    "host_from_url",
    "prepare_scoped_request",
    "scoped_request",
    "ScopeDenied",
]
