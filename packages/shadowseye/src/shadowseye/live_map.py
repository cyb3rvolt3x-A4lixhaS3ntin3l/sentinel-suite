"""L5 Live map lite — HTTP probe via stdlib urllib, scoped with http_guard."""

from __future__ import annotations

import re
from typing import Any, Callable, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sentinel_core import Scope, assert_url_in_scope

# (url, timeout) -> (status:int, body:bytes, final_url:str)
HttpOpener = Callable[[str, float], tuple[int, bytes, str]]

_TITLE_RE = re.compile(
    r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL
)


def _default_opener(url: str, timeout: float) -> tuple[int, bytes, str]:
    req = Request(url, method="GET", headers={"User-Agent": "sentinel-suite-shadowseye/0.1"})
    try:
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read(64_000)
            status = getattr(resp, "status", None) or resp.getcode() or 0
            final = resp.geturl() or url
            return int(status), body, final
    except HTTPError as exc:
        body = exc.read(64_000) if hasattr(exc, "read") else b""
        return int(exc.code or 0), body, url


def extract_title(body: bytes | str) -> str | None:
    """Best-effort HTML title extraction; None if missing."""
    try:
        text = body.decode("utf-8", errors="replace") if isinstance(body, (bytes, bytearray)) else str(body)
    except Exception:  # noqa: BLE001
        return None
    m = _TITLE_RE.search(text)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:200] if title else None


def http_probe(
    url: str,
    *,
    scope: Scope | None = None,
    opener: HttpOpener | None = None,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    """
    Probe one URL with optional scope hard-kill.

    Returns ``{url, status, title?}`` or None on transport failure.
    When ``scope`` is set, OOS raises ScopeDenied before any network.
    """
    if scope is not None:
        assert_url_in_scope(scope, url)

    open_fn = opener or _default_opener
    try:
        status, body, final_url = open_fn(url, timeout)
    except (URLError, TimeoutError, OSError, ValueError):
        return None
    except Exception:  # noqa: BLE001 — honest degrade
        return None

    entry: dict[str, Any] = {"url": final_url or url, "status": int(status)}
    title = extract_title(body)
    if title:
        entry["title"] = title
    return entry


def probe_http_inventory(
    inventory: dict[str, Any],
    *,
    scope: Scope | None = None,
    ports: Sequence[dict[str, Any]] | None = None,
    opener: HttpOpener | None = None,
    timeout: float = 5.0,
    schemes: Sequence[str] = ("http", "https"),
) -> list[dict[str, Any]]:
    """
    Build http[] entries from open ports (or default 80/443 per dns host).

    Bounded: one probe per (scheme, host, port) derived from inventory ports
    when present; otherwise skips (caller should have run port scan).
    """
    port_rows = list(ports) if ports is not None else list(inventory.get("ports") or [])
    results: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    for row in port_rows:
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or "").strip().lower().rstrip(".")
        try:
            port = int(row.get("port"))
        except (TypeError, ValueError):
            continue
        if not host:
            continue
        for scheme in schemes:
            # Skip nonsensical combos lightly: https on 80 still allowed but prefer match
            if scheme == "http" and port == 443:
                continue
            if scheme == "https" and port == 80:
                continue
            if port in (80, 443):
                url = f"{scheme}://{host}/"
            else:
                url = f"{scheme}://{host}:{port}/"
            if url in seen_urls:
                continue
            seen_urls.add(url)
            hit = http_probe(url, scope=scope, opener=opener, timeout=timeout)
            if hit:
                results.append(hit)
    return results
