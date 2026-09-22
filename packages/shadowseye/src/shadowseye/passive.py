"""L2 Passive DNS / CT MVP — native resolve + crt.sh stub (tools deferred)."""

from __future__ import annotations

import json
import socket
from typing import Any, Callable, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen

# Injectable HTTP fetcher: (url, timeout) -> bytes
Fetcher = Callable[[str, float], bytes]


def resolve_host(hostname: str) -> str | None:
    """Resolve hostname to first IPv4 via getaddrinfo. None on failure."""
    try:
        infos = socket.getaddrinfo(
            hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
    except (socket.gaierror, OSError):
        return None
    if not infos:
        return None
    return infos[0][4][0]


def _default_fetcher(url: str, timeout: float) -> bytes:
    req = Request(url, headers={"User-Agent": "sentinel-suite-shadowseye/0.1"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — intentional opt-in net
        return resp.read()


def crtsh_query(
    domain: str,
    *,
    fetcher: Fetcher | None = None,
    timeout: float = 8.0,
    network: bool = False,
) -> list[str]:
    """
    Query crt.sh for certificate transparency names for ``domain``.

    - Prefer injecting ``fetcher`` in tests (no live network).
    - Real network call only when ``network=True`` and no fetcher given.
    - On failure / timeout: honest degrade → empty list (never raises for net errors).

    Returns unique lowercase hostnames (may include wildcards stripped of leading ``*.``).
    """
    apex = (domain or "").strip().lower().rstrip(".")
    if not apex:
        return []

    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    fetch = fetcher
    if fetch is None:
        if not network:
            return []
        fetch = _default_fetcher

    try:
        raw = fetch(url, timeout)
    except (URLError, TimeoutError, OSError, ValueError):
        return []
    except Exception:  # noqa: BLE001 — honest degrade on any fetch failure
        return []

    if not raw:
        return []

    try:
        data = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, AttributeError):
        return []

    if not isinstance(data, list):
        return []

    names: list[str] = []
    seen: set[str] = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        value = row.get("name_value") or row.get("common_name") or ""
        for part in str(value).split("\n"):
            host = part.strip().lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            if not host or host in seen:
                continue
            # Keep only names under the queried apex (or the apex itself)
            if host == apex or host.endswith("." + apex):
                seen.add(host)
                names.append(host)
    return names


def native_wordlist_resolve(
    domains: Sequence[str],
    *,
    wordlist: Sequence[str] | None = None,
    resolve: bool = True,
) -> dict[str, Any]:
    """
    Native L2 lite: apex + tiny wordlist → dns_names (+ ips when resolve=True).

    Does not call external CT APIs. Source label: ``native``.
    """
    from shadowseye.inventory import empty_inventory, merge_sources

    words = list(wordlist) if wordlist is not None else ["www", "api", "mail"]
    inv = empty_inventory()
    seen_domains: set[str] = set()
    seen_dns: set[str] = set()
    seen_ips: set[str] = set()

    for raw in domains:
        apex = raw.strip().lower().rstrip(".")
        if not apex or apex in seen_domains:
            continue
        seen_domains.add(apex)
        inv["domains"].append(apex)

        if apex not in seen_dns:
            seen_dns.add(apex)
            inv["dns_names"].append({"name": apex, "parent": apex, "source": "native"})

        if resolve:
            ip = resolve_host(apex)
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                inv["ips"].append({"ip": ip, "host": apex})

        for word in words:
            word = word.strip().lower()
            if not word:
                continue
            fqdn = f"{word}.{apex}"
            if fqdn in seen_dns:
                continue
            if resolve:
                ip = resolve_host(fqdn)
                if ip is None:
                    continue
                seen_dns.add(fqdn)
                inv["dns_names"].append(
                    {"name": fqdn, "parent": apex, "source": "native"}
                )
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    inv["ips"].append({"ip": ip, "host": fqdn})
            else:
                seen_dns.add(fqdn)
                inv["dns_names"].append(
                    {"name": fqdn, "parent": apex, "source": "native"}
                )

    return merge_sources(inv, "native")


def merge_crtsh_into_inventory(
    inventory: dict[str, Any],
    domains: Sequence[str],
    *,
    fetcher: Fetcher | None = None,
    network: bool = False,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """
    Run crtsh_query per apex domain; append new DNS_NAME-shaped entries.

    Marks source ``crtsh`` when any name is added (or query attempted with results).
    """
    from shadowseye.inventory import merge_sources, normalize_inventory

    inv = normalize_inventory(inventory)
    seen = {
        (
            raw.strip().lower().rstrip(".")
            if isinstance(raw, str)
            else str(raw.get("name") or "").strip().lower().rstrip(".")
        )
        for raw in inv.get("dns_names") or []
    }
    got_any = False
    for raw in domains:
        apex = raw.strip().lower().rstrip(".")
        if not apex:
            continue
        names = crtsh_query(
            apex, fetcher=fetcher, timeout=timeout, network=network
        )
        for name in names:
            got_any = True
            if name in seen:
                continue
            seen.add(name)
            inv["dns_names"].append(
                {"name": name, "parent": apex, "source": "crtsh"}
            )
            if apex not in inv["domains"]:
                inv["domains"].append(apex)
    if got_any:
        inv = merge_sources(inv, "crtsh")
    return inv


# Multi-source documentation (tools deferred until ENGINE_ALLOWLIST hashes ready):
# - native: socket resolve + optional tiny wordlist
# - crtsh: Certificate Transparency stub via crt.sh JSON (injectable fetcher)
# - tools (subfinder/dnsx): deferred — empty allowlist ⇒ native-only is OK
