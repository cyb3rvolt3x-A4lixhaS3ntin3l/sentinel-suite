"""L2 Passive DNS / CT MVP — native resolve + hardened crt.sh + reverse-IP neighbours."""

from __future__ import annotations

import json
import socket
from typing import Any, Callable, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen

from sentinel_core import Scope

# Injectable HTTP fetcher: (url, timeout) -> bytes
Fetcher = Callable[[str, float], bytes]
# Injectable reverse-IP: (ip, timeout) -> list[str] hostnames
ReverseIpFetcher = Callable[[str, float], list[str]]

DEFAULT_CRTSH_TIMEOUT = 8.0
DEFAULT_REVERSE_IP_MAX_RESULTS = 50


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
        return resp.read(2_000_000)


def _normalize_ct_hostname(raw: str, apex: str) -> str | None:
    """
    Normalize a CT name_value token.

    - lowercase, strip trailing dots
    - strip a single leading ``*.`` wildcard label (keep the rest)
    - drop bare ``*``, empty, or names outside apex
    """
    host = (raw or "").strip().lower().rstrip(".")
    if not host or host == "*":
        return None
    # Carefully strip wildcard: only leading "*."
    if host.startswith("*."):
        host = host[2:].lstrip(".")
    if not host or "*" in host:
        return None
    if host == apex or host.endswith("." + apex):
        return host
    return None


def crtsh_query(
    domain: str,
    *,
    fetcher: Fetcher | None = None,
    timeout: float = DEFAULT_CRTSH_TIMEOUT,
    network: bool = False,
) -> list[str]:
    """
    Query crt.sh for certificate transparency names for ``domain``.

    - Prefer injecting ``fetcher`` in tests (no live network).
    - Real network call only when ``network=True`` and no fetcher given.
    - On failure / timeout / malformed JSON: honest degrade → empty list.
    - Dedupes, strips ``*.`` wildcards carefully, keeps apex-subordinate names.
    - Source label for inventory merge: ``crtsh``.

    Returns unique lowercase hostnames.
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
        raw = fetch(url, float(timeout))
    except (URLError, TimeoutError, OSError, ValueError, socket.timeout):
        return []
    except Exception:  # noqa: BLE001 — honest degrade on any fetch failure
        return []

    if not raw:
        return []

    # Parse quality: reject HTML error pages / non-JSON early
    try:
        if isinstance(raw, (bytes, bytearray)):
            text = raw.decode("utf-8", errors="replace").strip()
        else:
            text = str(raw).strip()
    except Exception:  # noqa: BLE001
        return []

    if not text or text[0] not in "[{":
        return []

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
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
            host = _normalize_ct_hostname(part, apex)
            if not host or host in seen:
                continue
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
    timeout: float = DEFAULT_CRTSH_TIMEOUT,
) -> dict[str, Any]:
    """
    Run crtsh_query per apex domain; append new DNS_NAME-shaped entries.

    Marks source ``crtsh`` when any name is added.
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


def _apex_of(host: str) -> str:
    """Naive registrable-ish apex (last two labels). Good enough without PSL."""
    parts = host.strip().lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.strip().lower().rstrip(".")


def scope_distance(
    hostname: str,
    scope: Scope | None,
    *,
    apexes: Sequence[str] | None = None,
) -> int | None:
    """
    Distance from authorized scope.

    - 0: ``scope.is_allowed(hostname)`` (or no scope + matches known apexes)
    - 1: shares naive apex with an allow pattern / known apex (sibling host)
    - None: out of reach — must be dropped
    """
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return None

    if scope is not None:
        if scope.is_allowed(host):
            return 0
        host_apex = _apex_of(host)
        for pattern in scope.allow or []:
            p = pattern.strip().lower().rstrip(".")
            if p.startswith("*."):
                p = p[2:]
            if _apex_of(p) == host_apex:
                return 1
        # Also compare against provided apexes
        for a in apexes or []:
            if _apex_of(a) == host_apex:
                return 1
        return None

    # Lab / no scope: distance relative to known apexes only
    if not apexes:
        return 0  # unconstrained lab — caller still applies max_results
    host_apex = _apex_of(host)
    for a in apexes:
        aa = a.strip().lower().rstrip(".")
        if host == aa or host.endswith("." + aa) or _apex_of(aa) == host_apex:
            if host == aa or host.endswith("." + aa):
                return 0
            return 1
    return None


def reverse_ip_neighbours(
    ip: str,
    *,
    fetcher: ReverseIpFetcher | None = None,
    scope: Scope | None = None,
    apexes: Sequence[str] | None = None,
    max_distance: int = 1,
    max_results: int = DEFAULT_REVERSE_IP_MAX_RESULTS,
    network: bool = False,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """
    Reverse-IP neighbour hostnames with hard scope-distance cap.

    - Injectable ``fetcher(ip, timeout) -> list[str]``.
    - Without fetcher / offline: honest empty list + source note (no invented hosts).
    - Keeps only hostnames with ``scope_distance <= max_distance``.
    - Out-of-scope neighbours are dropped and never fetched further.
    """
    addr = (ip or "").strip()
    note = "reverse-ip stub: no fetcher / offline — returning empty"
    source = "reverse-ip-stub"
    raw_hosts: list[str] = []

    if fetcher is not None:
        source = "reverse-ip"
        note = "fetcher-provided"
        try:
            raw_hosts = list(fetcher(addr, float(timeout)) or [])
        except Exception:  # noqa: BLE001 — honest degrade
            raw_hosts = []
            note = "fetcher failed — returning empty"
    elif network:
        # No default live reverse-IP provider pinned yet (honesty).
        note = (
            "no default reverse-IP provider; inject fetcher or wait for "
            "allowlisted engine — returning empty"
        )
        source = "reverse-ip-stub"
    else:
        note = "offline / no fetcher — returning empty"
        source = "reverse-ip-stub"

    kept: list[dict[str, Any]] = []
    dropped_oos = 0
    seen: set[str] = set()
    for raw in raw_hosts:
        host = str(raw).strip().lower().rstrip(".")
        if not host or host in seen:
            continue
        seen.add(host)
        dist = scope_distance(host, scope, apexes=apexes)
        if dist is None or dist > int(max_distance):
            dropped_oos += 1
            continue
        kept.append(
            {
                "name": host,
                "ip": addr,
                "source": "reverse-ip",
                "scope_distance": dist,
            }
        )
        if len(kept) >= int(max_results):
            break

    return {
        "ip": addr,
        "hostnames": kept,
        "dropped_oos": dropped_oos,
        "source": source,
        "note": note,
        "max_distance": int(max_distance),
        "max_results": int(max_results),
    }


def merge_reverse_ip_into_inventory(
    inventory: dict[str, Any],
    *,
    fetcher: ReverseIpFetcher | None = None,
    scope: Scope | None = None,
    max_distance: int = 1,
    max_results: int = DEFAULT_REVERSE_IP_MAX_RESULTS,
    network: bool = False,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """
    For each inventory IP, query reverse-IP neighbours; merge in-scope DNS names.
    """
    from shadowseye.inventory import merge_sources, normalize_inventory

    inv = normalize_inventory(inventory)
    apexes = [
        (d if isinstance(d, str) else str(d.get("domain") or ""))
        .strip()
        .lower()
        .rstrip(".")
        for d in (inv.get("domains") or [])
    ]
    apexes = [a for a in apexes if a]

    seen_dns = {
        (
            raw.strip().lower().rstrip(".")
            if isinstance(raw, str)
            else str(raw.get("name") or "").strip().lower().rstrip(".")
        )
        for raw in inv.get("dns_names") or []
    }

    notes = list(inv.get("notes") or [])
    got_any = False
    ips = list(inv.get("ips") or [])
    for entry in ips:
        if isinstance(entry, str):
            ip = entry.strip()
        else:
            ip = str(entry.get("ip") or "").strip()
        if not ip:
            continue
        result = reverse_ip_neighbours(
            ip,
            fetcher=fetcher,
            scope=scope,
            apexes=apexes,
            max_distance=max_distance,
            max_results=max_results,
            network=network,
            timeout=timeout,
        )
        if result.get("note"):
            notes.append(
                {
                    "source": result.get("source"),
                    "ip": ip,
                    "note": result["note"],
                    "dropped_oos": result.get("dropped_oos", 0),
                }
            )
        for row in result.get("hostnames") or []:
            name = row["name"]
            got_any = True
            if name in seen_dns:
                continue
            seen_dns.add(name)
            parent = _apex_of(name)
            inv["dns_names"].append(
                {
                    "name": name,
                    "parent": parent,
                    "source": "reverse-ip",
                    "scope_distance": row.get("scope_distance", 0),
                    "ip": ip,
                }
            )

    inv["notes"] = notes
    if got_any:
        inv = merge_sources(inv, "reverse-ip")
    elif fetcher is None:
        inv = merge_sources(inv, "reverse-ip-stub")
    return inv


# Multi-source documentation (tools deferred until ENGINE_ALLOWLIST hashes ready):
# - native: socket resolve + optional tiny wordlist
# - crtsh: Certificate Transparency via crt.sh JSON (injectable fetcher; hardened parse)
# - reverse-ip: injectable neighbour lookup with hard scope-distance cap
# - tools (subfinder/dnsx): deferred — empty allowlist ⇒ native-only is OK
