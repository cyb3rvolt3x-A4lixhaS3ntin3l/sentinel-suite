"""Thin ShadowsEye runner — stdlib inventory → inventory_to_events → program graph."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Sequence

from sentinel_core import (
    Scope,
    ScopeDenied,
    create_program,
    load_scope_file,
    open_graph,
    program_dir,
)
from shadowseye.bridge import inventory_to_events

# Tiny default wordlist for lab/tests — not a real recon dictionary.
DEFAULT_SUBDOMAIN_WORDS: tuple[str, ...] = ("www", "api", "mail")
DEFAULT_PORTS: tuple[int, ...] = (80, 443)


def require_scope_or_lab(
    scope_path: str | Path | None = None,
    *,
    i_own_this: bool = False,
) -> None:
    """
    Eye entry gate: scope file OR explicit lab override.

    Mirrors gungnir.bridge.require_scope_or_lab without coupling Eye→Hunt.
    """
    if i_own_this:
        return
    if scope_path is None:
        raise ScopeDenied(
            "scope required: pass --scope or --i-own-this for lab use"
        )
    path = Path(scope_path)
    if not path.is_file():
        raise ScopeDenied(f"scope file not found: {path}")
    load_scope_file(path)


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


def probe_port(host: str, port: int, *, timeout: float = 0.35) -> bool:
    """Bounded TCP connect probe. Returns True if connect succeeds."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def gather_inventory(
    domains: Sequence[str],
    *,
    wordlist: Sequence[str] | None = None,
    ports: Sequence[int] | None = None,
    resolve: bool = True,
    scan_ports: bool = True,
    port_host_override: str | None = None,
) -> dict[str, Any]:
    """
    Stdlib-only thin inventory (no whois/social/password stalking).

    ``port_host_override`` forces port probes to a specific host (e.g. 127.0.0.1
    in tests) while still recording inventory under the logical domain names.
    """
    words = list(wordlist) if wordlist is not None else list(DEFAULT_SUBDOMAIN_WORDS)
    port_list = list(ports) if ports is not None else list(DEFAULT_PORTS)

    inventory: dict[str, Any] = {
        "domains": [],
        "dns_names": [],
        "ips": [],
        "ports": [],
    }
    seen_domains: set[str] = set()
    seen_dns: set[str] = set()
    seen_ips: set[str] = set()

    for raw in domains:
        apex = raw.strip().lower().rstrip(".")
        if not apex or apex in seen_domains:
            continue
        seen_domains.add(apex)
        inventory["domains"].append(apex)

        if apex not in seen_dns:
            seen_dns.add(apex)
            inventory["dns_names"].append({"name": apex, "parent": apex})

        if resolve:
            ip = resolve_host(apex)
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                inventory["ips"].append({"ip": ip, "host": apex})

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
                inventory["dns_names"].append({"name": fqdn, "parent": apex})
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    inventory["ips"].append({"ip": ip, "host": fqdn})
            else:
                seen_dns.add(fqdn)
                inventory["dns_names"].append({"name": fqdn, "parent": apex})

        if scan_ports and port_list:
            probe_target = port_host_override or apex
            if port_host_override is None and resolve:
                for entry in inventory["ips"]:
                    if entry.get("host") == apex:
                        probe_target = entry["ip"]
                        break
            for port in port_list:
                if probe_port(probe_target, int(port)):
                    inventory["ports"].append({"host": apex, "port": int(port)})

    return inventory


def load_wordlist(path: str | Path | None) -> list[str]:
    if path is None:
        return list(DEFAULT_SUBDOMAIN_WORDS)
    p = Path(path)
    words: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        words.append(s.split()[0].lower())
    return words or list(DEFAULT_SUBDOMAIN_WORDS)


def run_eye(
    program_id: str,
    domains: Sequence[str],
    *,
    scope_path: str | Path | None = None,
    i_own_this: bool = False,
    wordlist_path: str | Path | None = None,
    ports: Sequence[int] | None = None,
    resolve: bool = True,
    scan_ports: bool = True,
    port_host_override: str | None = None,
    create_if_missing: bool = True,
) -> dict[str, Any]:
    """
    Require scope file OR --i-own-this, gather inventory, emit into program graph.

    When a Scope is loaded, each inventory domain is hard_kill'd before emit.
    """
    # Resolve scope path: explicit flag, else program scope.txt if it has allows
    effective_scope_path: Path | None = Path(scope_path) if scope_path else None

    if create_if_missing:
        create_program(program_id)

    if effective_scope_path is None and not i_own_this:
        candidate = program_dir(program_id) / "scope.txt"
        if candidate.is_file():
            loaded = load_scope_file(candidate)
            if loaded.allow:
                effective_scope_path = candidate

    require_scope_or_lab(effective_scope_path, i_own_this=i_own_this)

    scope: Scope | None = None
    if effective_scope_path is not None:
        scope = load_scope_file(effective_scope_path)

    words = load_wordlist(wordlist_path)
    inventory = gather_inventory(
        domains,
        wordlist=words,
        ports=ports,
        resolve=resolve,
        scan_ports=scan_ports,
        port_host_override=port_host_override,
    )

    # hard_kill before any graph write when scope is active
    if scope is not None:
        for dom in inventory.get("domains") or []:
            scope.hard_kill(dom)

    events_out: list[dict[str, Any]] = []
    with open_graph(program_id) as graph:
        emitted = inventory_to_events(graph, program_id, inventory)
        for ev in emitted:
            events_out.append(
                {"id": ev.id, "type": ev.type, "payload": dict(ev.payload)}
            )

    return {
        "program_id": program_id,
        "inventory": inventory,
        "events": events_out,
        "event_count": len(events_out),
        "scoped": scope is not None,
        "i_own_this": bool(i_own_this),
    }
