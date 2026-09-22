"""ShadowsEye runner — L0/L2/L5 lite inventory → events + optional watch diffs."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Callable, Sequence

from sentinel_core import (
    Scope,
    ScopeDenied,
    create_program,
    load_scope_file,
    open_graph,
    program_dir,
)
from shadowseye.bridge import inventory_to_events
from shadowseye.inventory import merge_sources, normalize_inventory
from shadowseye.live_map import probe_http_inventory
from shadowseye.tech_fingerprint import merge_tech_into_inventory
from shadowseye.identity import merge_identity_into_inventory
from shadowseye.passive import merge_crtsh_into_inventory, merge_reverse_ip_into_inventory
from shadowseye.ranker import rank_inventory, sort_dns_names_by_rank
from shadowseye.watch import watch_compare_and_persist

# Tiny default wordlist for lab/tests — not a real recon dictionary.
DEFAULT_SUBDOMAIN_WORDS: tuple[str, ...] = ("www", "api", "mail")
DEFAULT_PORTS: tuple[int, ...] = (80, 443)

# Layers enabled by this Phase B slice (honest labels for program.yml).
PHASE_B_SLICE1_LAYERS: tuple[str, ...] = ("L0", "L1", "L2", "L5", "L6", "ranker")
PHASE_B_SLICE2_LAYERS = PHASE_B_SLICE1_LAYERS  # alias after slice2 landing
PHASE_B_SLICE3_LAYERS: tuple[str, ...] = ("L0", "L1", "L2", "L5", "L6", "ranker")
PHASE_B_SLICE4_LAYERS: tuple[str, ...] = ("L0", "L1", "L2", "L5", "L6", "ranker")



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

    inventory: dict[str, Any] = normalize_inventory(
        {
            "domains": [],
            "dns_names": [],
            "ips": [],
            "ports": [],
        }
    )
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
            inventory["dns_names"].append(
                {"name": apex, "parent": apex, "source": "native"}
            )

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
                inventory["dns_names"].append(
                    {"name": fqdn, "parent": apex, "source": "native"}
                )
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    inventory["ips"].append({"ip": ip, "host": fqdn})
            else:
                seen_dns.add(fqdn)
                inventory["dns_names"].append(
                    {"name": fqdn, "parent": apex, "source": "native"}
                )

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

    return merge_sources(inventory, "native")


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


def touch_program_yml_layers(
    program_id: str,
    *,
    layers: Sequence[str] | None = None,
) -> None:
    """Ensure program.yml lists Phase B layers + updated_at (L0 brain)."""
    from datetime import datetime, timezone

    from sentinel_core.programs import update_program_yml_fields

    update_program_yml_fields(
        program_id,
        layers_enabled=list(layers or PHASE_B_SLICE4_LAYERS),
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


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
    no_tools: bool = True,
    crtsh: bool = True,
    crtsh_fetcher: Callable[[str, float], bytes] | None = None,
    crtsh_network: bool = False,
    http_probe: bool = True,
    http_opener: Callable[[str, float], tuple[int, bytes, str]] | None = None,
    fingerprint: bool = True,
    watch: bool = False,
    rank: bool = True,
    identity: bool = True,
    rdap_fetcher: Callable[[str, float], bytes] | None = None,
    mx_resolver: Callable[[str], list[str]] | None = None,
    txt_resolver: Callable[[str], list[str]] | None = None,
    identity_network: bool = False,
    reverse_ip: bool = True,
    reverse_ip_fetcher: Callable[[str, float], list[str]] | None = None,
    reverse_ip_network: bool = False,
    scope_distance: int = 1,
    reverse_ip_max_results: int = 50,
) -> dict[str, Any]:
    """
    Require scope file OR --i-own-this, gather inventory, emit into program graph.

    Phase B slice4:
    - L1: identity lite (RDAP/ASN/MX/SPF) low-confidence; ``--no-identity`` to skip
    - L2: native wordlist + hardened crt.sh + reverse-IP neighbours (scope-distance cap)
    - L5: bounded ports + http probe + deeper tech fingerprint heuristics (``--no-fingerprint``)
    - ranker: interestingness sort + rare/admin tech boosts
    - L6: ``watch=True`` persists runs/latest.json and returns diffs (incl. tech added/removed)
    - ``no_tools=True`` (default): skip external engines (allowlist empty; hashes HOLD)
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

    # L2 CT stub — always available via injectable fetcher; live net opt-in
    if crtsh:
        inventory = merge_crtsh_into_inventory(
            inventory,
            domains,
            fetcher=crtsh_fetcher,
            network=crtsh_network and crtsh_fetcher is None,
        )

    # L1 identity lite — RDAP / MX / SPF (injectable; default on)
    if identity:
        inventory = merge_identity_into_inventory(
            inventory,
            domains,
            rdap_fetcher=rdap_fetcher,
            mx_resolver=mx_resolver,
            txt_resolver=txt_resolver,
            network=identity_network and rdap_fetcher is None,
        )

    # L2 reverse-IP neighbours — hard scope-distance cap; stub empty without fetcher
    if reverse_ip:
        inventory = merge_reverse_ip_into_inventory(
            inventory,
            fetcher=reverse_ip_fetcher,
            scope=scope,
            max_distance=int(scope_distance),
            max_results=int(reverse_ip_max_results),
            network=reverse_ip_network and reverse_ip_fetcher is None,
        )

    # no_tools: engines deferred (empty allowlist). Flag retained for honesty.
    _ = no_tools  # tools path not implemented until hashes pinned

    # L5 http probe lite + optional tech fingerprint (stdlib heuristics)
    if http_probe and (inventory.get("ports") or []):
        http_rows = probe_http_inventory(
            inventory,
            scope=scope,
            opener=http_opener,
        )
        inventory["http"] = http_rows
        if fingerprint:
            inventory = merge_tech_into_inventory(inventory, http_rows)
        else:
            inventory.setdefault("tech", [])
    else:
        inventory.setdefault("tech", [])

    inventory = normalize_inventory(inventory)

    # hard_kill before any graph write when scope is active
    if scope is not None:
        for dom in inventory.get("domains") or []:
            scope.hard_kill(dom)

    # Interestingness ranker (default sort for --json)
    if rank:
        ranked = rank_inventory(inventory)
        inventory["ranked"] = ranked
        inventory["dns_names"] = sort_dns_names_by_rank(inventory, ranked)

    events_out: list[dict[str, Any]] = []
    with open_graph(program_id) as graph:
        emitted = inventory_to_events(graph, program_id, inventory)
        for ev in emitted:
            events_out.append(
                {"id": ev.id, "type": ev.type, "payload": dict(ev.payload)}
            )

    # L0: touch program.yml layers / updated_at
    try:
        touch_program_yml_layers(program_id)
    except OSError:
        pass

    watch_result: dict[str, Any] | None = None
    if watch:
        watch_result = watch_compare_and_persist(
            program_dir(program_id), inventory
        )

    out: dict[str, Any] = {
        "program_id": program_id,
        "inventory": inventory,
        "events": events_out,
        "event_count": len(events_out),
        "scoped": scope is not None,
        "i_own_this": bool(i_own_this),
        "no_tools": bool(no_tools),
        "layers": list(PHASE_B_SLICE4_LAYERS),
    }
    if watch_result is not None:
        out["watch"] = watch_result
    return out
