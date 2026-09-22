"""Emit ShadowsEye-shaped inventory events into sentinel_core graph."""

from __future__ import annotations

from typing import Any

from sentinel_core import Event, EventGraph, Scope


def emit_domain_event(
    graph: EventGraph,
    *,
    program_id: str,
    domain: str,
    parents: list[str] | None = None,
    confidence: float = 0.9,
    source_module: str = "shadowseye.bridge",
) -> Event:
    """Create and insert a DOMAIN event. Does not perform DNS or recon."""
    event = Event(
        type="DOMAIN",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload={"domain": domain},
    )
    graph.insert(event)
    return event


def emit_dns_name_event(
    graph: EventGraph,
    *,
    program_id: str,
    name: str,
    parents: list[str] | None = None,
    confidence: float = 0.85,
    source_module: str = "shadowseye.bridge",
    extra: dict[str, Any] | None = None,
) -> Event:
    """DNS_NAME event (hostname / FQDN discovered via inventory)."""
    payload: dict[str, Any] = {"name": name, **(extra or {})}
    event = Event(
        type="DNS_NAME",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload=payload,
    )
    graph.insert(event)
    return event


def emit_ip_event(
    graph: EventGraph,
    *,
    program_id: str,
    ip: str,
    parents: list[str] | None = None,
    confidence: float = 0.85,
    source_module: str = "shadowseye.bridge",
    host: str | None = None,
    extra: dict[str, Any] | None = None,
) -> Event:
    """IP event. Optional host field for reverse linkage honesty."""
    payload: dict[str, Any] = {"ip": ip, **(extra or {})}
    if host:
        payload["host"] = host
    event = Event(
        type="IP",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload=payload,
    )
    graph.insert(event)
    return event


def emit_open_port_event(
    graph: EventGraph,
    *,
    program_id: str,
    host: str,
    port: int,
    service: str | None = None,
    parents: list[str] | None = None,
    confidence: float = 0.8,
    source_module: str = "shadowseye.bridge",
    extra: dict[str, Any] | None = None,
) -> Event:
    """OPEN_PORT event — host + port (+ optional service string)."""
    payload: dict[str, Any] = {"host": host, "port": int(port), **(extra or {})}
    if service:
        payload["service"] = service
    event = Event(
        type="OPEN_PORT",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload=payload,
    )
    graph.insert(event)
    return event




def emit_url_event(
    graph: EventGraph,
    *,
    program_id: str,
    url: str,
    status: int | None = None,
    title: str | None = None,
    parents: list[str] | None = None,
    confidence: float = 0.75,
    source_module: str = "shadowseye.bridge",
    extra: dict[str, Any] | None = None,
) -> Event:
    """URL event from HTTP probe (L5 lite)."""
    payload: dict[str, Any] = {"url": url, **(extra or {})}
    if status is not None:
        payload["status"] = int(status)
    if title:
        payload["title"] = title
    event = Event(
        type="URL",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload=payload,
    )
    graph.insert(event)
    return event


def scoped_emit_domain(
    graph: EventGraph,
    scope: Scope,
    *,
    program_id: str,
    domain: str,
    parents: list[str] | None = None,
    confidence: float = 0.9,
) -> Event:
    """hard_kill domain first, then emit DOMAIN."""
    scope.hard_kill(domain)
    return emit_domain_event(
        graph,
        program_id=program_id,
        domain=domain,
        parents=parents,
        confidence=confidence,
    )




def emit_identity_event(
    graph: EventGraph,
    *,
    program_id: str,
    kind: str,
    value: str,
    parents: list[str] | None = None,
    confidence: float = 0.35,
    source_module: str = "shadowseye.identity",
    extra: dict[str, Any] | None = None,
) -> Event:
    """IDENTITY (or ASN/ORG/EMAIL) event from L1 lite — low confidence until confirmed."""
    payload: dict[str, Any] = {
        "kind": kind,
        "value": value,
        "identity_kind": (extra or {}).get("identity_kind") or kind,
        "confirmed": False,
        **(extra or {}),
    }
    # Prefer typed events when kind maps cleanly
    type_map = {"asn": "ASN", "org": "ORG", "email": "EMAIL", "mx": "IDENTITY", "spf": "IDENTITY", "rdap": "IDENTITY"}
    ev_type = type_map.get(kind, "IDENTITY")
    event = Event(
        type=ev_type,
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=confidence,
        payload=payload,
    )
    graph.insert(event)
    return event


def emit_tech_event(
    graph: EventGraph,
    *,
    program_id: str,
    name: str,
    confidence: float = 0.45,
    evidence: str | None = None,
    source: str | None = None,
    url: str | None = None,
    parents: list[str] | None = None,
    source_module: str = "shadowseye.tech_fingerprint",
    extra: dict[str, Any] | None = None,
) -> Event:
    """TECH event from L5 fingerprint heuristics (low–med confidence)."""
    payload: dict[str, Any] = {"name": name, **(extra or {})}
    if evidence:
        payload["evidence"] = evidence
    if source:
        payload["source"] = source
    if url:
        payload["url"] = url
    event = Event(
        type="TECH",
        source_module=source_module,
        program_id=program_id,
        parents=list(parents or []),
        confidence=float(confidence),
        payload=payload,
    )
    graph.insert(event)
    return event


def inventory_to_events(
    graph: EventGraph,
    program_id: str,
    inventory: dict[str, Any],
) -> list[Event]:
    """
    Convert a minimal ShadowsEye-lite inventory dict into linked events.

    Expected shape (all keys optional)::

        {
          \"domains\": [\"example.com\", ...],
          \"dns_names\": [\"www.example.com\", ...] | [{\"name\": ..., \"parent\": ...}],
          \"ips\": [\"1.2.3.4\", ...] | [{\"ip\": ..., \"host\": ...}],
          \"ports\": [{\"host\": ..., \"port\": 443, \"service\": \"https?\"}, ...],
        }

    Parents are linked where obvious (dns_name → matching domain; port → ip/domain).
    Does not perform network I/O.
    """
    events: list[Event] = []
    domain_ids: dict[str, str] = {}

    for raw in inventory.get("domains") or []:
        domain = raw if isinstance(raw, str) else str(raw.get("domain", ""))
        if not domain:
            continue
        ev = emit_domain_event(graph, program_id=program_id, domain=domain)
        domain_ids[domain.lower()] = ev.id
        events.append(ev)

    def _parent_for_host(host: str) -> list[str]:
        h = host.lower().rstrip(".")
        if h in domain_ids:
            return [domain_ids[h]]
        # subdomain-of known apex
        for apex, eid in domain_ids.items():
            if h.endswith("." + apex):
                return [eid]
        return []

    for raw in inventory.get("dns_names") or []:
        if isinstance(raw, str):
            name, parent_hint = raw, None
        else:
            name = str(raw.get("name") or raw.get("dns_name") or "")
            parent_hint = raw.get("parent") or raw.get("domain")
        if not name:
            continue
        parents = []
        if parent_hint and str(parent_hint).lower() in domain_ids:
            parents = [domain_ids[str(parent_hint).lower()]]
        else:
            parents = _parent_for_host(name)
        ev = emit_dns_name_event(
            graph, program_id=program_id, name=name, parents=parents
        )
        events.append(ev)

    ip_ids: dict[str, str] = {}
    for raw in inventory.get("ips") or []:
        if isinstance(raw, str):
            ip, host = raw, None
        else:
            ip = str(raw.get("ip") or "")
            host = raw.get("host")
        if not ip:
            continue
        parents = _parent_for_host(str(host)) if host else []
        ev = emit_ip_event(
            graph, program_id=program_id, ip=ip, host=host, parents=parents
        )
        ip_ids[ip] = ev.id
        events.append(ev)

    for raw in inventory.get("ports") or []:
        if not isinstance(raw, dict):
            continue
        host = str(raw.get("host") or "")
        port = raw.get("port")
        if not host or port is None:
            continue
        service = raw.get("service")
        parents = _parent_for_host(host)
        # Prefer IP parent when inventory linked host→ip
        for ip, eid in ip_ids.items():
            # weak link: if only one IP, still prefer domain parents first
            _ = ip
        ev = emit_open_port_event(
            graph,
            program_id=program_id,
            host=host,
            port=int(port),
            service=str(service) if service else None,
            parents=parents,
        )
        events.append(ev)

    for raw in inventory.get("http") or []:
        if not isinstance(raw, dict):
            continue
        url = str(raw.get("url") or "")
        if not url:
            continue
        status = raw.get("status")
        title = raw.get("title")
        # Parent: try host extracted from url against domain_ids
        parents: list[str] = []
        try:
            from urllib.parse import urlparse

            host = (urlparse(url).hostname or "").lower()
            parents = _parent_for_host(host) if host else []
        except Exception:
            parents = []
        ev = emit_url_event(
            graph,
            program_id=program_id,
            url=url,
            status=int(status) if status is not None else None,
            title=str(title) if title else None,
            parents=parents,
        )
        events.append(ev)


    for raw in inventory.get("identity") or []:
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind") or "")
        value = str(raw.get("value") or "")
        if not kind or not value:
            continue
        # skip honest stubs that are placeholders only if value starts with stub:
        # still emit them so inventory honesty is visible on the graph
        conf = float(raw.get("confidence") or 0.35)
        domain = raw.get("domain")
        parents: list[str] = []
        if domain and str(domain).lower() in domain_ids:
            parents = [domain_ids[str(domain).lower()]]
        extra = {
            k: v
            for k, v in raw.items()
            if k not in ("kind", "value", "confidence", "source")
        }
        extra["source"] = raw.get("source")
        ev = emit_identity_event(
            graph,
            program_id=program_id,
            kind=kind,
            value=value,
            parents=parents,
            confidence=conf,
            extra=extra,
        )
        events.append(ev)


    for raw in inventory.get("tech") or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        if not name:
            continue
        conf = float(raw.get("confidence") or 0.45)
        evidence = raw.get("evidence")
        src = raw.get("source")
        url = raw.get("url")
        parents: list[str] = []
        if url:
            try:
                from urllib.parse import urlparse

                host = (urlparse(str(url)).hostname or "").lower()
                parents = _parent_for_host(host) if host else []
            except Exception:
                parents = []
        ev = emit_tech_event(
            graph,
            program_id=program_id,
            name=name,
            confidence=conf,
            evidence=str(evidence) if evidence else None,
            source=str(src) if src else None,
            url=str(url) if url else None,
            parents=parents,
        )
        events.append(ev)


    return events
