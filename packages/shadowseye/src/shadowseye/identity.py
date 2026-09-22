"""L1 Identity lite — RDAP / ASN / MX / SPF as low-confidence public-data signals.

Public Whois/RDAP + DNS only. No username stalking (sherlock/maigret).
All HTTP/DNS accessors are injectable; live network is opt-in via ``network=True``.
Until DNS/cert confirms, entries stay ``confirmed: false`` with confidence ~0.3–0.4.
"""

from __future__ import annotations

import json
import random
import socket
import struct
from typing import Any, Callable, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen

# (url, timeout) -> bytes
Fetcher = Callable[[str, float], bytes]
# domain -> MX hostnames
MxResolver = Callable[[str], list[str]]
# domain -> TXT record strings
TxtResolver = Callable[[str], list[str]]

CONF_RDAP = 0.35
CONF_ASN = 0.35
CONF_MX = 0.40
CONF_SPF = 0.35


def _default_fetcher(url: str, timeout: float) -> bytes:
    req = Request(url, headers={"User-Agent": "sentinel-suite-shadowseye/0.1"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — intentional opt-in net
        return resp.read(512_000)


def _encode_dns_name(name: str) -> bytes:
    out = b""
    for part in name.strip(".").lower().split("."):
        label = part.encode("ascii", errors="ignore")
        if not label or len(label) > 63:
            continue
        out += bytes([len(label)]) + label
    return out + b"\x00"


def _decode_dns_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    seen = 0
    while offset < len(buf) and seen < 64:
        seen += 1
        length = buf[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(buf):
                break
            ptr = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                end = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        if offset + length > len(buf):
            break
        labels.append(buf[offset : offset + length].decode("ascii", errors="ignore"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels).lower().rstrip("."), end


def dns_query_udp(
    domain: str,
    qtype: int,
    *,
    nameserver: str = "8.8.8.8",
    timeout: float = 3.0,
    port: int = 53,
) -> bytes | None:
    """Minimal DNS-over-UDP. Returns raw response or None. Tests should inject resolvers."""
    apex = (domain or "").strip().lower().rstrip(".")
    if not apex:
        return None
    tid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    packet = header + _encode_dns_name(apex) + struct.pack("!HH", qtype, 1)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(packet, (nameserver, port))
            data, _ = sock.recvfrom(4096)
            return data
        finally:
            sock.close()
    except OSError:
        return None


def parse_mx_answers(response: bytes) -> list[str]:
    """Best-effort MX exchange hostnames from a DNS response."""
    if not response or len(response) < 12:
        return []
    try:
        _tid, _flags, qdcount, ancount, _ns, _ar = struct.unpack(
            "!HHHHHH", response[:12]
        )
    except struct.error:
        return []
    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_dns_name(response, offset)
        offset += 4
        if offset > len(response):
            return []
    hosts: list[str] = []
    seen: set[str] = set()
    for _ in range(ancount):
        _, offset = _decode_dns_name(response, offset)
        if offset + 10 > len(response):
            break
        rtype, _cls, _ttl, rdlength = struct.unpack(
            "!HHIH", response[offset : offset + 10]
        )
        offset += 10
        rdata_start = offset
        rdata = response[offset : offset + rdlength]
        offset += rdlength
        if rtype != 15 or len(rdata) < 3:
            continue
        # MX exchange name may use message-level compression pointers
        exchange, _ = _decode_dns_name(response, rdata_start + 2)
        host = exchange.lower().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def parse_txt_answers(response: bytes) -> list[str]:
    """Best-effort TXT strings from a DNS response."""
    if not response or len(response) < 12:
        return []
    try:
        _tid, _flags, qdcount, ancount, _ns, _ar = struct.unpack(
            "!HHHHHH", response[:12]
        )
    except struct.error:
        return []
    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_dns_name(response, offset)
        offset += 4
        if offset > len(response):
            return []
    texts: list[str] = []
    for _ in range(ancount):
        _, offset = _decode_dns_name(response, offset)
        if offset + 10 > len(response):
            break
        rtype, _cls, _ttl, rdlength = struct.unpack(
            "!HHIH", response[offset : offset + 10]
        )
        offset += 10
        rdata = response[offset : offset + rdlength]
        offset += rdlength
        if rtype != 16:
            continue
        i = 0
        chunks: list[str] = []
        while i < len(rdata):
            ln = rdata[i]
            i += 1
            chunks.append(rdata[i : i + ln].decode("utf-8", errors="replace"))
            i += ln
        if chunks:
            texts.append("".join(chunks))
    return texts


def mx_lookup(
    domain: str,
    *,
    resolver: MxResolver | None = None,
    network: bool = False,
) -> list[str]:
    """MX hostnames. Prefer injectable ``resolver``; live DNS only if ``network=True``."""
    apex = (domain or "").strip().lower().rstrip(".")
    if not apex:
        return []
    if resolver is not None:
        try:
            return [h.strip().lower().rstrip(".") for h in (resolver(apex) or []) if h]
        except Exception:  # noqa: BLE001
            return []
    if not network:
        return []
    try:
        raw = dns_query_udp(apex, 15)
        return parse_mx_answers(raw) if raw else []
    except Exception:  # noqa: BLE001
        return []


def spf_lookup(
    domain: str,
    *,
    resolver: TxtResolver | None = None,
    network: bool = False,
) -> list[str]:
    """SPF TXT records (``v=spf1…``). Injectable resolver; live only with ``network=True``."""
    apex = (domain or "").strip().lower().rstrip(".")
    if not apex:
        return []
    records: list[str] = []
    if resolver is not None:
        try:
            records = list(resolver(apex) or [])
        except Exception:  # noqa: BLE001
            return []
    elif network:
        try:
            raw = dns_query_udp(apex, 16)
            records = parse_txt_answers(raw) if raw else []
        except Exception:  # noqa: BLE001
            return []
    else:
        return []
    return [r for r in records if str(r).strip().lower().startswith("v=spf1")]


def rdap_lookup(
    domain: str,
    *,
    fetcher: Fetcher | None = None,
    network: bool = False,
    timeout: float = 8.0,
) -> dict[str, Any] | None:
    """
    Public RDAP domain lookup via rdap.org.

    Returns parsed JSON dict or None. Injectable fetcher; live net opt-in.
    """
    apex = (domain or "").strip().lower().rstrip(".")
    if not apex:
        return None
    url = f"https://rdap.org/domain/{apex}"
    fetch = fetcher
    if fetch is None:
        if not network:
            return None
        fetch = _default_fetcher
    try:
        raw = fetch(url, timeout)
    except (URLError, TimeoutError, OSError, ValueError):
        return None
    except Exception:  # noqa: BLE001
        return None
    if not raw:
        return None
    try:
        text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw)
        data = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, AttributeError):
        return None
    return data if isinstance(data, dict) else None


def _vcard_fn(vcard: Any) -> str | None:
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    props = vcard[1]
    if not isinstance(props, list):
        return None
    for item in props:
        if isinstance(item, list) and len(item) >= 4 and str(item[0]).lower() == "fn":
            val = str(item[3]).strip()
            return val or None
    return None


def _rdap_org_name(rdap: dict[str, Any]) -> str | None:
    for ent in rdap.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        name = _vcard_fn(ent.get("vcardArray"))
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if name and (
            "registrant" in roles
            or "registrar" in roles
            or "administrative" in roles
            or not roles
        ):
            return name
    return None


def _rdap_emails(rdap: dict[str, Any]) -> list[str]:
    emails: list[str] = []
    seen: set[str] = set()

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            vcard = obj.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if (
                        isinstance(item, list)
                        and len(item) >= 4
                        and str(item[0]).lower() == "email"
                    ):
                        em = str(item[3]).strip().lower()
                        if em and em not in seen:
                            seen.add(em)
                            emails.append(em)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(rdap)
    return emails


def _rdap_asn(rdap: dict[str, Any]) -> str | None:
    """ASN from RDAP entities when present (often absent on domain RDAP)."""
    for ent in rdap.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        handle = str(ent.get("handle") or "")
        if handle.upper().startswith("AS") and handle[2:].isdigit():
            return handle.upper()
        for pid in ent.get("publicIds") or []:
            if not isinstance(pid, dict):
                continue
            if str(pid.get("type") or "").lower() in ("asn", "autnum"):
                ident = str(pid.get("identifier") or "").strip()
                if ident:
                    return ident if ident.upper().startswith("AS") else f"AS{ident}"
    for key in ("network", "networks"):
        net = rdap.get(key)
        if isinstance(net, dict):
            start = net.get("startAutnum") or net.get("handle")
            if start:
                s = str(start)
                return s if s.upper().startswith("AS") else f"AS{s}"
        if isinstance(net, list):
            for item in net:
                if isinstance(item, dict) and item.get("startAutnum"):
                    s = str(item["startAutnum"])
                    return s if s.upper().startswith("AS") else f"AS{s}"
    return None


def identity_entry(
    kind: str,
    value: str,
    *,
    confidence: float,
    source: str,
    confirmed: bool = False,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Canonical inventory identity row."""
    row: dict[str, Any] = {
        "kind": kind,
        "value": value,
        "confidence": float(confidence),
        "source": source,
        "confirmed": bool(confirmed),
    }
    if extra:
        row.update(extra)
    return row


def gather_identity(
    domains: Sequence[str],
    *,
    rdap_fetcher: Fetcher | None = None,
    mx_resolver: MxResolver | None = None,
    txt_resolver: TxtResolver | None = None,
    network: bool = False,
    rdap_timeout: float = 8.0,
) -> list[dict[str, Any]]:
    """
    Collect low-confidence identity signals for apex domains.

    Public-data only (RDAP / MX / SPF). No sherlock/maigret/username stalk.
    """
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(
        kind: str,
        value: str,
        confidence: float,
        source: str,
        **extra: Any,
    ) -> None:
        val = (value or "").strip()
        if not val:
            return
        key = (kind, val.lower())
        if key in seen:
            return
        seen.add(key)
        entries.append(
            identity_entry(
                kind,
                val,
                confidence=confidence,
                source=source,
                confirmed=False,
                extra=extra or None,
            )
        )

    for raw in domains:
        apex = raw.strip().lower().rstrip(".")
        if not apex:
            continue

        want_rdap = rdap_fetcher is not None or network
        if want_rdap:
            rdap = rdap_lookup(
                apex,
                fetcher=rdap_fetcher,
                network=network and rdap_fetcher is None,
                timeout=rdap_timeout,
            )
            if rdap:
                org = _rdap_org_name(rdap)
                if org:
                    add(
                        "org",
                        org,
                        CONF_RDAP,
                        "rdap",
                        domain=apex,
                        identity_kind="rdap",
                    )
                for em in _rdap_emails(rdap):
                    add(
                        "email",
                        em,
                        CONF_RDAP,
                        "rdap",
                        domain=apex,
                        identity_kind="rdap",
                    )
                asn = _rdap_asn(rdap)
                if asn:
                    add(
                        "asn",
                        asn,
                        CONF_ASN,
                        "rdap",
                        domain=apex,
                        identity_kind="asn",
                    )
                else:
                    add(
                        "asn",
                        "stub:asn-unavailable",
                        CONF_ASN,
                        "rdap-stub",
                        domain=apex,
                        identity_kind="asn",
                        note=(
                            "ASN not present on domain RDAP; "
                            "confirm via IP/network RDAP later"
                        ),
                    )

        for mx in mx_lookup(apex, resolver=mx_resolver, network=network):
            add("mx", mx, CONF_MX, "dns-mx", domain=apex, identity_kind="mx")

        for spf in spf_lookup(apex, resolver=txt_resolver, network=network):
            add("spf", spf, CONF_SPF, "dns-txt", domain=apex, identity_kind="spf")

    return entries


def merge_identity_into_inventory(
    inventory: dict[str, Any],
    domains: Sequence[str],
    *,
    rdap_fetcher: Fetcher | None = None,
    mx_resolver: MxResolver | None = None,
    txt_resolver: TxtResolver | None = None,
    network: bool = False,
    rdap_timeout: float = 8.0,
) -> dict[str, Any]:
    """Append identity rows + source labels into inventory."""
    from shadowseye.inventory import merge_sources, normalize_inventory

    inv = normalize_inventory(inventory)
    rows = gather_identity(
        domains,
        rdap_fetcher=rdap_fetcher,
        mx_resolver=mx_resolver,
        txt_resolver=txt_resolver,
        network=network,
        rdap_timeout=rdap_timeout,
    )
    existing = list(inv.get("identity") or [])
    seen = {
        (str(r.get("kind")), str(r.get("value")).lower())
        for r in existing
        if isinstance(r, dict)
    }
    for row in rows:
        key = (str(row["kind"]), str(row["value"]).lower())
        if key in seen:
            continue
        seen.add(key)
        existing.append(row)
    inv["identity"] = existing
    if rows:
        sources = {str(r.get("source") or "identity") for r in rows}
        inv = merge_sources(inv, "identity", *sorted(s for s in sources if s))
    return inv
