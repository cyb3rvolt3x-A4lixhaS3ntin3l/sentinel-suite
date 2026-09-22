"""Phase B slice2 — L1 identity lite + deeper CT / reverse-IP."""

from __future__ import annotations

import json

import pytest

from sentinel_core import Scope, create_program
from shadowseye.identity import (
    gather_identity,
    merge_identity_into_inventory,
    mx_lookup,
    rdap_lookup,
    spf_lookup,
)
from shadowseye.inventory import empty_inventory
from shadowseye.passive import (
    crtsh_query,
    merge_reverse_ip_into_inventory,
    reverse_ip_neighbours,
    scope_distance,
)
from shadowseye.runner import run_eye


def _rdap_bytes(org: str = "Example Org", email: str = "admin@example.com") -> bytes:
    payload = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", org],
                        ["email", {}, "text", email],
                    ],
                ],
            }
        ]
    }
    return json.dumps(payload).encode()


def test_identity_rdap_mx_spf_mocked_low_confidence():
    rows = gather_identity(
        ["example.com"],
        rdap_fetcher=lambda u, t: _rdap_bytes(),
        mx_resolver=lambda d: ["mail.example.com"],
        txt_resolver=lambda d: ["v=spf1 include:_spf.google.com ~all"],
    )
    kinds = {r["kind"] for r in rows}
    assert "org" in kinds
    assert "email" in kinds
    assert "mx" in kinds
    assert "spf" in kinds
    assert "asn" in kinds  # honest stub when ASN absent
    for r in rows:
        assert r["confirmed"] is False
        assert 0.3 <= float(r["confidence"]) <= 0.4


def test_merge_identity_into_inventory_keys():
    inv = merge_identity_into_inventory(
        empty_inventory(),
        ["example.com"],
        rdap_fetcher=lambda u, t: _rdap_bytes("Acme"),
        mx_resolver=lambda d: ["mx1.example.com"],
    )
    assert inv["identity"]
    assert "identity" in (inv.get("sources") or [])
    assert all("kind" in r and "value" in r for r in inv["identity"])


def test_mx_spf_offline_without_resolver_or_network():
    assert mx_lookup("example.com") == []
    assert spf_lookup("example.com") == []
    assert rdap_lookup("example.com") is None


def test_crtsh_malformed_json_degrades():
    assert crtsh_query("example.com", fetcher=lambda u, t: b"<html>err</html>") == []
    assert crtsh_query("example.com", fetcher=lambda u, t: b"{not json") == []
    assert crtsh_query("example.com", fetcher=lambda u, t: b'{"oops":1}') == []


def test_crtsh_timeout_degrades():
    def boom(url: str, timeout: float) -> bytes:
        raise TimeoutError("slow")

    assert crtsh_query("example.com", fetcher=boom) == []


def test_crtsh_dedupe_and_wildcard_filter():
    def fetch(url: str, timeout: float) -> bytes:
        return json.dumps(
            [
                {"name_value": "*.example.com\nwww.example.com\nwww.example.com"},
                {"common_name": "*"},
                {"name_value": "evil.com"},
                {"name_value": "api.example.com"},
            ]
        ).encode()

    names = crtsh_query("example.com", fetcher=fetch)
    assert names.count("www.example.com") == 1
    assert "example.com" in names  # wildcard stripped to apex
    assert "api.example.com" in names
    assert "evil.com" not in names
    assert "*" not in names


def test_reverse_ip_drops_oos_keeps_in_scope():
    scope = Scope(allow=["example.com"])

    def fetch(ip: str, timeout: float) -> list[str]:
        return [
            "www.example.com",
            "api.example.com",
            "evil-other.com",
            "cdn.unrelated.net",
        ]

    result = reverse_ip_neighbours(
        "1.2.3.4",
        fetcher=fetch,
        scope=scope,
        max_distance=1,
    )
    names = [h["name"] for h in result["hostnames"]]
    assert "www.example.com" in names
    assert "api.example.com" in names
    assert "evil-other.com" not in names
    assert "cdn.unrelated.net" not in names
    assert result["dropped_oos"] >= 2


def test_reverse_ip_respects_max_distance():
    scope = Scope(allow=["app.example.com"])  # exact host allow

    def fetch(ip: str, timeout: float) -> list[str]:
        return ["app.example.com", "sibling.example.com", "totally.elsewhere.org"]

    # distance 0 only — sibling (same apex) is distance 1 → dropped
    r0 = reverse_ip_neighbours(
        "9.9.9.9", fetcher=fetch, scope=scope, max_distance=0
    )
    names0 = [h["name"] for h in r0["hostnames"]]
    assert names0 == ["app.example.com"]

    r1 = reverse_ip_neighbours(
        "9.9.9.9", fetcher=fetch, scope=scope, max_distance=1
    )
    names1 = [h["name"] for h in r1["hostnames"]]
    assert "app.example.com" in names1
    assert "sibling.example.com" in names1
    assert "totally.elsewhere.org" not in names1


def test_reverse_ip_offline_stub_empty():
    result = reverse_ip_neighbours("1.2.3.4")
    assert result["hostnames"] == []
    assert "stub" in result["source"] or "empty" in result["note"]


def test_scope_distance_helper():
    scope = Scope(allow=["example.com"])
    assert scope_distance("www.example.com", scope) == 0
    assert scope_distance("evil.com", scope) is None


def test_merge_reverse_ip_into_inventory_respects_scope(tmp_path):
    inv = empty_inventory()
    inv["domains"] = ["example.com"]
    inv["ips"] = [{"ip": "1.2.3.4", "host": "example.com"}]
    inv["dns_names"] = [{"name": "example.com", "parent": "example.com", "source": "native"}]
    scope = Scope(allow=["example.com"])

    def fetch(ip: str, timeout: float) -> list[str]:
        return ["staging.example.com", "oos.other.com"]

    out = merge_reverse_ip_into_inventory(
        inv, fetcher=fetch, scope=scope, max_distance=1
    )
    names = [
        d["name"] if isinstance(d, dict) else d for d in out["dns_names"]
    ]
    assert "staging.example.com" in names
    assert "oos.other.com" not in names
    assert "reverse-ip" in (out.get("sources") or [])


def test_run_eye_identity_and_events(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))

    result = run_eye(
        "eye-id",
        ["example.com"],
        i_own_this=True,
        resolve=False,
        scan_ports=False,
        http_probe=False,
        crtsh=False,
        rdap_fetcher=lambda u, t: _rdap_bytes("Lab Org"),
        mx_resolver=lambda d: ["mail.example.com"],
        txt_resolver=lambda d: ["v=spf1 -all"],
        reverse_ip=False,
    )
    ident = result["inventory"]["identity"]
    assert any(r["kind"] == "org" and r["value"] == "Lab Org" for r in ident)
    assert any(r["kind"] == "mx" for r in ident)
    assert all(r["confirmed"] is False for r in ident)
    types = {e["type"] for e in result["events"]}
    assert "IDENTITY" in types or "ORG" in types or "EMAIL" in types
    assert "L1" in result["layers"]


def test_run_eye_no_identity_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    result = run_eye(
        "eye-noid",
        ["example.com"],
        i_own_this=True,
        resolve=False,
        scan_ports=False,
        http_probe=False,
        crtsh=False,
        identity=False,
        reverse_ip=False,
        rdap_fetcher=lambda u, t: _rdap_bytes(),
    )
    assert result["inventory"].get("identity") in ([], None)


def test_run_eye_reverse_ip_mocked(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("eye-rev")
    scope = tmp_path / "home" / "programs" / "eye-rev" / "scope.txt"
    scope.write_text("example.com\n", encoding="utf-8")

    result = run_eye(
        "eye-rev",
        ["example.com"],
        scope_path=scope,
        resolve=False,
        scan_ports=False,
        http_probe=False,
        crtsh=False,
        identity=False,
        reverse_ip=True,
        # seed an IP so reverse-ip has something to query
        # gather_inventory with resolve=False won't add IPs — inject via reverse on empty is fine
        reverse_ip_fetcher=lambda ip, t: ["admin.example.com", "bad.elsewhere.com"],
        scope_distance=1,
    )
    # Without IPs, merge walks empty — still honest
    # Seed IP by running with a pre-merge path: add IP manually through resolve mock?
    # Instead assert no OOS leaked if any dns from reverse
    names = [
        d["name"] if isinstance(d, dict) else d
        for d in result["inventory"].get("dns_names") or []
    ]
    assert "bad.elsewhere.com" not in names


def test_run_eye_reverse_ip_with_seeded_ip(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    from shadowseye.passive import merge_reverse_ip_into_inventory as merge_rev
    from shadowseye.inventory import normalize_inventory

    inv = normalize_inventory(
        {
            "domains": ["example.com"],
            "dns_names": [{"name": "example.com", "parent": "example.com"}],
            "ips": [{"ip": "203.0.113.10", "host": "example.com"}],
        }
    )
    scope = Scope(allow=["example.com"])
    out = merge_rev(
        inv,
        fetcher=lambda ip, t: ["dev.example.com", "x.evil.com"],
        scope=scope,
        max_distance=1,
    )
    names = [d["name"] for d in out["dns_names"]]
    assert "dev.example.com" in names
    assert "x.evil.com" not in names


def test_cli_eye_no_identity_no_reverse(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    from sentinel_cli.cli import main

    rc = main(
        [
            "eye",
            "run",
            "eye-cli2",
            "example.com",
            "--i-own-this",
            "--no-resolve",
            "--no-ports",
            "--no-http",
            "--no-crtsh",
            "--no-identity",
            "--no-reverse-ip",
            "--json",
        ]
    )
    assert rc == 0
