import pytest

from gungnir import (
    emit_evidence_event,
    emit_finding_event,
    emit_verified_finding,
    require_scope_or_lab,
    scoped_emit_finding,
)
from sentinel_core import ScopeDenied, create_program, load_scope_text, open_graph
from shadowseye import (
    emit_domain_event,
    inventory_to_events,
    scoped_emit_domain,
)


def test_emit_domain_and_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("bridge")
    with open_graph("bridge") as g:
        d = emit_domain_event(g, program_id="bridge", domain="example.com")
        f = emit_finding_event(
            g,
            program_id="bridge",
            title="open redirect candidate",
            parents=[d.id],
            confidence=0.4,
        )
        assert g.get(d.id).type == "DOMAIN"
        assert g.get(f.id).type == "FINDING"
        assert d.id in g.get(f.id).parents


def test_require_scope_or_lab(tmp_path):
    with pytest.raises(ScopeDenied):
        require_scope_or_lab(None, i_own_this=False)
    require_scope_or_lab(None, i_own_this=True)
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n", encoding="utf-8")
    require_scope_or_lab(scope, i_own_this=False)


def test_inventory_to_events_multiple_types(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("inv")
    inventory = {
        "domains": ["acme.example"],
        "dns_names": ["www.acme.example", "api.acme.example"],
        "ips": [{"ip": "203.0.113.10", "host": "www.acme.example"}],
        "ports": [
            {"host": "www.acme.example", "port": 443, "service": "https"},
            {"host": "api.acme.example", "port": 80},
        ],
    }
    with open_graph("inv") as g:
        events = inventory_to_events(g, "inv", inventory)
        types = {e.type for e in events}
        assert "DOMAIN" in types
        assert "DNS_NAME" in types
        assert "IP" in types
        assert "OPEN_PORT" in types
        assert len(events) >= 6
        # parent linkage: dns under domain
        domain = next(e for e in events if e.type == "DOMAIN")
        dns = next(e for e in events if e.type == "DNS_NAME")
        assert domain.id in dns.parents


def test_scoped_emit_and_verified_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("hunt")
    scope = load_scope_text("in.example\n")
    with open_graph("hunt") as g:
        d = scoped_emit_domain(g, scope, program_id="hunt", domain="in.example")
        assert d.type == "DOMAIN"
        with pytest.raises(ScopeDenied):
            scoped_emit_domain(g, scope, program_id="hunt", domain="oos.example")

        f = emit_verified_finding(
            g,
            program_id="hunt",
            title="xss candidate",
            verification="needs_human",
            host="in.example",
            scope=scope,
            parents=[d.id],
        )
        assert f.payload["verification"] == "needs_human"
        assert f.payload["verified"] is False

        ev = emit_evidence_event(
            g,
            program_id="hunt",
            summary="screenshot placeholder",
            parents=[f.id],
        )
        assert ev.type == "EVIDENCE"

        with pytest.raises(ScopeDenied):
            scoped_emit_finding(
                g, scope, program_id="hunt", title="x", host="oos.example"
            )
