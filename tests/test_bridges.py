import pytest

from gungnir import emit_finding_event, require_scope_or_lab
from sentinel_core import ScopeDenied, create_program, open_graph
from shadowseye import emit_domain_event


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
