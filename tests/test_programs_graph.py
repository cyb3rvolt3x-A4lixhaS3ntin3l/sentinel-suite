import os

from sentinel_core import Event, create_program, open_graph


def test_create_program_and_graph(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    root = create_program("acme")
    assert (root / "program.yml").is_file()
    assert (root / "graph.sqlite").is_file()
    assert (root / "scope.txt").is_file()

    with open_graph("acme") as g:
        ev = Event(
            type="DOMAIN",
            source_module="test",
            program_id="acme",
            payload={"domain": "example.com"},
        )
        g.insert(ev)
        got = g.get(ev.id)
        assert got is not None
        assert got.type == "DOMAIN"
        assert got.payload["domain"] == "example.com"
        listed = g.list_by_type("DOMAIN")
        assert len(listed) == 1
        child = Event(
            type="DNS_NAME",
            source_module="test",
            program_id="acme",
            parents=[],
            payload={"name": "www.example.com"},
        )
        g.insert(child)
        g.link_parents(child.id, [ev.id])
        linked = g.get(child.id)
        assert ev.id in linked.parents
