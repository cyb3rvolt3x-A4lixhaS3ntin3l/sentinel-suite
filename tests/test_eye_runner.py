import pytest

from sentinel_core import ScopeDenied, create_program, open_graph
from shadowseye.runner import gather_inventory, require_scope_or_lab, run_eye


def test_eye_require_scope_or_lab(tmp_path):
    with pytest.raises(ScopeDenied):
        require_scope_or_lab(None, i_own_this=False)
    require_scope_or_lab(None, i_own_this=True)
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n", encoding="utf-8")
    require_scope_or_lab(scope, i_own_this=False)


def test_eye_runner_emits_into_graph(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    # Lab: example.com / 127.0.0.1 only with i_own_this; skip real DNS noise
    result = run_eye(
        "eye-lab",
        ["example.com"],
        i_own_this=True,
        resolve=False,
        scan_ports=True,
        port_host_override="127.0.0.1",
        ports=[9],  # discard port — usually closed; still exercises probe
        wordlist_path=None,
    )
    assert result["program_id"] == "eye-lab"
    assert result["event_count"] >= 1
    assert "example.com" in result["inventory"]["domains"]
    with open_graph("eye-lab") as g:
        # At least a DOMAIN event
        # EventGraph API: use get via emitted ids
        types = {e["type"] for e in result["events"]}
        assert "DOMAIN" in types
        assert "DNS_NAME" in types
        for e in result["events"]:
            assert g.get(e["id"]) is not None


def test_eye_runner_scope_hard_kill(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("eye-scoped")
    scope = tmp_path / "home" / "programs" / "eye-scoped" / "scope.txt"
    scope.write_text("in-scope.example\n", encoding="utf-8")
    with pytest.raises(ScopeDenied):
        run_eye(
            "eye-scoped",
            ["oos.example"],
            scope_path=scope,
            i_own_this=False,
            resolve=False,
            scan_ports=False,
        )


def test_gather_inventory_no_network_lab():
    inv = gather_inventory(
        ["lab.example"],
        wordlist=["www"],
        ports=[],
        resolve=False,
        scan_ports=False,
    )
    assert inv["domains"] == ["lab.example"]
    names = [d["name"] if isinstance(d, dict) else d for d in inv["dns_names"]]
    assert "lab.example" in names
    assert "www.lab.example" in names
