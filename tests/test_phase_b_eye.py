"""Phase B slice1 — ranker, watch, crtsh stub, http probe, --json sort, scope."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from sentinel_core import ScopeDenied, create_program, open_graph, program_dir
from shadowseye.live_map import extract_title, http_probe, probe_http_inventory
from shadowseye.passive import crtsh_query, merge_crtsh_into_inventory
from shadowseye.ranker import rank_inventory, score_hostname
from shadowseye.runner import run_eye
from shadowseye.watch import (
    diff_snapshots,
    load_latest_snapshot,
    save_snapshot,
    snapshot_from_inventory,
    watch_compare_and_persist,
)


def test_ranker_staging_admin_higher_than_www():
    www_score, _ = score_hostname("www.example.com")
    staging_score, staging_reasons = score_hostname("staging.example.com")
    admin_score, admin_reasons = score_hostname("admin.example.com")
    assert staging_score > www_score
    assert admin_score > www_score
    assert any("staging" in r for r in staging_reasons)
    assert any("admin" in r for r in admin_reasons)


def test_ranker_newness_boost():
    now = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)
    recent = (now - timedelta(hours=2)).isoformat()
    old = (now - timedelta(days=30)).isoformat()
    s_new, r_new = score_hostname("api.example.com", first_seen=recent, now=now)
    s_old, _ = score_hostname("api.example.com", first_seen=old, now=now)
    assert s_new > s_old
    assert any("new:24h" in r for r in r_new)


def test_rank_inventory_sort_order():
    inv = {
        "domains": ["example.com"],
        "dns_names": [
            {"name": "www.example.com"},
            {"name": "staging.example.com"},
            {"name": "admin.example.com"},
        ],
    }
    ranked = rank_inventory(inv)
    keys = [r["key"] for r in ranked]
    assert keys[0] in ("staging.example.com", "admin.example.com")
    assert keys.index("www.example.com") > keys.index("staging.example.com")


def test_watch_first_run_empty_diffs(tmp_path):
    inv = {
        "domains": ["example.com"],
        "dns_names": [{"name": "example.com"}, {"name": "www.example.com"}],
        "ports": [{"host": "example.com", "port": 443}],
        "http": [],
    }
    result = watch_compare_and_persist(tmp_path, inv)
    assert result["diffs"]["first_run"] is True
    assert result["diffs"]["dns_names"]["added"] == []
    assert result["diffs"]["dns_names"]["removed"] == []
    assert (tmp_path / "runs" / "latest.json").is_file()


def test_watch_second_run_detects_added_dns_port(tmp_path):
    inv1 = {
        "domains": ["example.com"],
        "dns_names": [{"name": "example.com"}],
        "ports": [{"host": "example.com", "port": 80}],
        "http": [],
    }
    watch_compare_and_persist(tmp_path, inv1)
    inv2 = {
        "domains": ["example.com"],
        "dns_names": [
            {"name": "example.com"},
            {"name": "api.example.com"},
        ],
        "ports": [
            {"host": "example.com", "port": 80},
            {"host": "example.com", "port": 443},
        ],
        "http": [{"url": "https://example.com/", "status": 200}],
    }
    result = watch_compare_and_persist(tmp_path, inv2)
    assert result["diffs"]["first_run"] is False
    assert "api.example.com" in result["diffs"]["dns_names"]["added"]
    assert {"host": "example.com", "port": 443} in result["diffs"]["ports"]["added"]
    assert "https://example.com/" in result["diffs"]["http"]["added"]


def test_crtsh_mocked_returns_names_and_events(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))

    def fake_fetch(url: str, timeout: float) -> bytes:
        assert "crt.sh" in url
        payload = [
            {"name_value": "staging.example.com\nadmin.example.com"},
            {"name_value": "*.dev.example.com"},
        ]
        return json.dumps(payload).encode("utf-8")

    names = crtsh_query("example.com", fetcher=fake_fetch)
    assert "staging.example.com" in names
    assert "admin.example.com" in names
    assert "dev.example.com" in names

    result = run_eye(
        "eye-crtsh",
        ["example.com"],
        i_own_this=True,
        resolve=False,
        scan_ports=False,
        http_probe=False,
        crtsh_fetcher=fake_fetch,
        watch=False,
    )
    dns = [
        d["name"] if isinstance(d, dict) else d
        for d in result["inventory"]["dns_names"]
    ]
    assert "staging.example.com" in dns
    assert "crtsh" in (result["inventory"].get("sources") or [])
    types = {e["type"] for e in result["events"]}
    assert "DNS_NAME" in types
    assert "DOMAIN" in types


def test_http_probe_mocked_no_live_net():
    def fake_opener(url: str, timeout: float):
        html = b"<html><title>Lab Title</title></html>"
        return 200, html, url

    hit = http_probe("https://example.com/", opener=fake_opener)
    assert hit is not None
    assert hit["status"] == 200
    assert hit["title"] == "Lab Title"

    inv = {
        "ports": [{"host": "example.com", "port": 443}],
    }
    rows = probe_http_inventory(inv, opener=fake_opener)
    assert len(rows) >= 1
    assert rows[0]["status"] == 200


def test_extract_title():
    assert extract_title(b"<title> Hi </title>") == "Hi"
    assert extract_title(b"<html></html>") is None


def test_json_sorts_by_interestingness(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))

    def fake_fetch(url: str, timeout: float) -> bytes:
        return json.dumps(
            [{"name_value": "staging.lab.example\nwww.lab.example"}]
        ).encode()

    result = run_eye(
        "eye-rank",
        ["lab.example"],
        i_own_this=True,
        resolve=False,
        scan_ports=False,
        http_probe=False,
        crtsh_fetcher=fake_fetch,
    )
    ranked = result["inventory"]["ranked"]
    assert ranked
    assert ranked[0]["score"] >= ranked[-1]["score"]
    # staging should outrank www when both present
    keys = [r["key"] for r in ranked]
    if "staging.lab.example" in keys and "www.lab.example" in keys:
        assert keys.index("staging.lab.example") < keys.index("www.lab.example")
    # dns_names order follows rank
    dns_names = [
        d["name"] if isinstance(d, dict) else d
        for d in result["inventory"]["dns_names"]
    ]
    if "staging.lab.example" in dns_names and "www.lab.example" in dns_names:
        assert dns_names.index("staging.lab.example") < dns_names.index(
            "www.lab.example"
        )


def test_scope_still_enforced_phase_b(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("eye-oos")
    scope = tmp_path / "home" / "programs" / "eye-oos" / "scope.txt"
    scope.write_text("in-scope.example\n", encoding="utf-8")
    with pytest.raises(ScopeDenied):
        run_eye(
            "eye-oos",
            ["oos.example"],
            scope_path=scope,
            i_own_this=False,
            resolve=False,
            scan_ports=False,
            http_probe=False,
            crtsh=False,
        )


def test_run_eye_watch_persists_and_program_yml(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    result = run_eye(
        "eye-watch",
        ["example.com"],
        i_own_this=True,
        resolve=False,
        scan_ports=True,
        ports=[9],
        port_host_override="127.0.0.1",
        http_probe=False,
        crtsh=False,
        watch=True,
    )
    assert "watch" in result
    assert result["watch"]["diffs"]["first_run"] is True
    root = program_dir("eye-watch")
    assert (root / "runs" / "latest.json").is_file()
    yml = (root / "program.yml").read_text(encoding="utf-8")
    assert "layers_enabled:" in yml
    assert "updated_at:" in yml
    assert "L2" in yml or "L0" in yml


def test_cli_eye_json_and_watch(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    from sentinel_cli.cli import main

    rc = main(
        [
            "eye",
            "run",
            "eye-cli",
            "example.com",
            "--i-own-this",
            "--no-resolve",
            "--no-ports",
            "--no-http",
            "--no-crtsh",
            "--json",
            "--watch",
            "--no-tools",
        ]
    )
    assert rc == 0


def test_diff_snapshots_unit():
    prev = snapshot_from_inventory(
        {
            "dns_names": ["a.example.com"],
            "ports": [{"host": "a.example.com", "port": 80}],
            "http": [],
            "domains": ["example.com"],
        }
    )
    cur = snapshot_from_inventory(
        {
            "dns_names": ["a.example.com", "b.example.com"],
            "ports": [
                {"host": "a.example.com", "port": 80},
                {"host": "a.example.com", "port": 443},
            ],
            "http": ["https://a.example.com/"],
            "domains": ["example.com"],
        }
    )
    d = diff_snapshots(prev, cur)
    assert d["first_run"] is False
    assert "b.example.com" in d["dns_names"]["added"]
    assert {"host": "a.example.com", "port": 443} in d["ports"]["added"]


def test_crtsh_degrades_on_fetch_failure():
    def boom(url: str, timeout: float) -> bytes:
        raise TimeoutError("nope")

    assert crtsh_query("example.com", fetcher=boom) == []


def test_merge_crtsh_into_inventory_idempotent():
    inv = {
        "domains": ["example.com"],
        "dns_names": [{"name": "example.com", "parent": "example.com"}],
        "ips": [],
        "ports": [],
        "http": [],
        "tech": [],
        "sources": ["native"],
        "ranked": [],
    }

    def fake_fetch(url: str, timeout: float) -> bytes:
        return json.dumps([{"name_value": "example.com"}]).encode()

    out = merge_crtsh_into_inventory(inv, ["example.com"], fetcher=fake_fetch)
    names = [d["name"] for d in out["dns_names"]]
    assert names.count("example.com") == 1
