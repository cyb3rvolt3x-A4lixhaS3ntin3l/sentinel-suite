"""Phase B slice3 — L5 tech fingerprint heuristics."""

from __future__ import annotations

import pytest

from sentinel_core import Event, EventGraph, create_program, open_graph
from shadowseye.bridge import emit_tech_event, inventory_to_events
from shadowseye.live_map import http_probe, probe_http_inventory
from shadowseye.ranker import rank_inventory
from shadowseye.runner import run_eye
from shadowseye.tech_fingerprint import (
    RARE_ADMIN_TECH,
    fingerprint,
    fingerprint_http_rows,
    merge_tech_into_inventory,
)


def test_fingerprint_nginx_php_wordpress_cookies():
    hits = fingerprint(
        url="https://blog.example.com/",
        headers={
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2.0",
            "Set-Cookie": "wordpress_logged_in_abc=1; path=/",
        },
        body=b'<html><meta name="generator" content="WordPress 6.4" /></html>',
    )
    names = {h["name"] for h in hits}
    assert "nginx" in names
    assert "php" in names
    assert "wordpress" in names
    for h in hits:
        assert 0.3 <= h["confidence"] <= 0.7
        assert h["evidence"]
        assert h["source"] in {"header", "cookie", "body", "path", "meta"}


def test_fingerprint_laravel_session_and_express():
    laravel = fingerprint(
        url="https://app.example.com/",
        headers={"Set-Cookie": "laravel_session=eyJpdiI6; path=/; httponly"},
        body=b"<html></html>",
    )
    assert any(h["name"] == "laravel" for h in laravel)

    express = fingerprint(
        url="https://api.example.com/",
        headers={"X-Powered-By": "Express", "Server": "nginx"},
        body=b"{}",
    )
    names = {h["name"] for h in express}
    assert "express" in names
    assert "nginx" in names


def test_fingerprint_aspnet_iis_django_rails():
    asp = fingerprint(
        url="https://corp.example.com/",
        headers={
            "Server": "Microsoft-IIS/10.0",
            "X-Powered-By": "ASP.NET",
            "X-AspNet-Version": "4.0.30319",
        },
    )
    names = {h["name"] for h in asp}
    assert "iis" in names
    assert "asp.net" in names

    django = fingerprint(
        url="https://dj.example.com/",
        headers={"Set-Cookie": "csrftoken=abc; Path=/"},
        body=b'<input name="csrfmiddlewaretoken" />',
    )
    assert any(h["name"] == "django" for h in django)

    rails = fingerprint(
        url="https://rails.example.com/",
        headers={"Set-Cookie": "_rails_session=BAh7; path=/"},
    )
    assert any(h["name"] == "rails" for h in rails)


def test_fingerprint_graphql_jenkins_spring_path():
    gq = fingerprint(url="https://api.example.com/graphql", headers={}, body=b"{}")
    assert any(h["name"] == "graphql" for h in gq)

    jk = fingerprint(
        url="https://ci.example.com/jenkins/",
        headers={"X-Jenkins": "2.426.1", "Server": "Jetty(10.0)"},
        body=b"<html>Jenkins</html>",
    )
    assert any(h["name"] == "jenkins" for h in jk)

    spring = fingerprint(
        url="https://svc.example.com/actuator/health",
        headers={"X-Application-Context": "app:8080"},
        body=b'{"status":"UP"}',
    )
    assert any(h["name"] == "spring" for h in spring)


def test_fingerprint_react_next_jquery_cloudflare():
    hits = fingerprint(
        url="https://www.example.com/",
        headers={"Server": "cloudflare", "cf-ray": "abc-SJC"},
        body=(
            b"<html><script src='/jquery.min.js'></script>"
            b"<script id='__NEXT_DATA__' type='application/json'>{}</script>"
            b"<div data-reactroot></div></html>"
        ),
    )
    names = {h["name"] for h in hits}
    assert "cloudflare" in names
    assert "jquery" in names
    assert "next.js" in names
    assert "react" in names


def test_fingerprint_http_rows_dedupe_and_merge_inventory():
    rows = [
        {
            "url": "https://a.example.com/",
            "headers": {"Server": "nginx"},
            "body_snippet": b"<html></html>",
        },
        {
            "url": "https://a.example.com/",
            "headers": {"Server": "nginx/1.25", "X-Powered-By": "PHP/8.1"},
            "body_snippet": b"",
        },
    ]
    tech = fingerprint_http_rows(rows)
    names = [t["name"] for t in tech]
    assert names.count("nginx") == 1
    assert "php" in names

    inv = {"http": rows, "sources": ["native"], "tech": []}
    out = merge_tech_into_inventory(inv)
    assert out["tech"]
    assert "tech_fingerprint" in out["sources"]
    # bodies scrubbed
    for row in out["http"]:
        assert "body_snippet" not in row
        assert "body" not in row


def test_http_probe_4tuple_opener_feeds_fingerprint():
    def opener(url: str, timeout: float):
        return (
            200,
            b'<meta name="generator" content="WordPress 6.0" />',
            url,
            {"Server": "Apache/2.4", "Set-Cookie": "wordpress_test_cookie=1"},
        )

    hit = http_probe("https://wp.example.com/", opener=opener)
    assert hit is not None
    assert hit["headers"]["server"].startswith("Apache")
    assert "body_snippet" in hit
    tech = fingerprint_http_rows([hit])
    names = {t["name"] for t in tech}
    assert "apache" in names
    assert "wordpress" in names


def test_legacy_3tuple_opener_still_works():
    def opener(url: str, timeout: float):
        return 200, b"<html><title>Ok</title></html>", url

    hit = http_probe("https://example.com/", opener=opener)
    assert hit["status"] == 200
    assert hit["title"] == "Ok"


def test_ranker_boosts_rare_admin_tech():
    inv = {
        "domains": ["example.com"],
        "dns_names": [
            {"name": "www.example.com"},
            {"name": "ci.example.com"},
        ],
        "tech": [
            {
                "name": "jenkins",
                "confidence": 0.65,
                "evidence": "X-Jenkins",
                "source": "header",
                "url": "https://ci.example.com/",
            }
        ],
    }
    ranked = rank_inventory(inv)
    by_key = {r["key"]: r for r in ranked}
    assert by_key["ci.example.com"]["score"] > by_key["www.example.com"]["score"]
    assert any(r.startswith("tech:jenkins") for r in by_key["ci.example.com"]["reasons"])
    assert "jenkins" in RARE_ADMIN_TECH


def test_emit_tech_event_and_inventory_to_events(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    create_program("tech-emit")
    with open_graph("tech-emit") as graph:
        ev = emit_tech_event(
            graph,
            program_id="tech-emit",
            name="nginx",
            confidence=0.55,
            evidence="Server: nginx",
            source="header",
            url="https://example.com/",
        )
        assert ev.type == "TECH"
        assert ev.payload["name"] == "nginx"

    inv = {
        "domains": ["example.com"],
        "dns_names": [{"name": "example.com", "parent": "example.com"}],
        "ips": [],
        "ports": [],
        "http": [{"url": "https://example.com/", "status": 200}],
        "tech": [
            {
                "name": "nginx",
                "confidence": 0.55,
                "evidence": "Server: nginx",
                "source": "header",
                "url": "https://example.com/",
            }
        ],
    }
    with open_graph("tech-emit") as graph:
        events = inventory_to_events(graph, "tech-emit", inv)
    types = {e.type for e in events}
    assert "TECH" in types
    assert "URL" in types
    assert "DOMAIN" in types


def test_run_eye_fingerprint_mocked_emits_tech(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr("shadowseye.runner.probe_port", lambda *a, **k: True)

    def opener(url: str, timeout: float):
        return (
            200,
            b"<html><title>Lab</title></html>",
            url,
            {"Server": "nginx", "X-Powered-By": "Express"},
        )

    result = run_eye(
        "eye-fp",
        ["example.com"],
        i_own_this=True,
        resolve=False,
        scan_ports=True,
        ports=[443],
        port_host_override="127.0.0.1",
        http_probe=True,
        fingerprint=True,
        http_opener=opener,
        crtsh=False,
        identity=False,
        reverse_ip=False,
        watch=False,
    )
    tech = result["inventory"]["tech"]
    names = {t["name"] for t in tech}
    assert "nginx" in names
    assert "express" in names
    types = {e["type"] for e in result["events"]}
    assert "TECH" in types
    # body scrubbed from http inventory
    for row in result["inventory"]["http"]:
        assert "body_snippet" not in row


def test_run_eye_no_fingerprint_skips_tech(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr("shadowseye.runner.probe_port", lambda *a, **k: True)

    def opener(url: str, timeout: float):
        return 200, b"<html></html>", url, {"Server": "nginx"}

    result = run_eye(
        "eye-nofp",
        ["example.com"],
        i_own_this=True,
        resolve=False,
        scan_ports=True,
        ports=[80],
        port_host_override="127.0.0.1",
        http_probe=True,
        fingerprint=False,
        http_opener=opener,
        crtsh=False,
        identity=False,
        reverse_ip=False,
    )
    assert result["inventory"].get("tech") == []
    assert "TECH" not in {e["type"] for e in result["events"]}


def test_no_http_implies_no_fingerprint(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    result = run_eye(
        "eye-nohttp",
        ["example.com"],
        i_own_this=True,
        resolve=False,
        scan_ports=False,
        http_probe=False,
        fingerprint=True,  # ignored without http/ports
        crtsh=False,
        identity=False,
        reverse_ip=False,
    )
    assert result["inventory"].get("tech") == []


def test_cli_no_fingerprint_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    from sentinel_cli.cli import build_parser, main

    p = build_parser()
    args = p.parse_args(
        [
            "eye",
            "run",
            "x",
            "example.com",
            "--i-own-this",
            "--no-fingerprint",
            "--no-resolve",
            "--no-ports",
            "--no-http",
            "--no-crtsh",
            "--no-identity",
            "--no-reverse-ip",
        ]
    )
    assert args.no_fingerprint is True

    rc = main(
        [
            "eye",
            "run",
            "eye-cli-fp",
            "example.com",
            "--i-own-this",
            "--no-resolve",
            "--no-ports",
            "--no-http",
            "--no-crtsh",
            "--no-identity",
            "--no-reverse-ip",
            "--no-fingerprint",
            "--json",
        ]
    )
    assert rc == 0


def test_tech_event_schema_accepts_tech_type():
    ev = Event(
        type="TECH",
        source_module="test",
        program_id="p",
        confidence=0.5,
        payload={"name": "nginx"},
    )
    assert ev.type == "TECH"
