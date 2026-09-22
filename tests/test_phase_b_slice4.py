"""Phase B slice4 — deeper L5 fingerprints + L6 tech diffs."""

from __future__ import annotations

import json

from sentinel_core import ENGINE_ALLOWLIST, create_program, program_dir
from shadowseye.ranker import rank_inventory
from shadowseye.runner import PHASE_B_SLICE4_LAYERS, run_eye
from shadowseye.tech_fingerprint import (
    RARE_ADMIN_TECH,
    fingerprint,
    fingerprint_http_rows,
)
from shadowseye.watch import (
    diff_snapshots,
    snapshot_from_inventory,
    watch_compare_and_persist,
)


def test_fingerprint_tomcat_jira_confluence():
    tomcat = fingerprint(
        url="https://app.example.com/manager/html",
        headers={"Server": "Apache-Coyote/1.1"},
        body=b"<html>Apache Tomcat</html>",
    )
    assert any(h["name"] == "tomcat" for h in tomcat)

    jira = fingerprint(
        url="https://jira.example.com/secure/Dashboard.jspa",
        headers={"Set-Cookie": "atlassian.xsrf.token=BW8E; Path=/"},
        body=b"<html>Atlassian Jira</html>",
    )
    assert any(h["name"] == "jira" for h in jira)

    conf = fingerprint(
        url="https://wiki.example.com/wiki/spaces/ENG",
        headers={},
        body=b"<html>com.atlassian.confluence</html>",
    )
    assert any(h["name"] == "confluence" for h in conf)


def test_fingerprint_grafana_kibana_vercel_netlify():
    grafana = fingerprint(
        url="https://metrics.example.com/grafana/",
        headers={"Set-Cookie": "grafana_session=abc; Path=/"},
        body=b"<html>Grafana</html>",
    )
    assert any(h["name"] == "grafana" for h in grafana)

    kibana = fingerprint(
        url="https://logs.example.com/app/kibana",
        headers={"kbn-name": "kibana", "kbn-version": "8.11.0"},
        body=b"{}",
    )
    assert any(h["name"] == "kibana" for h in kibana)

    vercel = fingerprint(
        url="https://app.example.com/",
        headers={"Server": "Vercel", "x-vercel-id": "sfo1::abc"},
        body=b"<html></html>",
    )
    assert any(h["name"] == "vercel" for h in vercel)

    netlify = fingerprint(
        url="https://site.example.com/",
        headers={"Server": "Netlify", "x-nf-request-id": "01ABC"},
        body=b"<html></html>",
    )
    assert any(h["name"] == "netlify" for h in netlify)


def test_fingerprint_shopify_magento_drupal_joomla_cookies():
    shopify = fingerprint(
        url="https://store.example.com/",
        headers={
            "X-ShopId": "12345",
            "Set-Cookie": "_shopify_y=1; path=/",
        },
        body=b'<script src="https://cdn.shopify.com/s/files/1.js"></script>',
    )
    assert any(h["name"] == "shopify" for h in shopify)

    magento = fingerprint(
        url="https://shop.example.com/",
        headers={"X-Magento-Cache-Debug": "MISS", "Set-Cookie": "mage-cache-storage=1"},
        body=b'<link href="/static/version169/frontend/css.css" />',
    )
    assert any(h["name"] == "magento" for h in magento)

    drupal = fingerprint(
        url="https://cms.example.com/",
        headers={"X-Drupal-Cache": "HIT", "X-Generator": "Drupal 10"},
        body=b"<script>drupalSettings={}</script><path>/sites/default/files</path>",
    )
    assert any(h["name"] == "drupal" for h in drupal)

    joomla = fingerprint(
        url="https://cms.example.com/",
        headers={"Set-Cookie": "joomla_user_state=logged_in; path=/"},
        body=b'<meta name="generator" content="Joomla! 4.0" />',
    )
    assert any(h["name"] == "joomla" for h in joomla)


def test_fingerprint_flask_fastapi_gin_wp_json():
    flask = fingerprint(
        url="https://api.example.com/",
        headers={"Server": "Werkzeug/3.0.0 Python/3.12"},
        body=b"OK",
    )
    assert any(h["name"] == "flask" for h in flask)

    fastapi = fingerprint(
        url="https://api.example.com/docs",
        headers={"Server": "uvicorn"},
        body=b"<html>fastapi swagger</html>",
    )
    names = {h["name"] for h in fastapi}
    assert "uvicorn" in names
    assert "fastapi" in names

    gin = fingerprint(
        url="https://api.example.com/",
        headers={"Server": "gin"},
        body=b"gin-gonic",
    )
    assert any(h["name"] == "gin" for h in gin)

    wp = fingerprint(
        url="https://blog.example.com/wp-json/wp/v2/posts",
        headers={"Server": "nginx"},
        body=b'[{"id":1}]',
    )
    assert any(h["name"] == "wordpress" for h in wp)


def test_fingerprint_git_exposure_clue_low_conf_no_probe():
    """Fingerprint-only: clue already in fetched URL/body — no /.git fetch."""
    via_url = fingerprint(
        url="https://example.com/.git/HEAD",
        headers={"Content-Type": "text/plain"},
        body=b"ref: refs/heads/main\n",
    )
    hit = next(h for h in via_url if h["name"] == "git-exposure")
    assert hit["confidence"] <= 0.45
    assert hit["source"] in {"path", "body"}

    via_body = fingerprint(
        url="https://example.com/backup.txt",
        headers={},
        body=b"ref: refs/heads/develop\n",
    )
    assert any(h["name"] == "git-exposure" for h in via_body)
    assert "git-exposure" in RARE_ADMIN_TECH


def test_fingerprint_confidence_bands_honest():
    hits = fingerprint(
        url="https://ci.example.com/jenkins/",
        headers={"X-Jenkins": "2.426", "Server": "Jetty"},
        body=b"Jenkins Hudson",
    )
    for h in hits:
        assert 0.35 <= h["confidence"] <= 0.70
        assert h["evidence"]
        assert h["source"] in {"header", "cookie", "body", "path", "meta"}


def test_snapshot_includes_tech_keys():
    inv = {
        "domains": ["example.com"],
        "dns_names": [{"name": "example.com"}],
        "ports": [],
        "http": [],
        "tech": [
            {"name": "nginx", "confidence": 0.55, "evidence": "Server", "source": "header"},
            {"name": "jenkins", "confidence": 0.65, "evidence": "X-Jenkins", "source": "header"},
        ],
    }
    snap = snapshot_from_inventory(inv, ts="2026-09-22T10:00:00+00:00")
    assert snap["tech"] == ["jenkins", "nginx"]


def test_diff_snapshots_tech_added_removed():
    prev = snapshot_from_inventory(
        {
            "dns_names": ["example.com"],
            "ports": [],
            "http": [],
            "tech": [{"name": "nginx"}],
        },
        ts="t1",
    )
    cur = snapshot_from_inventory(
        {
            "dns_names": ["example.com"],
            "ports": [],
            "http": [],
            "tech": [{"name": "nginx"}, {"name": "grafana"}, {"name": "jira"}],
        },
        ts="t2",
    )
    d = diff_snapshots(prev, cur)
    assert d["first_run"] is False
    assert "grafana" in d["tech"]["added"]
    assert "jira" in d["tech"]["added"]
    assert d["tech"]["removed"] == []

    cur2 = snapshot_from_inventory(
        {
            "dns_names": ["example.com"],
            "ports": [],
            "http": [],
            "tech": [{"name": "grafana"}],
        },
        ts="t3",
    )
    d2 = diff_snapshots(cur, cur2)
    assert "nginx" in d2["tech"]["removed"]
    assert "jira" in d2["tech"]["removed"]
    assert d2["tech"]["added"] == []


def test_watch_second_run_detects_new_tech(tmp_path):
    inv1 = {
        "domains": ["example.com"],
        "dns_names": [{"name": "example.com"}],
        "ports": [{"host": "example.com", "port": 443}],
        "http": [{"url": "https://example.com/"}],
        "tech": [{"name": "nginx", "confidence": 0.55, "evidence": "Server", "source": "header"}],
    }
    r1 = watch_compare_and_persist(tmp_path, inv1)
    assert r1["diffs"]["first_run"] is True
    assert r1["diffs"]["tech"]["added"] == []

    inv2 = {
        "domains": ["example.com"],
        "dns_names": [{"name": "example.com"}],
        "ports": [{"host": "example.com", "port": 443}],
        "http": [{"url": "https://example.com/"}],
        "tech": [
            {"name": "nginx", "confidence": 0.55, "evidence": "Server", "source": "header"},
            {
                "name": "grafana",
                "confidence": 0.55,
                "evidence": "grafana_session",
                "source": "cookie",
                "url": "https://example.com/",
            },
        ],
    }
    r2 = watch_compare_and_persist(tmp_path, inv2)
    assert r2["diffs"]["first_run"] is False
    assert "grafana" in r2["diffs"]["tech"]["added"]
    assert "nginx" not in r2["diffs"]["tech"]["added"]

    latest = json.loads((tmp_path / "runs" / "latest.json").read_text(encoding="utf-8"))
    assert "grafana" in latest["tech"]
    assert "nginx" in latest["tech"]


def test_run_eye_watch_tech_diff_second_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr("shadowseye.runner.probe_port", lambda *a, **k: True)

    def opener_nginx(url: str, timeout: float):
        return 200, b"<html></html>", url, {"Server": "nginx"}

    r1 = run_eye(
        "eye-tech-watch",
        ["example.com"],
        i_own_this=True,
        resolve=False,
        scan_ports=True,
        ports=[443],
        port_host_override="127.0.0.1",
        http_probe=True,
        fingerprint=True,
        http_opener=opener_nginx,
        crtsh=False,
        identity=False,
        reverse_ip=False,
        watch=True,
    )
    assert r1["watch"]["diffs"]["first_run"] is True
    assert "nginx" in {t["name"] for t in r1["inventory"]["tech"]}

    def opener_grafana(url: str, timeout: float):
        return (
            200,
            b"<html>Grafana dashboard</html>",
            url,
            {"Server": "nginx", "Set-Cookie": "grafana_session=xyz; Path=/"},
        )

    r2 = run_eye(
        "eye-tech-watch",
        ["example.com"],
        i_own_this=True,
        resolve=False,
        scan_ports=True,
        ports=[443],
        port_host_override="127.0.0.1",
        http_probe=True,
        fingerprint=True,
        http_opener=opener_grafana,
        crtsh=False,
        identity=False,
        reverse_ip=False,
        watch=True,
    )
    assert r2["watch"]["diffs"]["first_run"] is False
    assert "grafana" in r2["watch"]["diffs"]["tech"]["added"]
    assert set(PHASE_B_SLICE4_LAYERS) <= set(r2["layers"])


def test_ranker_boosts_new_rare_admin_tech():
    inv = {
        "domains": ["example.com"],
        "dns_names": [
            {"name": "www.example.com"},
            {"name": "metrics.example.com"},
        ],
        "tech": [
            {
                "name": "grafana",
                "confidence": 0.55,
                "evidence": "grafana_session",
                "source": "cookie",
                "url": "https://metrics.example.com/",
            }
        ],
    }
    ranked = rank_inventory(inv)
    by_key = {r["key"]: r for r in ranked}
    assert by_key["metrics.example.com"]["score"] > by_key["www.example.com"]["score"]
    assert any(r.startswith("tech:grafana") for r in by_key["metrics.example.com"]["reasons"])


def test_engine_allowlist_still_empty():
    assert ENGINE_ALLOWLIST == {}


def test_fingerprint_http_rows_new_stacks_dedupe():
    rows = [
        {
            "url": "https://a.example.com/",
            "headers": {"Server": "Vercel", "x-vercel-id": "1"},
            "body_snippet": b"",
        },
        {
            "url": "https://a.example.com/",
            "headers": {"Server": "Vercel", "X-ShopId": "9"},
            "body_snippet": b"cdn.shopify.com",
        },
    ]
    tech = fingerprint_http_rows(rows)
    names = [t["name"] for t in tech]
    assert names.count("vercel") == 1
    assert "shopify" in names
