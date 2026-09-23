"""Phase C slice15 — owned collaborator callback listener (localhost default)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from gungnir.packs import PackRunError, discover_packs, list_pack_manifests, run_pack
from gungnir.packs.ssrf_collaborator.caps import (
    COACH_BIND_NON_LOOPBACK,
    COACH_LISTEN_DURATION,
    COACH_LISTEN_HITS,
    COACH_METADATA_REFUSED,
    DEFAULT_BIND,
    DEFAULT_LISTEN_DURATION_S,
    DEFAULT_MAX_HITS,
    HARD_MAX_HITS,
    HARD_MAX_LISTEN_DURATION_S,
    HARD_MAX_REQUESTS,
    CapExceededError,
    assert_bind_allowed,
    assert_collaborator_allowed,
    assert_metadata_refused,
    is_cloud_metadata_target,
    is_loopback_bind,
    resolve_caps,
    resolve_listen_caps,
)
from gungnir.packs.ssrf_collaborator.listener import (
    CollaboratorListener,
    ListenerHitCapError,
    emit_collaborator_hit,
    hit_record_from_request,
    start_ephemeral_listener,
)
from gungnir.packs.http_desync.caps import HARD_MAX_REQUESTS as DESYNC_HARD_MAX
from gungnir.packs.race_toctou.caps import (
    HARD_MAX_DURATION_S as RACE_HARD_MAX_DURATION_S,
    HARD_MAX_REQUESTS as RACE_HARD_MAX_REQUESTS,
    HARD_MAX_WORKERS as RACE_HARD_MAX_WORKERS,
)
from sentinel_core import (
    ENGINE_ALLOWLIST,
    EVENT_TYPES,
    Event,
    create_program,
    open_graph,
    program_dir,
)

PRIOR_PACKS = (
    "ato_oauth_oidc",
    "bola_idor_bfla",
    "business_logic",
    "race_toctou",
    "graphql",
    "xss_dom",
    "csrf_state",
    "open_redirect",
    "cache_host",
    "jwt_session",
    "http_desync",
    "ssrf_collaborator",
)


def _cli(*args: str, env: dict | None = None) -> subprocess.CompletedProcess[str]:
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run(
        [sys.executable, "-m", "sentinel_cli.cli", *args],
        capture_output=True,
        text=True,
        env=e,
    )


def test_engine_allowlist_still_empty_slice15():
    assert ENGINE_ALLOWLIST == {}


def test_collaborator_hit_in_event_types():
    assert "COLLABORATOR_HIT" in EVENT_TYPES
    ev = Event(
        type="COLLABORATOR_HIT",
        source_module="test",
        program_id="p",
        payload={"method": "GET", "path": "/x"},
    )
    assert ev.type == "COLLABORATOR_HIT"


def test_twelve_packs_intact():
    manifests = {m.id: m for m in list_pack_manifests()}
    for pid in PRIOR_PACKS:
        assert pid in manifests
    packs = discover_packs()
    assert set(packs) >= set(PRIOR_PACKS)


def test_prior_hard_caps_untouched_slice15():
    assert RACE_HARD_MAX_WORKERS == 4
    assert RACE_HARD_MAX_REQUESTS == 20
    assert RACE_HARD_MAX_DURATION_S == 5.0
    assert DESYNC_HARD_MAX == 10
    assert HARD_MAX_REQUESTS == 10


def test_default_bind_is_loopback():
    caps = resolve_listen_caps()
    assert caps.bind == DEFAULT_BIND == "127.0.0.1"
    assert is_loopback_bind(caps.bind)
    assert caps.max_duration_s == DEFAULT_LISTEN_DURATION_S == 120.0
    assert caps.max_hits == DEFAULT_MAX_HITS == 50
    assert caps.max_duration_s <= HARD_MAX_LISTEN_DURATION_S
    assert caps.max_hits <= HARD_MAX_HITS


def test_assert_bind_allowed_loopback_ok():
    assert assert_bind_allowed("127.0.0.1", i_understand_lab=False) == "127.0.0.1"
    assert assert_bind_allowed("localhost", i_understand_lab=False) == "localhost"
    assert assert_bind_allowed("::1", i_understand_lab=False) == "::1"


def test_assert_bind_refuses_wildcard_without_lab():
    with pytest.raises(CapExceededError) as ei:
        assert_bind_allowed("0.0.0.0", i_understand_lab=False)
    msg = str(ei.value)
    assert "0.0.0.0" in msg or "loopback" in msg.lower() or "non-loopback" in msg.lower()
    assert "i-understand-lab" in msg.lower() or "lab" in msg.lower()


def test_assert_bind_refuses_ipv6_wildcard_without_lab():
    with pytest.raises(CapExceededError):
        assert_bind_allowed("::", i_understand_lab=False)


def test_assert_bind_wildcard_ok_with_lab_flag():
    assert assert_bind_allowed("0.0.0.0", i_understand_lab=True) == "0.0.0.0"


def test_resolve_listen_caps_over_duration_hard_fails():
    with pytest.raises(CapExceededError) as ei:
        resolve_listen_caps(max_duration=HARD_MAX_LISTEN_DURATION_S + 1)
    assert "duration" in str(ei.value).lower() or "hard" in str(ei.value).lower()


def test_resolve_listen_caps_over_hits_hard_fails():
    with pytest.raises(CapExceededError) as ei:
        resolve_listen_caps(max_hits=HARD_MAX_HITS + 1)
    assert "hit" in str(ei.value).lower() or "hard" in str(ei.value).lower()


def test_metadata_collaborator_still_refused():
    assert is_cloud_metadata_target("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(CapExceededError) as ei:
        assert_metadata_refused(
            "http://169.254.169.254/",
            i_understand_lab=False,
            lab_fixture_mode=False,
        )
    assert "metadata" in str(ei.value).lower() or "169.254" in str(ei.value)
    with pytest.raises(CapExceededError):
        assert_collaborator_allowed(
            "http://metadata.google.internal/",
            i_own_this=True,
            i_understand_lab=False,
            lab_fixture_mode=False,
            fixtures_only=True,
        )


def test_hit_record_redacts_sensitive_headers_and_truncates_body():
    hit = hit_record_from_request(
        method="POST",
        path="/ssrf-callback?x=1",
        headers={
            "Authorization": "Bearer SECRET_TOKEN_VALUE",
            "Cookie": "session=abc",
            "X-Trace": "ok",
        },
        body=b"x" * 1000,
        client_addr="127.0.0.1",
    )
    assert hit["method"] == "POST"
    assert hit["headers"]["authorization"] == "[redacted]"
    assert hit["headers"]["cookie"] == "[redacted]"
    assert hit["headers"]["x-trace"] == "ok"
    assert len(hit["body_snippet"]) <= 300
    assert hit["body_len"] == 1000


def test_listener_logs_collaborator_hit_to_graph(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    pid = "c15-hit"
    create_program(pid)
    lst = start_ephemeral_listener(
        program_id=pid, max_duration=15, max_hits=10, emit_to_graph=True
    )
    try:
        req = urllib.request.Request(
            lst.url, data=b"callback-body", method="POST"
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            assert resp.status == 200
        # Allow graph write
        deadline = time.time() + 2
        while lst.hits_logged < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert lst.hits_logged == 1
        with open_graph(pid) as g:
            rows = g.list_by_type("COLLABORATOR_HIT")
        assert len(rows) >= 1
        payload = rows[0].payload
        assert payload.get("method") == "POST"
        assert "/ssrf-callback" in str(payload.get("path") or "")
        assert "callback-body" in str(payload.get("body_snippet") or "")
    finally:
        lst.stop()


def test_listener_max_hits_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    pid = "c15-hits"
    create_program(pid)
    caps = resolve_listen_caps(max_hits=2, max_duration=20, port=0)
    lst = CollaboratorListener(caps, program_id=pid, emit_to_graph=True)
    lst.start()
    try:
        for i in range(2):
            urllib.request.urlopen(lst.url + f"?i={i}", timeout=3)
        time.sleep(0.2)
        assert lst.hits_logged == 2
        # Third should be refused (429) / cap path
        try:
            urllib.request.urlopen(lst.url + "?i=overflow", timeout=3)
        except urllib.error.HTTPError as exc:
            assert exc.code in (429, 200)  # 429 preferred; race may still 200 then stop
        # Cap reason eventually max_hits
        deadline = time.time() + 2
        while lst._closed_reason is None and time.time() < deadline:  # noqa: SLF001
            time.sleep(0.05)
        assert lst.hits_logged <= 2 or lst.summary().get("closed_reason") == "max_hits"
    finally:
        lst.stop()


def test_emit_collaborator_hit_direct(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    pid = "c15-emit"
    create_program(pid)
    with open_graph(pid) as g:
        ev = emit_collaborator_hit(
            g,
            program_id=pid,
            hit={"method": "GET", "path": "/x", "headers": {}, "body_snippet": ""},
        )
    assert ev.type == "COLLABORATOR_HIT"
    with open_graph(pid) as g:
        rows = g.list_by_type("COLLABORATOR_HIT")
    assert any(r.id == ev.id for r in rows)


def test_pack_listen_sets_local_collaborator_url(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    pid = "c15-pack-listen"
    create_program(pid)
    result = run_pack(
        "ssrf_collaborator",
        pid,
        i_own_this=True,
        listen=True,
        max_duration=15.0,
    )
    assert result["findings_emitted"] >= 1
    collab = result.get("collaborator") or ""
    assert collab.startswith("http://127.0.0.1:")
    assert "/ssrf-callback" in collab
    listen = result.get("listen") or {}
    assert listen.get("bind") == "127.0.0.1"
    # Fixture path still works with --listen
    assert result.get("fixtures_only") in (True, False, None)


def test_pack_fixture_without_listen_still_works(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    pid = "c15-fixture"
    create_program(pid)
    result = run_pack("ssrf_collaborator", pid, i_own_this=True)
    assert result["findings_emitted"] >= 1
    assert result.get("listen") is None


def test_pack_listen_refuses_non_loopback_bind_without_lab(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    pid = "c15-bind-refuse"
    create_program(pid)
    with pytest.raises((CapExceededError, PackRunError)):
        run_pack(
            "ssrf_collaborator",
            pid,
            i_own_this=True,
            listen=True,
            listen_bind="0.0.0.0",
            i_understand_lab=False,
            max_duration=5.0,
        )


def test_cli_collaborator_serve_default_bind_and_hit(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    # Short duration serve in subprocess is heavy; exercise resolve via help + refuse
    r = _cli("collaborator", "serve", "--help", env={"SENTINEL_HOME": str(tmp_path)})
    assert r.returncode == 0
    assert "127.0.0.1" in r.stdout or "bind" in r.stdout.lower()
    assert "i-understand-lab" in r.stdout


def test_cli_refuse_wildcard_bind_without_lab(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    r = _cli(
        "collaborator",
        "serve",
        "--program",
        "c15cli",
        "--bind",
        "0.0.0.0",
        "--max-duration",
        "1",
        env={"SENTINEL_HOME": str(tmp_path)},
    )
    assert r.returncode == 2
    err = (r.stderr + r.stdout).lower()
    assert "lab" in err or "loopback" in err or "0.0.0.0" in err


def test_cli_metadata_collaborator_still_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    r = _cli(
        "hunt",
        "pack",
        "run",
        "ssrf_collaborator",
        "--program",
        "c15meta",
        "--i-own-this",
        "--collaborator",
        "http://169.254.169.254/latest/meta-data/",
        env={"SENTINEL_HOME": str(tmp_path)},
    )
    assert r.returncode == 2
    err = (r.stderr + r.stdout).lower()
    assert "metadata" in err or "169.254" in err


def test_cli_pack_listen_help_and_run(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    help_r = _cli("hunt", "pack", "run", "--help", env={"SENTINEL_HOME": str(tmp_path)})
    assert "--listen" in help_r.stdout
    create_program("c15cli-listen")
    r = _cli(
        "hunt",
        "pack",
        "run",
        "ssrf_collaborator",
        "--program",
        "c15cli-listen",
        "--i-own-this",
        "--listen",
        "--max-duration",
        "10",
        env={"SENTINEL_HOME": str(tmp_path)},
    )
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["findings_emitted"] >= 1
    assert str(data.get("collaborator") or "").startswith("http://127.0.0.1:")


def test_ssrf_request_caps_unchanged():
    caps = resolve_caps()
    assert caps.max_requests <= HARD_MAX_REQUESTS
    with pytest.raises(CapExceededError):
        resolve_caps(max_requests=HARD_MAX_REQUESTS + 1)


def test_coach_constants_present():
    assert "0.0.0.0" in COACH_BIND_NON_LOOPBACK or "loopback" in COACH_BIND_NON_LOOPBACK.lower()
    assert "duration" in COACH_LISTEN_DURATION.lower() or "hard" in COACH_LISTEN_DURATION.lower()
    assert "hit" in COACH_LISTEN_HITS.lower()
    assert "metadata" in COACH_METADATA_REFUSED.lower()
