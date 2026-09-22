from sentinel_core import (
    bin_dir,
    detect_engine,
    ensure_engine,
    list_pinned,
    pin_engine,
    stamp_run,
)


def test_engine_pin(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    b = bin_dir()
    assert b.is_dir()
    pin_engine("httpx", "1.6.0")
    pinned = list_pinned()
    assert pinned["httpx"]["version"] == "1.6.0"
    rec = stamp_run("httpx")
    assert rec["version"] == "1.6.0"
    assert (b / "run_stamps.jsonl").is_file()


def test_detect_engine_finds_known_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    # `true` or `python3` should be on PATH in CI/dev boxes
    found = detect_engine("true") or detect_engine("python3") or detect_engine("python")
    assert found is not None
    assert found["path"]
    assert found["source"] in ("path", "bin_dir")


def test_ensure_engine_missing_and_download_deferred(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    missing = ensure_engine("definitely-not-a-real-engine-zzz", download=False)
    assert missing["status"] == "missing"
    deferred = ensure_engine("definitely-not-a-real-engine-zzz", download=True)
    assert deferred["status"] == "download_deferred"
    assert "deferred" in deferred["message"].lower() or "detect+stamp" in deferred["message"]
