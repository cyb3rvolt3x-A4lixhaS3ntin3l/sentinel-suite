from sentinel_core import bin_dir, list_pinned, pin_engine, stamp_run


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
