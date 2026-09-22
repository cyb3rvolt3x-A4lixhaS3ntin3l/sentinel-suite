import subprocess
import sys
from pathlib import Path


def test_doctor_exit_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    proc = subprocess.run(
        [sys.executable, "-m", "sentinel_cli.cli", "doctor"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "doctor: PASS" in proc.stdout
    assert "engines" in proc.stdout.lower()


def test_program_init(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    proc = subprocess.run(
        [sys.executable, "-m", "sentinel_cli.cli", "program", "init", "lab1"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (tmp_path / "home" / "programs" / "lab1" / "graph.sqlite").is_file()


def test_import_brief_writes_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["SENTINEL_HOME"] = str(tmp_path / "home")
    brief = tmp_path / "brief.txt"
    brief.write_text(
        """
        In Scope:
        - *.import.example
        - shop.import.example

        Out of Scope:
        - blog.import.example
        """,
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_cli.cli",
            "program",
            "import-brief",
            "imported",
            str(brief),
            "--platform",
            "h1",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    scope_path = tmp_path / "home" / "programs" / "imported" / "scope.txt"
    assert scope_path.is_file()
    text = scope_path.read_text(encoding="utf-8")
    assert "shop.import.example" in text or "*.import.example" in text
    assert "!blog.import.example" in text
    yml = (tmp_path / "home" / "programs" / "imported" / "program.yml").read_text(
        encoding="utf-8"
    )
    assert "brief_platform: h1" in yml
    assert "scope_allow_count:" in yml
