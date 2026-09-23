"""Productization step 3 — README honesty (no fake metrics / no PyPI claim)."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_readme_product_story_and_free_promise():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "FREE_PROMISE" in readme
    assert "free forever" in readme.lower()
    assert "authorized" in readme.lower()
    assert "127.0.0.1:8888" in readme
    assert "sentinel ui --open" in readme
    assert "sentinel demo" in readme
    assert "sentinel full-run" in readme
    # product-complete: do not shout leftover phase/sprint hero
    head = readme.split("## Architecture", 1)[0]
    assert "Phase G0 COMPLETE" not in head
    assert "work in progress product" not in head.lower()
    assert "Sprint 0" not in head


def test_readme_no_fake_badges_or_pypi_claim():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    low = readme.lower()
    assert "shields.io/github/stars" not in low
    assert "shields.io/pypi" not in low
    assert "pypi.org/project" not in low
    assert "img.shields.io/github/downloads" not in low
    # honest: PyPI is not published
    assert "not" in low and "published" in low
    assert "unsigned" in low
    assert "004917159410226b4b88488f98142971c2679246e558d1e2111f826f167c9024" in readme


def test_readme_embeds_real_demo_assets():
    demos = REPO / "docs" / "assets" / "demos"
    for name in (
        "demo_walkthrough.mp4",
        "demo_preview.gif",
        "ui_home.png",
        "cli_walkthrough.png",
        "demo_andrax_report.md",
        "demo_sentinelreign_report.md",
    ):
        assert (demos / name).is_file(), name
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "docs/assets/demos/demo_preview.gif" in readme
    assert "docs/assets/demos/demo_walkthrough.mp4" in readme
    assert "docs/assets/demos/ui_home.png" in readme
    assert "docs/assets/demos/cli_walkthrough.png" in readme
    # honest zeros from the real run
    assert "0" in readme
    andrax = (demos / "demo_andrax_report.md").read_text(encoding="utf-8")
    reign = (demos / "demo_sentinelreign_report.md").read_text(encoding="utf-8")
    assert "Findings included: 0" in andrax
    assert "Findings included: 0" in reign


def test_install_does_not_claim_pypi_or_signed():
    install = (REPO / "docs" / "INSTALL.md").read_text(encoding="utf-8")
    low = install.lower()
    assert "not" in low and "published" in low
    assert "unsigned" in low
    assert "sentinel ui --open" in install
    assert "Phase G0 COMPLETE" not in install
