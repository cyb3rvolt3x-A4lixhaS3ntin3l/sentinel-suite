"""L6 Watch diffs MVP — persist run snapshots and emit added/removed diffs."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def runs_dir(program_root: Path) -> Path:
    d = Path(program_root) / "runs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def snapshot_from_inventory(inventory: dict[str, Any], *, ts: str | None = None) -> dict[str, Any]:
    """Build a comparable snapshot dict from inventory."""
    dns: list[str] = []
    for raw in inventory.get("dns_names") or []:
        if isinstance(raw, str):
            name = raw.strip().lower().rstrip(".")
        else:
            name = str(raw.get("name") or "").strip().lower().rstrip(".")
        if name:
            dns.append(name)
    ports: list[dict[str, Any]] = []
    for raw in inventory.get("ports") or []:
        if not isinstance(raw, dict):
            continue
        host = str(raw.get("host") or "").strip().lower().rstrip(".")
        try:
            port = int(raw.get("port"))
        except (TypeError, ValueError):
            continue
        if host:
            ports.append({"host": host, "port": port})
    http_urls: list[str] = []
    for raw in inventory.get("http") or []:
        if isinstance(raw, dict) and raw.get("url"):
            http_urls.append(str(raw["url"]))
        elif isinstance(raw, str):
            http_urls.append(raw)

    return {
        "ts": ts or _utcnow_iso(),
        "dns_names": sorted(set(dns)),
        "ports": sorted(ports, key=lambda p: (p["host"], p["port"])),
        "http": sorted(set(http_urls)),
        "domains": sorted(
            {
                (d if isinstance(d, str) else str(d.get("domain") or "")).strip().lower().rstrip(".")
                for d in (inventory.get("domains") or [])
                if (d if isinstance(d, str) else d.get("domain"))
            }
        ),
        "identity": sorted(
            {
                f"{r.get('kind')}:{r.get('value')}"
                for r in (inventory.get("identity") or [])
                if isinstance(r, dict) and r.get("kind") and r.get("value")
            }
        ),
    }


def load_latest_snapshot(program_root: Path) -> dict[str, Any] | None:
    path = runs_dir(program_root) / "latest.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def save_snapshot(program_root: Path, snapshot: dict[str, Any]) -> Path:
    """
    Write ``runs/latest.json`` and a timestamped history copy under ``runs/history/``.
    """
    root = runs_dir(program_root)
    history = root / "history"
    history.mkdir(parents=True, exist_ok=True)
    latest = root / "latest.json"
    text = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
    latest.write_text(text, encoding="utf-8")
    ts = str(snapshot.get("ts") or _utcnow_iso()).replace(":", "").replace("+", "p")
    hist_name = f"{ts}.json"
    # Keep filename filesystem-safe
    hist_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in hist_name)
    hist_path = history / hist_name
    hist_path.write_text(text, encoding="utf-8")
    return latest


def diff_snapshots(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
) -> dict[str, Any]:
    """
    Compare snapshots. First run (previous is None) → honest empty diffs.

    Emits added/removed for dns_names, ports, http.
    """
    empty = {
        "first_run": previous is None,
        "previous_ts": (previous or {}).get("ts"),
        "current_ts": current.get("ts"),
        "dns_names": {"added": [], "removed": []},
        "ports": {"added": [], "removed": []},
        "http": {"added": [], "removed": []},
    }
    if previous is None:
        return empty

    prev_dns = set(previous.get("dns_names") or [])
    cur_dns = set(current.get("dns_names") or [])
    empty["dns_names"] = {
        "added": sorted(cur_dns - prev_dns),
        "removed": sorted(prev_dns - cur_dns),
    }

    def _port_key(p: Any) -> tuple[str, int] | None:
        if not isinstance(p, dict):
            return None
        host = str(p.get("host") or "").strip().lower()
        try:
            port = int(p.get("port"))
        except (TypeError, ValueError):
            return None
        if not host:
            return None
        return (host, port)

    prev_ports = {k for k in (_port_key(p) for p in previous.get("ports") or []) if k}
    cur_ports = {k for k in (_port_key(p) for p in current.get("ports") or []) if k}
    empty["ports"] = {
        "added": [{"host": h, "port": p} for h, p in sorted(cur_ports - prev_ports)],
        "removed": [{"host": h, "port": p} for h, p in sorted(prev_ports - cur_ports)],
    }

    prev_http = set(previous.get("http") or [])
    cur_http = set(current.get("http") or [])
    empty["http"] = {
        "added": sorted(cur_http - prev_http),
        "removed": sorted(prev_http - cur_http),
    }
    return empty


def watch_compare_and_persist(
    program_root: Path,
    inventory: dict[str, Any],
) -> dict[str, Any]:
    """
    Load previous latest snapshot, diff against current inventory, then persist.

    Mental model: snapshot timestamps support “last 24h / 7d” comparisons later;
    this MVP stores ts on every snapshot.
    """
    previous = load_latest_snapshot(program_root)
    current = snapshot_from_inventory(inventory)
    diffs = diff_snapshots(previous, current)
    save_snapshot(program_root, current)
    return {
        "diffs": diffs,
        "snapshot_ts": current.get("ts"),
        "previous_ts": (previous or {}).get("ts"),
        "latest_path": str(runs_dir(program_root) / "latest.json"),
    }
