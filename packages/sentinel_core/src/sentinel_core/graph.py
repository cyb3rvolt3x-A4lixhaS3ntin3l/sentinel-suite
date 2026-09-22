"""SQLite WAL event graph store (per program)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from sentinel_core.events import Event


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    source_module TEXT NOT NULL,
    program_id TEXT NOT NULL,
    parents_json TEXT NOT NULL DEFAULT '[]',
    scope_distance INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_program ON events(program_id);
"""


class EventGraph:
    """Open or create a program graph.sqlite (WAL mode)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> EventGraph:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def insert(self, event: Event) -> None:
        self._conn.execute(
            """
            INSERT INTO events (
                id, type, source_module, program_id, parents_json,
                scope_distance, first_seen, last_seen, confidence, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id,
                event.type,
                event.source_module,
                event.program_id,
                json.dumps(list(event.parents)),
                int(event.scope_distance),
                event.first_seen.isoformat(),
                event.last_seen.isoformat(),
                float(event.confidence),
                json.dumps(event.payload),
            ),
        )
        self._conn.commit()

    def get(self, event_id: str) -> Event | None:
        row = self._conn.execute(
            "SELECT * FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_event(row)

    def list_by_type(self, event_type: str) -> list[Event]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE type = ? ORDER BY first_seen",
            (event_type,),
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def link_parents(self, event_id: str, parent_ids: Iterable[str]) -> None:
        event = self.get(event_id)
        if event is None:
            raise KeyError(f"event not found: {event_id}")
        merged = list(dict.fromkeys([*event.parents, *parent_ids]))
        self._conn.execute(
            "UPDATE events SET parents_json = ? WHERE id = ?",
            (json.dumps(merged), event_id),
        )
        self._conn.commit()

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event.from_dict(
            {
                "id": row["id"],
                "type": row["type"],
                "source_module": row["source_module"],
                "program_id": row["program_id"],
                "parents": json.loads(row["parents_json"]),
                "scope_distance": row["scope_distance"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "confidence": row["confidence"],
                "payload": json.loads(row["payload_json"]),
            }
        )
