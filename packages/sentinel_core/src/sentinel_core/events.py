"""Event schema v1 for Sentinel Suite."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


# Reasonable set from the product plan event graph (schema v1).
EVENT_TYPES = frozenset(
    {
        "ORG",
        "DOMAIN",
        "DNS_NAME",
        "IP",
        "ASN",
        "CERT",
        "OPEN_PORT",
        "SERVICE",
        "URL",
        "ENDPOINT",
        "PARAM",
        "JS_ASSET",
        "SECRET_CANDIDATE",
        "TECH",
        "CLOUD_ASSET",
        "REPO",
        "PERSON",
        "EMAIL",
        "IDENTITY",
        "SESSION",
        "FINDING",
        "EVIDENCE",
        "CHAIN",
        "FLOW",
        "STEP",
        "COLLABORATOR_HIT",
    }
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Event:
    """Schema v1 event node on the program graph."""

    type: str
    source_module: str
    program_id: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parents: list[str] = field(default_factory=list)
    scope_distance: int = 0
    first_seen: datetime = field(default_factory=_utcnow)
    last_seen: datetime = field(default_factory=_utcnow)
    confidence: float = 1.0
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {self.type!r}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if isinstance(self.first_seen, str):
            self.first_seen = datetime.fromisoformat(self.first_seen)
        if isinstance(self.last_seen, str):
            self.last_seen = datetime.fromisoformat(self.last_seen)
        if self.parents is None:
            self.parents = []
        if self.payload is None:
            self.payload = {}

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        return cls(**dict(data))
