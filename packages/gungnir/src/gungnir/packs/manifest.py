"""Hunt pack manifest — dataclass contract (YAML-shaped fields, no PyYAML req)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class PackManifest:
    """
    Pack discovery metadata.

    Field ``pack_class`` serializes as ``class`` (e.g. ato_oauth).
    ``needs_roles`` is 0, 1, or 2:
      - 0: Role A optional (pack soft-fails auth-gated checks with coach)
      - 1: Role A required (fail-closed)
      - 2: Role A + Role B required (fail-closed)
    """

    id: str
    pack_class: str
    needs_roles: int
    consumes: tuple[str, ...] = ()
    emits: tuple[str, ...] = ()
    noise_class: str = "med"
    description: str = ""
    version: str = "0"

    def __post_init__(self) -> None:
        if self.needs_roles not in (0, 1, 2):
            raise ValueError(f"needs_roles must be 0, 1, or 2, got {self.needs_roles}")
        if not self.id.strip():
            raise ValueError("pack id must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["class"] = d.pop("pack_class")
        d["consumes"] = list(self.consumes)
        d["emits"] = list(self.emits)
        return d


CHECKLIST_FIELDS = ("in_scope", "reproducible", "impact", "evidence_attached")


def finding_gate_checklist(
    *,
    in_scope: bool = False,
    reproducible: bool = False,
    impact: str = "unknown",
    evidence_attached: bool = False,
) -> dict[str, Any]:
    """Finding gate checklist fields required on emit."""
    return {
        "in_scope": bool(in_scope),
        "reproducible": bool(reproducible),
        "impact": impact,
        "evidence_attached": bool(evidence_attached),
    }
