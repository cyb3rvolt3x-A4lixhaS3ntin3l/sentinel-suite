"""Scope kernel MVP — raw allow/deny + brief parser stub + hard kill."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


class ScopeDenied(Exception):
    """Raised by hard_kill when a target is out of scope."""


@dataclass
class Scope:
    """In-memory allow/deny lists (raw text kernel)."""

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    def is_allowed(self, target: str) -> bool:
        t = target.strip().lower().rstrip(".")
        if not t:
            return False
        for d in self.deny:
            if _matches(t, d):
                return False
        if not self.allow:
            return False
        for a in self.allow:
            if _matches(t, a):
                return True
        return False

    def hard_kill(self, target: str) -> None:
        """Raise ScopeDenied if target is not allowed (OOS = hard kill)."""
        if not self.is_allowed(target):
            raise ScopeDenied(f"out of scope: {target!r}")


def _matches(target: str, pattern: str) -> bool:
    """Exact host match or subdomain-of pattern (*.example.com style)."""
    p = pattern.strip().lower().rstrip(".")
    if not p:
        return False
    if p.startswith("*."):
        suffix = p[1:]  # .example.com
        return target.endswith(suffix) or target == p[2:]
    return target == p or target.endswith("." + p)


def load_scope_text(text: str) -> Scope:
    """
    Parse raw scope text.
    - Blank / # comments ignored
    - Lines starting with ! are deny
    - Other non-empty lines are allow
    """
    allow: list[str] = []
    deny: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("!"):
            deny.append(s[1:].strip())
        else:
            allow.append(s)
    return Scope(allow=allow, deny=deny)


def load_scope_file(path: str | Path) -> Scope:
    return load_scope_text(Path(path).read_text(encoding="utf-8"))


_H1_IN_SCOPE = re.compile(
    r"(?i)^\s*(?:\*\s*)?(?:in[\s-]?scope|scope)\s*[:\-]?\s*$"
)
_H1_OUT_SCOPE = re.compile(
    r"(?i)^\s*(?:\*\s*)?(?:out[\s-]?of[\s-]?scope|oos)\s*[:\-]?\s*$"
)
_BULLET = re.compile(r"^\s*[-*•]\s+(.+)$")
_DOMAINISH = re.compile(
    r"(?i)\b((?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b"
)


def parse_brief_stub(text: str) -> Scope:
    """
    Minimal H1-ish / generic brief parser stub.

    Looks for In-scope / Out-of-scope section headers and collects
    bullet or bare domain-like tokens. Not a full platform importer —
    Sprint 0 MVP only.
    """
    allow: list[str] = []
    deny: list[str] = []
    mode: str | None = None

    for line in text.splitlines():
        if _H1_IN_SCOPE.match(line):
            mode = "allow"
            continue
        if _H1_OUT_SCOPE.match(line):
            mode = "deny"
            continue
        if mode is None:
            continue
        m = _BULLET.match(line)
        chunk = m.group(1) if m else line.strip()
        if not chunk or chunk.startswith("#"):
            continue
        for dom in _DOMAINISH.findall(chunk):
            if mode == "allow":
                allow.append(dom.lower())
            else:
                deny.append(dom.lower())

    return Scope(allow=allow, deny=deny)
