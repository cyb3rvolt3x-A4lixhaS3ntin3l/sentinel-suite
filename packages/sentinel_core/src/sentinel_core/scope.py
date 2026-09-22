"""Scope kernel MVP — raw allow/deny + multi-platform brief parsers + hard kill."""

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
    r"(?i)^\s*(?:\*\s*)?(?:#{1,3}\s*)?(?:in[\s-]?scope|scope)\s*[:\-]?\s*$"
)
_H1_OUT_SCOPE = re.compile(
    r"(?i)^\s*(?:\*\s*)?(?:#{1,3}\s*)?(?:out[\s-]?of[\s-]?scope|oos)\s*[:\-]?\s*$"
)
# Bugcrowd / generic section variants
_BC_IN_SCOPE = re.compile(
    r"(?i)^\s*(?:#{1,3}\s*)?(?:\*\*)?(?:targets?|in[\s-]?scope(?:\s+targets?)?|"
    r"scope\s+targets?|assets?\s+in\s+scope)(?:\*\*)?\s*[:\-]?\s*$"
)
_BC_OUT_SCOPE = re.compile(
    r"(?i)^\s*(?:#{1,3}\s*)?(?:\*\*)?(?:out[\s-]?of[\s-]?scope(?:\s+targets?)?|"
    r"excluded?(?:\s+targets?)?|not\s+in\s+scope)(?:\*\*)?\s*[:\-]?\s*$"
)
_BULLET = re.compile(r"^\s*[-*•]\s+(.+)$")
_DOMAINISH = re.compile(
    r"(?i)\b((?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b"
)


def _parse_sectioned_brief(
    text: str,
    *,
    in_patterns: list[re.Pattern[str]],
    out_patterns: list[re.Pattern[str]],
) -> Scope:
    allow: list[str] = []
    deny: list[str] = []
    mode: str | None = None

    for line in text.splitlines():
        if any(p.match(line) for p in in_patterns):
            mode = "allow"
            continue
        if any(p.match(line) for p in out_patterns):
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


def parse_brief_h1(text: str) -> Scope:
    """H1-ish brief: In Scope / Out of Scope section headers + domain bullets."""
    return _parse_sectioned_brief(
        text,
        in_patterns=[_H1_IN_SCOPE],
        out_patterns=[_H1_OUT_SCOPE],
    )


def parse_brief_bugcrowd(text: str) -> Scope:
    """
    Bugcrowd / generic section-header brief.

    Accepts Targets / In Scope Targets / Out of Scope / Excluded variants.
    Falls back to H1 patterns so mixed briefs still parse.
    """
    return _parse_sectioned_brief(
        text,
        in_patterns=[_BC_IN_SCOPE, _H1_IN_SCOPE],
        out_patterns=[_BC_OUT_SCOPE, _H1_OUT_SCOPE],
    )


def _has_header(patterns: list[re.Pattern[str]], text: str) -> bool:
    for line in text.splitlines():
        if any(p.match(line) for p in patterns):
            return True
    return False


def detect_brief_platform(text: str) -> str:
    """
    Heuristic platform detection for program briefs.

    Returns one of: ``h1``, ``bugcrowd``, ``raw``, ``generic``.
    """
    sample = text[:8000]
    lower = sample.lower()

    has_h1 = _has_header([_H1_IN_SCOPE, _H1_OUT_SCOPE], sample)
    has_bc = _has_header([_BC_IN_SCOPE, _BC_OUT_SCOPE], sample)
    has_section = has_h1 or has_bc

    bang_lines = sum(
        1 for ln in sample.splitlines() if ln.strip().startswith("!")
    )
    if not has_section and bang_lines > 0:
        return "raw"
    if not has_section:
        # Bare domain list → treat as raw
        doms = _DOMAINISH.findall(sample)
        if doms and all(
            (ln.strip().startswith("#") or not ln.strip() or _DOMAINISH.search(ln))
            for ln in sample.splitlines()
        ):
            return "raw"

    # Prefer bugcrowd when Targets / Excluded style headers present
    if has_bc and (
        "bugcrowd" in lower
        or "targets" in lower
        or "excluded" in lower
    ):
        return "bugcrowd"

    if has_h1:
        return "h1"

    if has_section:
        return "generic"

    return "raw"


def parse_brief(text: str, platform: str = "auto") -> Scope:
    """
    Parse a program brief into a Scope.

    platform: auto | h1 | bugcrowd | generic | raw
    """
    plat = (platform or "auto").strip().lower()
    if plat == "auto":
        plat = detect_brief_platform(text)

    if plat == "raw":
        return load_scope_text(text)
    if plat == "h1":
        return parse_brief_h1(text)
    if plat in ("bugcrowd", "generic"):
        return parse_brief_bugcrowd(text)

    raise ValueError(
        f"unknown brief platform: {platform!r} "
        "(expected auto|h1|bugcrowd|generic|raw)"
    )


def parse_brief_stub(text: str) -> Scope:
    """
    Backward-compatible H1-ish stub — delegates to parse_brief(..., \"h1\").
    """
    return parse_brief(text, platform="h1")


def scope_to_raw_text(scope: Scope) -> str:
    """Serialize Scope back to raw allow/deny lines for scope.txt."""
    lines = [
        "# Generated by sentinel program import-brief",
        "# Allow one host/domain per line; lines starting with ! are deny",
    ]
    for a in scope.allow:
        lines.append(a)
    for d in scope.deny:
        lines.append(f"!{d}")
    return "\n".join(lines) + "\n"
