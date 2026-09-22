"""Interestingness ranker — score assets for default JSON sort."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

# Hostname tokens that bump interestingness (admin/staging/dev/etc.)
INTERESTING_TOKENS: tuple[str, ...] = (
    "admin",
    "staging",
    "stage",
    "graphql",
    "jenkins",
    "vpn",
    "internal",
    "intranet",
    "dev",
    "test",
    "uat",
    "qa",
    "api",
    "auth",
    "sso",
    "login",
    "portal",
    "jenkins",
    "jira",
    "confluence",
    "git",
    "gitlab",
    "ci",
    "cdn-origin",
)

BORING_TOKENS: tuple[str, ...] = (
    "www",
    "mail",
    "mx",
    "ns1",
    "ns2",
    "smtp",
    "pop",
    "imap",
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (TypeError, ValueError):
        return None


def score_hostname(
    hostname: str,
    *,
    first_seen: Any = None,
    now: datetime | None = None,
    auth_required: bool | None = None,
) -> tuple[float, list[str]]:
    """
    Score a hostname for interestingness.

    Factors:
    - newness: first_seen within last 24h / 7d
    - interesting tokens in labels (admin/staging/graphql/…)
    - boring tokens slightly lower score
    - auth_required True bumps; False (no-auth known) slight bump for exposure
    """
    host = (hostname or "").strip().lower().rstrip(".")
    reasons: list[str] = []
    score = 0.0
    if not host:
        return 0.0, ["empty"]

    labels = host.split(".")
    # Drop apex-ish last two labels when scoring tokens
    label_set = set(labels)

    matched = [t for t in INTERESTING_TOKENS if t in label_set or any(t in lab for lab in labels[:-2] or labels)]
    # Prefer exact label matches
    exact = [t for t in INTERESTING_TOKENS if t in label_set]
    if exact:
        score += 25.0 * len(set(exact))
        reasons.append("token:" + ",".join(sorted(set(exact))[:5]))
    elif matched:
        # substring in non-apex labels
        score += 12.0
        reasons.append("token_sub:" + matched[0])

    boring = [t for t in BORING_TOKENS if t in label_set]
    if boring and not exact:
        score -= 5.0
        reasons.append("boring:" + boring[0])

    # Depth: deeper subdomains slightly more interesting
    if len(labels) >= 4:
        score += 3.0
        reasons.append("depth")

    ts = _parse_ts(first_seen)
    ref = now or _utcnow()
    if ts is not None:
        age = ref - ts
        if age <= timedelta(hours=24):
            score += 20.0
            reasons.append("new:24h")
        elif age <= timedelta(days=7):
            score += 10.0
            reasons.append("new:7d")

    if auth_required is True:
        score += 8.0
        reasons.append("auth:required")
    elif auth_required is False:
        score += 5.0
        reasons.append("auth:open")

    # Floor: bare apex / www still gets a small base so sort is stable
    if score <= 0:
        score = 1.0
        if not reasons:
            reasons.append("base")

    return float(score), reasons


def score_asset(asset: dict[str, Any], *, now: datetime | None = None) -> tuple[float, list[str]]:
    """Score a generic asset dict with optional key/host/name/url fields."""
    key = (
        asset.get("key")
        or asset.get("name")
        or asset.get("host")
        or asset.get("dns_name")
        or asset.get("url")
        or asset.get("domain")
        or ""
    )
    # For URLs, use hostname portion lightly
    host = str(key)
    if "://" in host:
        try:
            from urllib.parse import urlparse

            host = urlparse(host).hostname or host
        except Exception:  # noqa: BLE001
            pass
    return score_hostname(
        host,
        first_seen=asset.get("first_seen"),
        now=now,
        auth_required=asset.get("auth_required"),
    )


def rank_inventory(
    inventory: dict[str, Any],
    *,
    now: datetime | None = None,
    first_seen_map: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Build ``ranked`` list from dns_names (+ domains) sorted by score desc.

    Each entry: ``{key, score, reasons: []}``.
    """
    first_seen_map = first_seen_map or {}
    keys: list[str] = []
    seen: set[str] = set()

    for raw in inventory.get("dns_names") or []:
        if isinstance(raw, str):
            name = raw.strip().lower().rstrip(".")
        else:
            name = str(raw.get("name") or "").strip().lower().rstrip(".")
        if name and name not in seen:
            seen.add(name)
            keys.append(name)

    for raw in inventory.get("domains") or []:
        name = (raw if isinstance(raw, str) else str(raw.get("domain") or "")).strip().lower().rstrip(".")
        if name and name not in seen:
            seen.add(name)
            keys.append(name)

    # MX hosts from identity are slightly less interesting than admin/staging
    mx_hosts = {
        str(r.get("value") or "").strip().lower().rstrip(".")
        for r in (inventory.get("identity") or [])
        if isinstance(r, dict) and str(r.get("kind") or "").lower() == "mx"
    }

    ranked: list[dict[str, Any]] = []
    for key in keys:
        fs = first_seen_map.get(key)
        score, reasons = score_hostname(key, first_seen=fs, now=now)
        if key in mx_hosts and not any(
            t in key.split(".") for t in ("admin", "staging", "api", "vpn", "dev")
        ):
            score -= 3.0
            reasons = list(reasons) + ["identity_mx_only"]
        ranked.append({"key": key, "score": round(score, 2), "reasons": reasons})

    ranked.sort(key=lambda r: (-float(r["score"]), r["key"]))
    return ranked


def sort_dns_names_by_rank(
    inventory: dict[str, Any],
    ranked: Sequence[dict[str, Any]] | None = None,
) -> list[Any]:
    """Return dns_names reordered to match interestingness rank."""
    ranked_list = list(ranked) if ranked is not None else rank_inventory(inventory)
    order = {r["key"]: i for i, r in enumerate(ranked_list)}
    rows = list(inventory.get("dns_names") or [])

    def _name(raw: Any) -> str:
        if isinstance(raw, str):
            return raw.strip().lower().rstrip(".")
        return str(raw.get("name") or "").strip().lower().rstrip(".")

    return sorted(rows, key=lambda r: (order.get(_name(r), 10_000), _name(r)))
