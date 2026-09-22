"""Auth / OAuth / OIDC / SAML / magic-link surface candidate heuristics.

Path/query only — no network. Callers must scope-gate before any request.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

# Path / query token hints (case-insensitive substring or segment).
_AUTH_PATH_TOKENS = (
    "authorize",
    "oauth",
    "oidc",
    "saml",
    "sso",
    "login",
    "signin",
    "sign-in",
    "logout",
    "signout",
    "callback",
    "redirect_uri",
    "reset",
    "forgot",
    "password",
    "magic",
    "magic-link",
    "magiclink",
    "token",
    "auth",
    "connect",
    "openid",
    "well-known",
)

_QUERY_KEYS = (
    "redirect_uri",
    "redirect_url",
    "return_to",
    "returnurl",
    "next",
    "continue",
    "state",
    "code",
    "client_id",
    "response_type",
    "scope",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "access_token",
    "id_token",
    "token",
)

_KIND_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("oauth_authorize", re.compile(r"(?i)(oauth|/authorize|openid|oidc)")),
    ("oidc", re.compile(r"(?i)(oidc|openid|\.well-known)")),
    ("saml", re.compile(r"(?i)saml")),
    ("callback", re.compile(r"(?i)(callback|/cb\b|redirect)")),
    ("password_reset", re.compile(r"(?i)(reset|forgot).*?(pass|pwd)?|(pass|pwd).*?(reset|forgot)")),
    ("magic_link", re.compile(r"(?i)(magic[-_]?link|magiclink|/magic\b)")),
    ("login", re.compile(r"(?i)(login|signin|sign-in|/auth\b)")),
]


def _classify(url: str, path: str, query_keys: set[str]) -> list[str]:
    blob = f"{path}?{'&'.join(sorted(query_keys))}"
    kinds: list[str] = []
    for name, pat in _KIND_RULES:
        if pat.search(blob) or pat.search(url):
            kinds.append(name)
    if "redirect_uri" in query_keys or "redirect_url" in query_keys:
        if "oauth_param" not in kinds:
            kinds.append("oauth_param")
    if not kinds:
        # Generic auth surface if token matched
        kinds.append("auth_surface")
    return kinds


def detect_auth_surface_candidates(
    urls: list[str] | None = None,
    *,
    inventory: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Detect login/reset/OAuth/OIDC/SAML/magic-link **candidates** from URLs.

    Sources:
    - explicit ``urls`` list
    - Eye inventory ``http[]`` entries (url/final_url) and top-level URL strings

    Returns candidate dicts: {url, host, path, kinds, query_keys, reason}.
    Does not fetch. Scope-gate before requesting.
    """
    collected: list[str] = []
    if urls:
        collected.extend(str(u) for u in urls if u)
    if inventory:
        for item in inventory.get("http") or []:
            if isinstance(item, dict):
                for key in ("url", "final_url", "location"):
                    if item.get(key):
                        collected.append(str(item[key]))
            elif isinstance(item, str):
                collected.append(item)
        for key in ("urls", "endpoints"):
            for u in inventory.get(key) or []:
                if isinstance(u, str):
                    collected.append(u)
                elif isinstance(u, dict) and u.get("url"):
                    collected.append(str(u["url"]))

    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for raw in collected:
        url = raw.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
        except Exception:  # noqa: BLE001
            continue
        host = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path or "/"
        q = parse_qs(parsed.query, keep_blank_values=True)
        query_keys = {k.lower() for k in q}
        path_l = path.lower()
        query_l = parsed.query.lower()
        fragment_l = (parsed.fragment or "").lower()

        hit = False
        reasons: list[str] = []
        for tok in _AUTH_PATH_TOKENS:
            if tok in path_l or tok in query_l or tok in fragment_l:
                hit = True
                reasons.append(f"token:{tok}")
        for k in query_keys:
            if k in _QUERY_KEYS or k in {t.lower() for t in _AUTH_PATH_TOKENS}:
                hit = True
                reasons.append(f"query:{k}")

        if not hit:
            continue

        kinds = _classify(url, path_l, query_keys)
        out.append(
            {
                "url": url,
                "host": host,
                "path": path,
                "kinds": kinds,
                "query_keys": sorted(query_keys),
                "reason": sorted(set(reasons))[:12],
                "candidate": True,
            }
        )
    return out
