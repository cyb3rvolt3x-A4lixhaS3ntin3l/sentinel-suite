"""L5 tech fingerprint — native/stdlib header + body heuristics.

Honest, not Wappalyzer-complete. Confidence stays low–med for heuristic matches.
Injectable response objects (headers/body/url) — no live network required.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

# Rare / admin-ish stacks that should boost interestingness when seen.
RARE_ADMIN_TECH: frozenset[str] = frozenset(
    {
        "jenkins",
        "graphql",
        "spring",
        "wordpress",
        "laravel",
        "django",
        "rails",
        "asp.net",
        "iis",
        "php",
        "express",
        "next.js",
        "react",
    }
)

# Confidence bands for heuristic matches (honest labelling).
CONF_LOW = 0.40
CONF_MED = 0.55
CONF_MED_HIGH = 0.65


def _norm_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    if not headers:
        return {}
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k is None:
            continue
        key = str(k).strip().lower()
        if not key:
            continue
        # Collapse multi-value lists
        if isinstance(v, (list, tuple)):
            val = ", ".join(str(x) for x in v)
        else:
            val = str(v)
        out[key] = val
    return out


def _body_text(body: bytes | str | None) -> str:
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        return body.decode("utf-8", errors="replace")
    return str(body)


def _cookie_blob(
    headers: Mapping[str, str],
    cookies: Sequence[str] | None,
) -> str:
    parts: list[str] = []
    if cookies:
        parts.extend(str(c) for c in cookies)
    # Set-Cookie may appear once or as combined
    sc = headers.get("set-cookie") or ""
    if sc:
        parts.append(sc)
    # Cookie request header (rare on responses but allowed for injectables)
    ck = headers.get("cookie") or ""
    if ck:
        parts.append(ck)
    return "\n".join(parts).lower()


def _add(
    hits: dict[str, dict[str, Any]],
    name: str,
    *,
    confidence: float,
    evidence: str,
    source: str,
) -> None:
    """Keep highest-confidence evidence per tech name."""
    key = name.strip().lower()
    if not key:
        return
    conf = max(0.0, min(1.0, float(confidence)))
    prev = hits.get(key)
    if prev is None or conf > float(prev["confidence"]):
        hits[key] = {
            "name": key,
            "confidence": round(conf, 2),
            "evidence": evidence[:240],
            "source": source,
        }


def fingerprint(
    *,
    url: str = "",
    headers: Mapping[str, Any] | None = None,
    body: bytes | str | None = None,
    cookies: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Fingerprint one HTTP response.

    Returns list of ``{name, confidence, evidence, source}`` sorted by name.
    """
    hdrs = _norm_headers(headers)
    text = _body_text(body)
    text_l = text.lower()
    url_l = (url or "").strip().lower()
    cookie_l = _cookie_blob(hdrs, cookies)
    hits: dict[str, dict[str, Any]] = {}

    # --- Server header ---
    server = hdrs.get("server", "")
    server_l = server.lower()
    if "nginx" in server_l:
        _add(hits, "nginx", confidence=CONF_MED, evidence=f"Server: {server}", source="header")
    if "apache" in server_l:
        _add(hits, "apache", confidence=CONF_MED, evidence=f"Server: {server}", source="header")
    if "cloudflare" in server_l or "cf-ray" in hdrs or "cf-cache-status" in hdrs:
        evid = server if "cloudflare" in server_l else "cf-ray/cf-cache-status"
        _add(hits, "cloudflare", confidence=CONF_MED, evidence=str(evid), source="header")
    if "microsoft-iis" in server_l or "iis/" in server_l:
        _add(hits, "iis", confidence=CONF_MED, evidence=f"Server: {server}", source="header")
    if "gunicorn" in server_l:
        _add(hits, "gunicorn", confidence=CONF_MED, evidence=f"Server: {server}", source="header")
    if "openresty" in server_l:
        _add(hits, "openresty", confidence=CONF_MED, evidence=f"Server: {server}", source="header")

    # --- X-Powered-By ---
    xpb = hdrs.get("x-powered-by", "")
    xpb_l = xpb.lower()
    if "php" in xpb_l:
        _add(hits, "php", confidence=CONF_MED, evidence=f"X-Powered-By: {xpb}", source="header")
    if "asp.net" in xpb_l or "aspnet" in xpb_l:
        _add(hits, "asp.net", confidence=CONF_MED, evidence=f"X-Powered-By: {xpb}", source="header")
    if "express" in xpb_l:
        _add(hits, "express", confidence=CONF_MED, evidence=f"X-Powered-By: {xpb}", source="header")
    if "next.js" in xpb_l or "nextjs" in xpb_l:
        _add(hits, "next.js", confidence=CONF_MED, evidence=f"X-Powered-By: {xpb}", source="header")

    # ASP.NET telltales
    if "x-aspnet-version" in hdrs or "x-aspnetmvc-version" in hdrs:
        _add(
            hits,
            "asp.net",
            confidence=CONF_MED_HIGH,
            evidence="X-AspNet-Version / X-AspNetMvc-Version",
            source="header",
        )

    # Django
    if "csrftoken" in cookie_l or "django" in text_l[:8000]:
        if "csrftoken" in cookie_l:
            _add(hits, "django", confidence=CONF_MED, evidence="cookie:csrftoken", source="cookie")
        elif "csrfmiddlewaretoken" in text_l:
            _add(
                hits,
                "django",
                confidence=CONF_MED,
                evidence="csrfmiddlewaretoken in body",
                source="body",
            )

    # Rails
    if "_session" in cookie_l and ("_rails" in cookie_l or "rack.session" in cookie_l):
        _add(hits, "rails", confidence=CONF_MED, evidence="rails/rack session cookie", source="cookie")
    elif re.search(r"\b_rails_session\b|rack\.session", cookie_l):
        _add(hits, "rails", confidence=CONF_MED, evidence="rails session cookie", source="cookie")
    if "x-runtime" in hdrs and "rails" not in hits and "php" not in hits:
        # weak — many stacks set X-Runtime; only note as low if path/body hint
        if "rails" in text_l[:4000] or "/rails/" in url_l:
            _add(hits, "rails", confidence=CONF_LOW, evidence="X-Runtime + rails hint", source="header")

    # Laravel
    if "laravel_session" in cookie_l or "xsrf-token" in cookie_l and "laravel" in text_l[:4000]:
        _add(hits, "laravel", confidence=CONF_MED, evidence="laravel_session cookie", source="cookie")
    elif "laravel_session" in cookie_l:
        _add(hits, "laravel", confidence=CONF_MED, evidence="laravel_session", source="cookie")

    # WordPress cookies / paths / generator
    if re.search(r"wordpress_[a-z0-9_]*", cookie_l) or "wp-settings" in cookie_l:
        _add(hits, "wordpress", confidence=CONF_MED, evidence="wordpress_* cookie", source="cookie")
    if "/wp-content/" in text_l or "/wp-includes/" in text_l or "/wp-admin" in url_l:
        _add(
            hits,
            "wordpress",
            confidence=CONF_MED,
            evidence="wp-content/wp-includes/wp-admin path",
            source="path" if "/wp-admin" in url_l else "body",
        )
    if re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*wordpress',
        text_l,
        re.I,
    ) or re.search(
        r'<meta[^>]+content=["\'][^"\']*wordpress[^"\']*["\'][^>]+name=["\']generator["\']',
        text_l,
        re.I,
    ):
        _add(hits, "wordpress", confidence=CONF_MED_HIGH, evidence="meta generator WordPress", source="meta")

    # PHP session
    if "phpsessid" in cookie_l:
        _add(hits, "php", confidence=CONF_LOW, evidence="PHPSESSID cookie", source="cookie")

    # Java / Spring / Jenkins
    if "jsessionid" in cookie_l:
        _add(hits, "java", confidence=CONF_LOW, evidence="JSESSIONID cookie", source="cookie")
    if "/actuator" in url_l or "x-application-context" in hdrs:
        _add(hits, "spring", confidence=CONF_MED, evidence="actuator / X-Application-Context", source="path")
    if "jenkins" in server_l or "x-jenkins" in hdrs or "/jenkins" in url_l:
        evid = hdrs.get("x-jenkins") or server or url
        _add(hits, "jenkins", confidence=CONF_MED_HIGH, evidence=str(evid)[:120], source="header")
    if "jenkins" in text_l[:6000] and ("hudson" in text_l[:6000] or "jenkins-agent" in text_l):
        _add(hits, "jenkins", confidence=CONF_MED, evidence="jenkins body signature", source="body")

    # GraphQL path
    if "/graphql" in url_l or re.search(r'["\']/graphql["\']', text_l[:8000]):
        _add(hits, "graphql", confidence=CONF_MED if "/graphql" in url_l else CONF_LOW,
             evidence="/graphql path or reference", source="path")

    # jQuery / React / Next
    if re.search(r"jquery[.-]?(\d|\.min\.js)|/jquery\.js", text_l):
        _add(hits, "jquery", confidence=CONF_LOW, evidence="jquery script reference", source="body")
    if re.search(r"\breact(?:-dom)?[\.\"'/]|data-reactroot|__NEXT_DATA__", text_l):
        if "__next_data__" in text_l or "/_next/" in text_l or "next.js" in text_l[:4000]:
            _add(hits, "next.js", confidence=CONF_MED, evidence="__NEXT_DATA__ or /_next/", source="body")
        if "data-reactroot" in text_l or "react" in text_l[:8000]:
            _add(hits, "react", confidence=CONF_LOW, evidence="react body signature", source="body")

    # Express via common header combo already handled; also x-powered-by

    # Generic generator meta
    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        text,
        re.I,
    )
    if not m:
        m = re.search(
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
            text,
            re.I,
        )
    if m:
        gen = m.group(1).strip()
        gen_l = gen.lower()
        if "wordpress" in gen_l:
            _add(hits, "wordpress", confidence=CONF_MED_HIGH, evidence=f"generator:{gen}", source="meta")
        elif "drupal" in gen_l:
            _add(hits, "drupal", confidence=CONF_MED, evidence=f"generator:{gen}", source="meta")
        elif "joomla" in gen_l:
            _add(hits, "joomla", confidence=CONF_MED, evidence=f"generator:{gen}", source="meta")

    # Attach url when present for ranker host linkage
    rows = sorted(hits.values(), key=lambda r: r["name"])
    if url:
        for row in rows:
            row["url"] = url
    return rows


def fingerprint_http_rows(
    http_rows: Sequence[Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    """
    Fingerprint a list of HTTP inventory rows.

    Each row may carry ``url``, ``headers``, ``body`` / ``body_snippet``, ``cookies``.
    Dedupes by tech name keeping highest confidence; merges evidence lightly.
    """
    merged: dict[str, dict[str, Any]] = {}
    for row in http_rows or []:
        if not isinstance(row, Mapping):
            continue
        url = str(row.get("url") or "")
        headers = row.get("headers") if isinstance(row.get("headers"), Mapping) else {}
        body = row.get("body")
        if body is None:
            body = row.get("body_snippet")
        cookies = row.get("cookies")
        if isinstance(cookies, str):
            cookies = [cookies]
        for hit in fingerprint(url=url, headers=headers, body=body, cookies=cookies):
            name = hit["name"]
            prev = merged.get(name)
            if prev is None or float(hit["confidence"]) > float(prev["confidence"]):
                merged[name] = dict(hit)
    return sorted(merged.values(), key=lambda r: r["name"])


def merge_tech_into_inventory(
    inventory: dict[str, Any],
    http_rows: Sequence[Mapping[str, Any]] | None = None,
    *,
    scrub_bodies: bool = True,
) -> dict[str, Any]:
    """Run fingerprint on http[] (or provided rows) and set inventory['tech']."""
    rows = list(http_rows) if http_rows is not None else list(inventory.get("http") or [])
    tech = fingerprint_http_rows(rows)
    inventory["tech"] = tech
    if tech:
        sources = list(inventory.get("sources") or [])
        if "tech_fingerprint" not in {str(s).lower() for s in sources}:
            sources.append("tech_fingerprint")
        inventory["sources"] = sources
    if scrub_bodies and inventory.get("http"):
        cleaned = []
        for row in inventory["http"]:
            if not isinstance(row, dict):
                cleaned.append(row)
                continue
            r = dict(row)
            r.pop("body_snippet", None)
            r.pop("body", None)
            cleaned.append(r)
        inventory["http"] = cleaned
    return inventory
