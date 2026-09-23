"""Browser open helpers for ``sentinel ui`` / demo / full-run (productization).

Honesty rules (from productization research):
- Open **only** after the UI server has bound.
- Prefer loopback URLs; non-loopback opens only with an **explicit** ``--open``.
- Default ON for interactive TTY; OFF in CI/Docker/non-TTY unless overridden.
- ``SENTINEL_UI_OPEN=0|1`` and ``SENTINEL_NO_OPEN=1`` / ``CI=1`` participate.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse


def _env_truthy(raw: str | None) -> bool | None:
    if raw is None:
        return None
    v = raw.strip().lower()
    if v in {"1", "true", "yes", "on"}:
        return True
    if v in {"0", "false", "no", "off", ""}:
        return False
    return None


def resolve_open_browser(
    *,
    open_flag: bool | None,
    bind: str | None,
    env: Mapping[str, str] | None = None,
    isatty: bool | None = None,
) -> bool:
    """Decide whether to call ``webbrowser.open`` for the local UI.

    ``open_flag``: True (``--open``), False (``--no-open``), or None (default policy).
    """
    from sentinel_cli.ui_server import is_loopback_bind, DEFAULT_UI_BIND

    e = env if env is not None else os.environ
    host = (bind or DEFAULT_UI_BIND).strip() or DEFAULT_UI_BIND
    loopback = is_loopback_bind(host)

    if open_flag is False:
        return False

    no_open_env = _env_truthy(e.get("SENTINEL_NO_OPEN"))
    if no_open_env is True:
        return False

    ui_open = _env_truthy(e.get("SENTINEL_UI_OPEN"))
    if ui_open is False:
        return False

    ci = (e.get("CI") or "").strip().lower()
    if ci in {"1", "true", "yes"} and open_flag is not True and ui_open is not True:
        return False

    if open_flag is True:
        return True

    if ui_open is True:
        # Env opt-in still respects non-loopback foot-gun unless --open was used
        # (open_flag True already returned). Non-loopback + env alone → False.
        return bool(loopback)

    if not loopback:
        return False

    tty = sys.stdin.isatty() if isatty is None else bool(isatty)
    return bool(tty)


def loopback_display_url(bind: str, port: int) -> str:
    """URL shown to humans / opened in the browser.

    Wildcard binds (0.0.0.0 / ::) are advertised as 127.0.0.1 so a host browser
    can reach Docker-published or lab binds via localhost forwarding.
    """
    from sentinel_cli.ui_server import is_loopback_bind

    host = (bind or "127.0.0.1").strip() or "127.0.0.1"
    if host in {"0.0.0.0", "*", "::", "[::]"} or not is_loopback_bind(host):
        display = "127.0.0.1"
    elif host == "localhost":
        display = "127.0.0.1"
    elif host.startswith("[") and host.endswith("]"):
        display = host
    elif ":" in host and not host.startswith("["):
        display = f"[{host}]"
    else:
        display = host
    return f"http://{display}:{int(port)}/"


def url_is_safe_to_open(url: str, *, require_loopback: bool = True) -> bool:
    """Refuse non-http(s) and (by default) non-loopback hosts."""
    from sentinel_cli.ui_server import is_loopback_bind

    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    host = parsed.hostname or ""
    if require_loopback and not is_loopback_bind(host):
        return False
    return True


def open_ui_url(url: str, *, require_loopback: bool = True) -> dict[str, Any]:
    """Open ``url`` in the default browser. Returns a small status dict."""
    import webbrowser

    if not url_is_safe_to_open(url, require_loopback=require_loopback):
        return {
            "opened": False,
            "url": url,
            "error": "refused_non_loopback_or_bad_scheme",
        }
    try:
        ok = bool(webbrowser.open(url))
        return {"opened": ok, "url": url, "error": None if ok else "webbrowser_open_false"}
    except Exception as exc:  # noqa: BLE001
        return {"opened": False, "url": url, "error": str(exc)}


__all__ = [
    "loopback_display_url",
    "open_ui_url",
    "resolve_open_browser",
    "url_is_safe_to_open",
]
