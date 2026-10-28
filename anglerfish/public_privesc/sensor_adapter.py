"""Sensor-facing adapter for the public→privesc bait chain.

Returns phpapp-compatible 5-tuples. Does NOT bind a server. php2shell stays
parallel and untouched. Hard stops identical to the local pack handler.
"""

from __future__ import annotations

import io
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from . import paths, tags
from .handler import drain_events, handle, log_event

# Clinic soft-fail / homepage stay owned by phpapp — do not steal them live.
_LIVE_SKIP = frozenset({
    "/", "/index.php", "/index.html", "/home",
    "/login.php",  # clinic soft-fail login (pack uses /portal/login.php)
})


def owns_path(path: str) -> bool:
    """True if this pack should answer the path on the live sensor."""
    clean = (path or "/").split("?", 1)[0] or "/"
    if clean in _LIVE_SKIP:
        return False
    if clean in (
        paths.PUBLIC_ZIP,
        paths.PUBLIC_UPLOADS_INDEX,
        paths.PUBLIC_UPLOADS_BAK,
        paths.PUBLIC_UPLOADS_ZIP,
        paths.PUBLIC_BACKUPS_INDEX,
        paths.PUBLIC_JS,
        paths.PUBLIC_ROBOTS,
        paths.PUBLIC_PHPMYADMIN,
        paths.PUBLIC_GIT_HEAD,
        paths.PUBLIC_GIT_CONFIG,
        paths.HANDOFF,
        paths.DEPLOY_ID,
        paths.TERM,
        paths.DASHBOARD,
        "/backups",
        "/uploads",
        "/uploads/",
        "/uploads/tmp",
        "/staff/docs",
        "/staff/docs/",
    ):
        return True
    if clean in paths.PUBLIC_PHPMYADMIN_ALT:
        return True
    if clean in paths.PMA_DOCPATH_PATHS:
        return True
    if clean in paths.PUBLIC_SERVER_STATUS:
        return True
    if clean in paths.PUBLIC_ACTUATOR_ENV:
        return True
    if clean in paths.PUBLIC_WP_LOGIN:
        return True
    # Live login aliases — exclude /login.php (in _LIVE_SKIP)
    live_login = set(paths.LOGIN_PATHS) - {"/login.php"}
    if clean in live_login:
        return True
    if clean.startswith(paths.LOOT_PREFIX):
        return True
    return False


class _Hdr(dict):
    """Minimal headers map with case-insensitive .get for the pack handler."""

    def get(self, key, default=None):  # type: ignore[override]
        if key in self:
            return dict.get(self, key, default)
        kl = key.lower()
        for k, v in self.items():
            if str(k).lower() == kl:
                return v
        return default


class _Capture(object):
    """Enough of BaseHTTPRequestHandler for public_privesc.handler.handle()."""

    protocol_version = "HTTP/1.0"

    def __init__(self, method: str, path: str, body: bytes, headers: Dict[str, str]):
        self.command = (method or "GET").upper()
        # handler urlparses self.path — keep query string if present
        self.path = path or "/"
        self.headers = _Hdr(headers or {})
        self.rfile = io.BytesIO(body or b"")
        self.wfile = io.BytesIO()
        self.status = 200
        self.resp_headers: List[Tuple[str, str]] = []
        self._ended = False

    def send_response(self, code: int, message: str = None) -> None:  # noqa: ARG002
        self.status = int(code)

    def send_header(self, key: str, value: str) -> None:
        self.resp_headers.append((key, value))

    def end_headers(self) -> None:
        self._ended = True

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def try_handle(
    path: str,
    method: str = "GET",
    body: bytes = b"",
    world: Optional[Dict[str, Any]] = None,
    cookie: str = "",
    content_type: str = "",
) -> Optional[Tuple[bytes, str, int, str, list]]:
    """If pack owns path, return (body, ctype, status, set_cookie, extra_headers).

    Side-effect: appends bait tags onto world['bait_tags'] (and drains pack
    log_event buffer into world['bait_events']).
    Returns None when the path is not pack-owned (caller continues).
    """
    if not owns_path(path):
        return None

    world = world if isinstance(world, dict) else {}
    # Prefer explicit cookie arg; else world http_cookie (sensor convention)
    cookie = cookie or (world.get("http_cookie") or "")
    ctype_in = content_type or ""
    if not ctype_in and method.upper() == "POST":
        # sensor often only puts Content-Type on headers_prefix; default form
        ctype_in = "application/x-www-form-urlencoded"

    headers = {
        "Cookie": cookie,
        "Content-Type": ctype_in,
        "Content-Length": str(len(body or b"")),
    }
    # Keep query on path for PMA docpath etc.
    full_path = path
    drain_events()  # isolate this request's events
    cap = _Capture(method, full_path, body or b"", headers)
    handle(cap)

    # Collect tags from drain_events
    evs = drain_events()
    tag_list: List[str] = []
    for e in evs:
        t = e.get("tag") or ""
        if t and t not in tag_list:
            tag_list.append(t)
    if tag_list:
        prev = list(world.get("bait_tags") or [])
        for t in tag_list:
            if t not in prev:
                prev.append(t)
        world["bait_tags"] = prev
    if evs:
        world.setdefault("bait_events", []).extend(evs)

    # Map captured headers → phpapp 5-tuple
    ctype = "text/html; charset=utf-8"
    extra: List[str] = []
    set_cookie = ""  # LFSESSID goes in extra_headers (clinic clears set_cookie slot)
    for k, v in cap.resp_headers:
        lk = k.lower()
        if lk == "content-type":
            ctype = v
        elif lk == "content-length":
            continue
        elif lk == "connection":
            continue
        elif lk == "server":
            continue  # sensor sets Server
        elif lk == "x-powered-by":
            extra.append("X-Powered-By: %s\r\n" % v)
        elif lk == "set-cookie":
            extra.append("Set-Cookie: %s\r\n" % v)
        elif lk == "location":
            extra.append("Location: %s\r\n" % v)
        else:
            extra.append("%s: %s\r\n" % (k, v))

    body_out = cap.wfile.getvalue()
    return (body_out, ctype, cap.status, set_cookie, extra)


# Re-export tags for Blue / tests
ALL_TAGS = tags.ALL_TAGS
