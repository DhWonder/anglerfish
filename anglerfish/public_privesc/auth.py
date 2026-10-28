"""LFSESSID session store — in-memory only, local smoke. Nothing real unlocked."""

from __future__ import annotations

import secrets
import threading
import time
from typing import Any, Dict, Optional

from .creds import BACKUP_PASS, BACKUP_USER, WEAK_PASS, WEAK_USER

SESSION_TTL_SEC = 1800
COOKIE_NAME = "LFSESSID"

_lock = threading.Lock()
_SESSIONS: Dict[str, Dict[str, Any]] = {}


def _purge(now: Optional[float] = None) -> None:
    now = now or time.time()
    dead = [k for k, v in _SESSIONS.items() if v.get("exp", 0) < now]
    for k in dead:
        _SESSIONS.pop(k, None)


def mint_session(priv: str = "www-data", user: str = WEAK_USER) -> str:
    sid = secrets.token_hex(16)
    with _lock:
        _purge()
        _SESSIONS[sid] = {
            "user": user,
            "priv": priv,
            "escalated": False,
            "exp": time.time() + SESSION_TTL_SEC,
            "created": time.time(),
        }
    return sid


def get_session(sid: Optional[str]) -> Optional[Dict[str, Any]]:
    if not sid:
        return None
    with _lock:
        _purge()
        st = _SESSIONS.get(sid)
        if not st:
            return None
        st["exp"] = time.time() + SESSION_TTL_SEC
        return dict(st)


def mark_escalated(sid: str) -> bool:
    with _lock:
        st = _SESSIONS.get(sid)
        if not st:
            return False
        st["escalated"] = True
        st["priv"] = "backup"
        st["user"] = BACKUP_USER
        st["exp"] = time.time() + SESSION_TTL_SEC
        return True


def check_weak(user: str, password: str) -> bool:
    return user == WEAK_USER and password == WEAK_PASS


def check_backup(user: str, password: str) -> bool:
    return user == BACKUP_USER and password == BACKUP_PASS


def parse_cookie(header: str) -> Optional[str]:
    if not header:
        return None
    for part in header.split(";"):
        part = part.strip()
        if part.startswith(COOKIE_NAME + "="):
            return part.split("=", 1)[1].strip()[:64]
    return None


def set_cookie_header(sid: str) -> str:
    return "%s=%s; Path=/; HttpOnly" % (COOKIE_NAME, sid)
