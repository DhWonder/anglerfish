"""
PHP2Shell full-chain lure state machine (Blue+Red merge) — local prototype.

Feature flags:
  ANGLERFISH_PHP2SHELL_FULLCHAIN=1  — enable S1–S4 state machine (default off)
  ANGLERFISH_PHP2SHELL_OOM_SHAPE=1  — rare sticky-once OOM-500 on huge S1 (default off)
  ANGLERFISH_PHP2SHELL_FAKE_LEAK    — B1 huge PHPSESSID cookie after S1 (default ON;
                                      set 0/false/off to disable)
  ANGLERFISH_PHP2SHELL_FAKE_PERSIST — felt-win fake C2 + persistence overlay
                                      (cron/ssh keys/webshell/ps/ss); default OFF

Hard stops: no FS write of attacker body to include/docroot, no exec/eval/
include, no outbound fetch, sanitized marker echo only, allowlisted S3
paths, cap+drain elsewhere. Research samples go under a non-webroot
quarantine dir only (capped .bin).
"""

from __future__ import print_function

import hashlib
import os
import random
import re
import secrets
import threading
import time
from collections import OrderedDict

# --- config -----------------------------------------------------------------
# Research profile TTL (Red addendum); was 120s.
STATE_TTL_SEC = 300
MARKER_MAX = 96
PROGRESS_NAME_MAX = 64
S1_DELAY_MS = (100, 400)
RACE_FLAKE_WINDOW_SEC = 0.3
RACE_FLAKE_PCT = 25  # ~20–30%
OOM_SHAPE_CL = 32_000_000
INSPECT_PREFIX_CAP = 256 * 1024
SAMPLE_KEEP_CAP = 64 * 1024
SAMPLE_PART_CAP = 32 * 1024
SAMPLE_MAX_PARTS = 3
# B1-style fake session-cookie leak (skid/mid "win" feel). Default ON.
FAKE_LEAK_MIN = 8 * 1024
FAKE_LEAK_MAX = 64 * 1024
DEFAULT_SAMPLE_DIR = "/var/lib/anglerfish/samples/php2shell"
# Matches clinic phpinfo System line (Apache/PHP cover).
CLINIC_HOSTNAME = "ip-10-0-0-21"

_NEUTRALIZE = re.compile(
    r"(?is)(<\?=?|<\?php|system|exec|passthru|shell_exec|proc_open|popen|"
    r"curl|wget|file_get_contents|file_put_contents|include|require|eval|"
    r"`|<\?=|\$_|\\x[0-9a-f]{2})"
)

# Unified S3 / fingerprint canary allowlist (one frozenset with phpapp).
# Docroot /shell.php and /.s.php intentionally excluded from 200 set.
SHELL_ALLOWLIST = frozenset({
    "/uploads/shell.php",
    "/uploads/p2s.php",
    "/uploads/sess_canary.php",
    "/uploads/.well-known-up.php",
})

# Broader dictionary: log as php2shell_drop_probe even when 404.
DROP_PROBE_PATHS = frozenset(SHELL_ALLOWLIST | {
    "/shell.php",
    "/.s.php",
    "/s.php",
    "/cmd.php",
    "/c.php",
    "/x.php",
    "/xx.php",
    "/1.php",
    "/wp-content/uploads/shell.php",
    "/uploads/x.php",
    "/uploads/cmd.php",
    "/uploads/up.php",
    "/tmp/p2s.php",
    "/tmp/shell.php",
    "/var/www/html/.s.php",
    "/var/www/html/shell.php",
    "/var/tmp/shell.php",
})

_S2_PROGRESS_PATHS = frozenset({
    "/session_upload_progress.php",
})

_UPLOAD_ROUTES = frozenset({
    "/upload.php",
    "/upload",
    "/admin/upload.php",
    "/index.php",  # Profile P1: kits POST progress to index.php too
})

_S2_SESS_PATH_RE = re.compile(
    r"^(?:/var/lib/php/sessions|/tmp|/var/lib/php)/sess_([A-Za-z0-9,-]{1,128})$"
)

_lock = threading.Lock()
_STATE = {}  # sessid -> dict
_LEAKED_FAMILIES = set()  # sticky-once fake-leak per sess_family/campaign_key
# B1 junk cookie → original sid (clients honor Set-Cookie and come back with junk)
_LEAK_BY_HASH = {}  # sha256(full junk) -> original sid
_LEAK_BY_PREFIX = {}  # junk[:N] -> original sid (N in LEAK_PREFIX_LENS)
LEAK_PREFIX_LENS = (32, 64, 128, 256)
# Felt-win fake persist/C2 overlay (in-memory only; never real FS/cron/ssh/sockets)
_PERSIST_OVERLAY = {}  # sess_family -> overlay dict


def fullchain_enabled():
    return os.environ.get("ANGLERFISH_PHP2SHELL_FULLCHAIN", "").strip() in (
        "1", "true", "yes", "on")


def oom_shape_enabled():
    """Separate flag; default OFF (Red: abandons kits if always-on)."""
    return os.environ.get("ANGLERFISH_PHP2SHELL_OOM_SHAPE", "").strip() in (
        "1", "true", "yes", "on")


def fake_leak_enabled():
    """B1-style fake PHPSESSID leak. Default ON; set 0/false/off to disable."""
    v = os.environ.get("ANGLERFISH_PHP2SHELL_FAKE_LEAK")
    if v is None:
        return True
    return v.strip().lower() not in ("0", "false", "no", "off")


def fake_persist_enabled():
    """Felt-win fake C2 + persistence overlay. Default OFF."""
    return os.environ.get("ANGLERFISH_PHP2SHELL_FAKE_PERSIST", "").strip().lower() in (
        "1", "true", "yes", "on")


def register_leak_cookie(junk, original_sid):
    """Map leak cookie (full hash + prefixes) → original sid for post-leak gating."""
    if not junk or not original_sid:
        return
    sid = re.sub(r"[\r\n;]", "", str(original_sid))[:128]
    junk_s = str(junk)
    digest = hashlib.sha256(junk_s.encode("utf-8", "replace")).hexdigest()
    with _lock:
        _LEAK_BY_HASH[digest] = sid
        for n in LEAK_PREFIX_LENS:
            if len(junk_s) >= n:
                _LEAK_BY_PREFIX[junk_s[:n]] = sid


def resolve_sessid(raw_sessid):
    """Resolve inbound PHPSESSID to state key.

    Normal sids pass through (capped 128). Oversized B1 junk — or the
    128-char truncation phpapp stores as phpsessid_echo — maps back to the
    original sid via leak hash/prefix tables so S2/S3/fake-shell still gate.
    """
    if not raw_sessid:
        return ""
    cleaned = re.sub(r"[\r\n;]", "", str(raw_sessid))
    if not cleaned:
        return ""
    with _lock:
        digest = hashlib.sha256(cleaned.encode("utf-8", "replace")).hexdigest()
        hit = _LEAK_BY_HASH.get(digest)
        if hit:
            return hit
        for n in LEAK_PREFIX_LENS:
            if len(cleaned) >= n:
                hit = _LEAK_BY_PREFIX.get(cleaned[:n])
                if hit:
                    return hit
        hit = _LEAK_BY_PREFIX.get(cleaned)
        if hit:
            return hit
    return cleaned[:128]


def _fake_leak_junk(sess_family_id, campaign_key=""):
    """Large urlencoded-looking junk, varied per sess_family (8–64KiB)."""
    seed = "%s|%s" % (sess_family_id or "", campaign_key or "")
    digest = hashlib.sha256(seed.encode("utf-8", "replace")).digest()
    span = FAKE_LEAK_MAX - FAKE_LEAK_MIN + 1
    size = FAKE_LEAK_MIN + (digest[0] * 256 + digest[1]) % span
    rng = random.Random(int.from_bytes(digest[:8], "big"))
    alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    parts = []
    total = 0
    while total < size:
        if rng.random() < 0.18:
            piece = "%%%02X" % rng.randint(0, 255)
        else:
            piece = rng.choice(alphabet) * rng.randint(4, 24)
        parts.append(piece)
        total += len(piece)
    return "".join(parts)[:size]


def maybe_attach_fake_leak(st, cookie, research):
    """Sticky-once after progress/OOM-shaped S1: huge PHPSESSID Set-Cookie.

    Kits/skids feel a memory-leak win; we never RCE. Once per sess_family
    (fallback campaign_key). Junk varies by family — not identical every hit.
    """
    research = research if research is not None else {}
    if not fake_leak_enabled():
        return cookie, research
    st = st or {}
    fam = st.get("sess_family") or sess_family(st.get("sessid") or "")
    ck = st.get("campaign_key") or ""
    key = fam or ck
    if not key:
        return cookie, research
    with _lock:
        if key in _LEAKED_FAMILIES:
            return cookie, research
        _LEAKED_FAMILIES.add(key)
    junk = _fake_leak_junk(fam, ck)
    research["fake_leak_cookie"] = True
    research["fake_leak_len"] = len(junk)
    research["php2shell_fake_leak_cookie"] = True
    sid = st.get("sessid") or ""
    if sid:
        register_leak_cookie(junk, sid)
        touch_state(
            sid,
            fake_leak_fired=True,
            leak_cookie_sha256=hashlib.sha256(
                junk.encode("utf-8", "replace")).hexdigest(),
            leak_cookie_prefix=junk[:128],
        )
    # Replace PHPSESSID with leak blob (B1-style "win"). Keep junk as signal;
    # state stays on original sid; inbound junk resolves via leak map.
    return ("PHPSESSID=%s; path=/" % junk), research


def shell_allowlist():
    return SHELL_ALLOWLIST


def drop_probe_paths():
    return DROP_PROBE_PATHS


def sample_dir():
    return (os.environ.get("ANGLERFISH_PHP2SHELL_SAMPLE_DIR") or
            DEFAULT_SAMPLE_DIR)


def sanitize_marker(raw, max_len=MARKER_MAX):
    """Neutralize code-like tokens; return safe short echo string.

    Red Delta A: strip framing breakers `|\";\x00` so a planted
    evil\"break cannot break upload_progress_<name>| or s:N:\"…\" framing.
    """
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        s = bytes(raw).decode("latin-1", "replace")
    else:
        s = str(raw)
    s = s.replace("\x00", "")
    # Framing breakers for progress key + php-serialize string bodies.
    for ch in ("|", '"', "\\", ";"):
        s = s.replace(ch, "")
    s = _NEUTRALIZE.sub("", s)
    s = re.sub(r"[\r\n\t]+", " ", s)
    s = re.sub(r"[^\x20-\x7e]", "", s)
    return s[:max_len]


def mint_sessid():
    return secrets.token_hex(16)


def phpsessid_sha256(sessid):
    if not sessid:
        return ""
    return hashlib.sha256(str(sessid).encode("utf-8", "replace")).hexdigest()


def phpsessid_head_tail(sessid, n=8):
    s = str(sessid or "")
    if len(s) <= n * 2:
        return s
    return "%s…%s" % (s[:n], s[-n:])


def campaign_key(src_ip="", progress_name="", ua="", payload_urls=None):
    """Stable-ish cluster key for campaign research (not a security boundary)."""
    urls = ",".join((payload_urls or [])[:3])
    raw = "|".join([
        (src_ip or "").rsplit(".", 1)[0] if src_ip else "",  # /24-ish
        sanitize_marker(progress_name, 32),
        (ua or "")[:80],
        urls[:120],
    ])
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def sess_family(sessid):
    """Family id from sessid hash prefix (cluster sibling sessions)."""
    h = phpsessid_sha256(sessid)
    return h[:12] if h else ""


def _purge_expired(now=None):
    now = now if now is not None else time.time()
    dead = [k for k, v in _STATE.items() if v.get("expires", 0) <= now]
    for k in dead:
        _STATE.pop(k, None)


def get_state(sessid):
    if not sessid:
        return None
    with _lock:
        _purge_expired()
        st = _STATE.get(sessid)
        if not st:
            return None
        return dict(st)


def touch_state(sessid, **fields):
    """Create/refresh in-memory state for sessid. Returns state dict copy."""
    if not sessid:
        sessid = mint_sessid()
    sessid = re.sub(r"[\r\n;]", "", str(sessid))[:128]
    now = time.time()
    with _lock:
        _purge_expired(now)
        st = _STATE.get(sessid) or {
            "sessid": sessid,
            "stage": "new",
            "marker": "",
            "progress_name": "",
            "created": now,
            "bytes_processed": 0,
            "content_length": 0,
            "done": False,
            "oom_fired": False,
            "s2_attempted": False,
            "drop_paths_probed": [],
        }
        st.update(fields)
        st["sessid"] = sessid
        st["expires"] = now + STATE_TTL_SEC
        st["updated"] = now
        _STATE[sessid] = st
        return dict(st)


def note_s1(sessid, progress_name="", body_prefix=b"", payload_urls=None,
            declared_length=0, src_ip="", ua="", campaign=None):
    """Record S1 upload; extract sanitized marker from progress or prefix."""
    prog = sanitize_marker(progress_name, PROGRESS_NAME_MAX)
    marker = prog
    if not marker and body_prefix:
        text = body_prefix.decode("latin-1", "replace") if isinstance(
            body_prefix, (bytes, bytearray)) else str(body_prefix)
        cands = re.findall(r"[A-Za-z0-9_\-]{8,96}", text)
        for c in cands:
            sm = sanitize_marker(c)
            if len(sm) >= 8:
                marker = sm
                break
    sid = sessid or mint_sessid()
    now = time.time()
    declared = int(declared_length or 0)
    kept = len(body_prefix or b"")
    # Initial progress toward declared (or kept) — not full CL.
    initial_bp = min(kept, declared) if declared else kept
    ck = campaign or campaign_key(src_ip, prog, ua, payload_urls)
    return touch_state(
        sid,
        stage="s1_done",
        progress_name=prog,
        marker=marker,
        payload_urls=list(payload_urls or [])[:5],
        s1_at=now,
        start_time=int(now),
        bytes_processed=initial_bp,
        content_length=declared or max(initial_bp, 1),
        done=False,
        campaign_key=ck,
        sess_family=sess_family(sid),
        src_ip=src_ip or "",
        ua=(ua or "")[:200],
    )


# --- PHP session.serialize_handler=php encode --------------------------------

def _php_str_escape(raw):
    """Escape \\, \", and NUL for s:N:\"…\" framing (Red Delta A).

    Length of the escaped form is what we emit in s:N so framing stays
    self-consistent for naive greppers even if sanitize was skipped.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    else:
        raw = bytes(raw)
    out = bytearray()
    for b in raw:
        if b == 0x5C:  # backslash
            out.extend(b"\\\\")
        elif b == 0x22:  # double quote
            out.extend(b'\\"')
        elif b == 0x00:  # NUL
            out.extend(b"\\0")
        else:
            out.append(b)
    return bytes(out)


def _php_serialize(val):
    """Minimal PHP serialize for ints/bools/strings/dicts (ordered)."""
    if isinstance(val, bool):
        return "b:%d;" % (1 if val else 0)
    if isinstance(val, int):
        return "i:%d;" % val
    if isinstance(val, float):
        return "d:%s;" % repr(val)
    if isinstance(val, (bytes, bytearray)):
        raw = _php_str_escape(bytes(val))
        return 's:%d:"%s";' % (len(raw), raw.decode("latin-1"))
    if isinstance(val, str):
        raw = _php_str_escape(val)
        return 's:%d:"%s";' % (len(raw), raw.decode("latin-1"))
    if isinstance(val, dict):
        parts = []
        for k, v in val.items():
            if isinstance(k, int) and not isinstance(k, bool):
                parts.append("i:%d;" % k)
            else:
                ks = _php_str_escape(str(k))
                parts.append('s:%d:"%s";' % (len(ks), ks.decode("latin-1")))
            parts.append(_php_serialize(v))
        return "a:%d:{%s}" % (len(val), "".join(parts))
    if val is None:
        return "N;"
    raw = _php_str_escape(str(val))
    return 's:%d:"%s";' % (len(raw), raw.decode("latin-1"))


def s2_session_blob(st):
    """
    Fake session.upload_progress blob using session.serialize_handler=php.

    Shape: upload_progress_<name>|a:5:{...}
    NOT pipe-draft, NOT JSON. Marker only sanitized; optional embed in
    benign files[0].name. done=b:0 then later polls b:1 with rising
    bytes_processed (caller advances state before calling).
    """
    st = st or {}
    marker = sanitize_marker(st.get("marker") or "")
    prog = sanitize_marker(st.get("progress_name") or "x", PROGRESS_NAME_MAX) or "x"
    now = int(st.get("start_time") or time.time())
    bytes_proc = int(st.get("bytes_processed") or 0)
    content_length = int(st.get("content_length") or max(bytes_proc, 1))
    done = bool(st.get("done"))
    # Benign filename; optionally embed sanitized marker for second grep hit.
    if marker:
        fname = ("up_%s.bin" % marker)[:64]
    else:
        fname = "upload.bin"
    files0 = OrderedDict([
        ("field_name", "file"),
        ("name", fname),
        ("tmp_name", "/tmp/phpXXXXXX"),
        ("error", 0),
        ("done", done),
        ("start_time", now),
        ("bytes_processed", bytes_proc),
    ])
    progress = OrderedDict([
        ("start_time", now),
        ("content_length", content_length),
        ("bytes_processed", bytes_proc),
        ("done", done),
        ("files", OrderedDict([(0, files0)])),
    ])
    return "upload_progress_%s|%s" % (prog, _php_serialize(progress))


def _advance_s2_progress(sessid, st):
    """Monotonic bytes_processed; flip done when catching content_length."""
    cl = int(st.get("content_length") or 1)
    cur = int(st.get("bytes_processed") or 0)
    if cur >= cl:
        new_bp, done = cl, True
    else:
        bump = max(1, (cl - cur) // 3)
        new_bp = min(cl, cur + bump)
        done = new_bp >= cl
    return touch_state(
        sessid,
        stage="s2_done",
        bytes_processed=new_bp,
        done=done,
        s2_attempted=True,
        s2_at=time.time(),
    )


def _should_race_flake(st):
    """~20–30% of S2 within ~300ms of S1 (or first probe) → 404; retry OK."""
    if not st:
        return False
    if os.environ.get("ANGLERFISH_PHP2SHELL_NO_FLAKE", "").strip() in (
            "1", "true", "yes", "on"):
        return False
    now = time.time()
    s1_at = float(st.get("s1_at") or 0)
    first = not st.get("s2_attempted")
    within = s1_at and (now - s1_at) <= RACE_FLAKE_WINDOW_SEC
    if first or within:
        return random.randint(1, 100) <= RACE_FLAKE_PCT
    return False


def s1_soft_fail_html(company, progress_name="", sessid=""):
    """Vary soft-fail wording slightly by sessid; reflect sanitized progress."""
    prog = sanitize_marker(progress_name, PROGRESS_NAME_MAX) or "upload"
    salt = (sum(ord(c) for c in (sessid or prog)) % 3)
    tails = (
        "Try again later.",
        "Please retry shortly.",
        "Disk tmp busy; retry.",
    )
    msg = ("Upload failed: temporary directory full (progress=%s). %s"
           % (prog, tails[salt]))
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>Upload — %s</title>"
        "<link rel=stylesheet href=/assets/app.css></head><body>"
        "<main class=wrap><h1>Upload</h1><p class=err>%s</p>"
        "<p><a href=/upload.php>Back</a></p></main></body></html>"
    ) % (company, msg)


def _extract_shell_cmd(query="", body=b""):
    """Pull cmd-looking param from query or body. Never executes it."""
    keys = ("cmd", "c", "command", "exec", "do", "run", "shell")
    q = query or ""
    for part in q.split("&"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.lower() in keys:
            try:
                from urllib.parse import unquote_plus
                return unquote_plus(v)[:500]
            except Exception:
                return v[:500]
    raw = body or b""
    if isinstance(raw, str):
        raw = raw.encode("latin-1", "replace")
    text_b = bytes(raw[:4096]).decode("latin-1", "replace")
    for part in text_b.replace("\n", "&").split("&"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip().lower() in keys:
            try:
                from urllib.parse import unquote_plus
                return unquote_plus(v.strip())[:500]
            except Exception:
                return v.strip()[:500]
    stripped = text_b.strip()
    if stripped and len(stripped) <= 200 and all(
            32 <= ord(ch) < 127 for ch in stripped):
        low = stripped.lower()
        if any(tok in low for tok in (
                "whoami", "id", "uname", "ls", "sudo", "cat", "pwd",
                "ps", "curl", "wget", "echo", "bash", "nc ", "ncat",
                "python", "perl", "php ", "/dev/tcp", "chmod", "touch")):
            return stripped[:500]
    return ""


def _fake_shell_gate_ok(st):
    """Felt-win cmds only after FAKE_LEAK or >= s2."""
    if not st:
        return False
    if st.get("fake_leak_fired"):
        return True
    return st.get("stage") in ("s2_done", "s3_seen", "s4_seen")


_BAIT_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
    "clinic:x:1001:1001:Clinic App:/home/clinic:/bin/bash\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
)

_WRITE_PATH_RE = re.compile(
    r"(>{1,2}|\btee\b)\s*([~/\w.\-]+)",
    re.I,
)
_FETCH_URL_RE = re.compile(
    r"(?i)(?:curl|wget)\b[^\s]*\s+(?:-[a-zA-Z]*\s+)*"
    r"['\"]?(https?://[^\s'\";|&]+|[^\s'\";|&]+\.[^\s'\";|&]+)"
)
_REV_SHELL_RE = re.compile(
    r"(?is)(/dev/tcp/|bash\s+-i|/dev/udp/|"
    r"\bnc\b.{0,40}\s-e\b|\bncat\b.{0,40}\s-e\b|"
    r"socket\.connect|reverse.?shell|mkfifo.{0,40}/dev/tcp|"
    r"python.{0,80}socket|perl.{0,80}socket|"
    r"php.{0,80}fsockopen|socat.{0,40}exec)",
)



def _looks_like_write(c):
    """Detect echo/redirect/tee/write toward bait paths. Never writes FS."""
    if ">>" in c or re.search(r"(?<![0-9])>(?!>)", c):
        return True
    if re.search(r"\btee\b", c):
        return True
    if re.search(r"\b(touch|chmod|chown)\b\s+/", c):
        return True
    if re.search(r"\b(touch|chmod|chown)\b\s+~", c):
        return True
    return False


def _write_target_path(c):
    m = _WRITE_PATH_RE.search(c or "")
    if m:
        return m.group(2)
    m2 = re.search(r"\b(?:touch|chmod|chown)\b\s+([~/\w.\-]+)", c or "", re.I)
    if m2:
        return m2.group(1)
    return ""


def _extract_fetch_url(cmd):
    """Pull URL-ish arg from curl/wget. Never fetched."""
    c = cmd or ""
    m = _FETCH_URL_RE.search(c)
    if m:
        return m.group(1)[:300]
    m2 = re.search(r"(https?://[^\s'\";|&]+)", c, re.I)
    if m2:
        return m2.group(1)[:300]
    parts = c.split()
    for i, p in enumerate(parts):
        pl = p.lower()
        if pl in ("curl", "wget", "/usr/bin/curl", "/usr/bin/wget"):
            for q in parts[i + 1:]:
                if q.startswith("-") and q not in ("-O",):
                    # skip single-letter flag clusters; keep bare args
                    if len(q) <= 3:
                        continue
                    continue
                if q in ("-O", "-o", "--output"):
                    continue
                return q.strip("'\"")[:300]
            break
    return ""


def _empty_persist_overlay():
    return {
        "files": {},
        "crontab": None,
        "procs": [],
        "c2_peer": None,
        "webshells": [],
    }


def _overlay_for(fam):
    """Return (and create) in-memory persist overlay for sess_family.

    Caller must NOT hold _lock; this acquires it once (Lock is not reentrant).
    """
    key = fam or "_"
    with _lock:
        ov = _PERSIST_OVERLAY.get(key)
        if ov is None:
            ov = _empty_persist_overlay()
            _PERSIST_OVERLAY[key] = ov
        return ov


def _overlay_snapshot(fam):
    """Copy overlay fields for safe reads outside lock."""
    key = fam or "_"
    with _lock:
        ov = _PERSIST_OVERLAY.get(key)
        if ov is None:
            return _empty_persist_overlay()
        return {
            "files": dict(ov.get("files") or {}),
            "crontab": ov.get("crontab"),
            "procs": list(ov.get("procs") or []),
            "c2_peer": ov.get("c2_peer"),
            "webshells": list(ov.get("webshells") or []),
        }


def _overlay_set_file(fam, path, content):
    key = fam or "_"
    with _lock:
        ov = _PERSIST_OVERLAY.get(key)
        if ov is None:
            ov = _empty_persist_overlay()
            _PERSIST_OVERLAY[key] = ov
        ov["files"][path] = content if content is not None else ""


def _overlay_set_crontab(fam, text):
    key = fam or "_"
    with _lock:
        ov = _PERSIST_OVERLAY.get(key)
        if ov is None:
            ov = _empty_persist_overlay()
            _PERSIST_OVERLAY[key] = ov
        ov["crontab"] = text if text is not None else ""


def _overlay_add_proc(fam, proc):
    if not proc:
        return
    key = fam or "_"
    with _lock:
        ov = _PERSIST_OVERLAY.get(key)
        if ov is None:
            ov = _empty_persist_overlay()
            _PERSIST_OVERLAY[key] = ov
        if proc not in ov["procs"]:
            ov["procs"].append(proc)
        ov["procs"] = ov["procs"][-2:]


def _overlay_set_c2_peer(fam, peer):
    if not peer:
        return
    key = fam or "_"
    with _lock:
        ov = _PERSIST_OVERLAY.get(key)
        if ov is None:
            ov = _empty_persist_overlay()
            _PERSIST_OVERLAY[key] = ov
        ov["c2_peer"] = peer


def _overlay_add_webshell(fam, path):
    if not path:
        return
    key = fam or "_"
    with _lock:
        ov = _PERSIST_OVERLAY.get(key)
        if ov is None:
            ov = _empty_persist_overlay()
            _PERSIST_OVERLAY[key] = ov
        if path not in ov["webshells"]:
            ov["webshells"].append(path)
        ov["files"].setdefault(path, "")


_SSH_KEY_PATH_RE = re.compile(
    r"(?i)(?:authorized_keys)|"
    r"(?:(?:~|/root|/var/www|/home/[\w.-]+)/\.ssh(?:/authorized_keys)?)"
)


_CRON_PATH_RE = re.compile(
    r"(?i)(?:/etc/cron\.d/[\w.-]+|"
    r"/var/spool/cron/crontabs/[\w.-]+|"
    r"/etc/crontab)$"
)

_MINER_LEAVES = frozenset({
    "bot", "x", ".x", "xmrig", "kinsing", "redtail", "busybox",
    "m", "f", "a.out",
})

_SS_NETSTAT_RE = re.compile(
    r"^(?:ss|netstat)\b",
    re.I,
)


def _normalize_ssh_path(path):
    p = (path or "").strip()
    if p.startswith("~/"):
        p = "/var/www/" + p[2:]
    elif p == "~":
        p = "/var/www"
    if p.endswith("/.ssh") or p.endswith("/.ssh/"):
        p = p.rstrip("/") + "/authorized_keys"
    return p


def _is_ssh_key_path(path):
    p = (path or "").strip()
    if not p:
        return False
    if "authorized_keys" in p.lower():
        return True
    if "/.ssh" in p.lower() or p.startswith("~/.ssh"):
        return True
    return False


def _is_webshell_path(path):
    p = (path or "").lower()
    if not p.endswith(".php"):
        return False
    return (
        p.startswith("/uploads")
        or p.startswith("/tmp")
        or p.startswith("/var/tmp")
        or p.startswith("/var/www")
        or "shell" in p
    )


def _extract_echo_payload(cmd):
    """Best-effort payload from echo '...' / echo \"...\" / echo word."""
    raw = cmd or ""
    m = re.search(r"""\becho\s+(?:-e\s+)?(['"])(.*?)\1""", raw, re.I | re.S)
    if m:
        return m.group(2)
    m2 = re.search(r"""\becho\s+(?:-e\s+)?(\S+)""", raw, re.I)
    if m2:
        return m2.group(1)
    return ""


def _peer_from_url(url):
    """host:port from URL; never connects. Default :80 / :443 by scheme."""
    u = (url or "").strip()
    if not u:
        return ""
    m = re.match(r"(?i)^(https?)://([^/\s:]+)(?::(\d+))?", u)
    if m:
        scheme, host, port = m.group(1).lower(), m.group(2), m.group(3)
        if not port:
            port = "443" if scheme == "https" else "80"
        return "%s:%s" % (host, port)
    m2 = re.match(r"(?i)^([^/\s:]+)(?::(\d+))?", u)
    if m2:
        return "%s:%s" % (m2.group(1), m2.group(2) or "80")
    return ""


def _plant_proc_name(cmd):
    """Leaf / path to show in decoy ps after chmod/nohup/./bot."""
    raw = (cmd or "").strip()
    raw = re.sub(r"(?i)^nohup\s+", "", raw)
    raw = re.sub(r"\s*&\s*$", "", raw)
    for tok in raw.split():
        if tok.startswith("-"):
            continue
        if tok.lower() in ("chmod", "chown", "touch", "bash", "sh", "nohup"):
            continue
        if "/" in tok or tok.startswith("./") or tok.lower().strip("./") in _MINER_LEAVES:
            return tok
    # fallback: last non-flag token
    toks = [t for t in raw.split() if not t.startswith("-")]
    if toks:
        return toks[-1]
    return "./bot"


def _is_run_plant_cmd(c, cmd):
    """nohup / ./bot / /tmp/bot / miner leaf — claim exec, never run."""
    if re.search(r"(?i)\bnohup\b", c):
        return True
    toks = c.split()
    if not toks:
        return False
    first = toks[0]
    if first.startswith("./"):
        return True
    if first.startswith("/tmp/") or first.startswith("/var/tmp/"):
        leaf = first.rstrip("/").split("/")[-1]
        if leaf in _MINER_LEAVES or leaf.startswith("."):
            return True
    leaf0 = first.strip("./")
    if leaf0 in _MINER_LEAVES and not first.startswith("chmod"):
        # bare `kinsing` / `xmrig` / `bot`
        if first in _MINER_LEAVES or first.strip("./") in _MINER_LEAVES:
            return True
    return False


def _is_chmod_cmd(c):
    return bool(re.match(r"(?i)^chmod\b", c or ""))


def _cron_write_target(c, cmd):
    """Return cron overlay path key or 'crontab' if this is a crontab install."""
    if re.search(r"(?i)\bcrontab\b", c) and not re.search(r"(?i)\bcrontab\s+-l\b", c):
        return "crontab"
    m = _WRITE_PATH_RE.search(c or "")
    if m:
        tgt = m.group(2)
        if _CRON_PATH_RE.search(tgt):
            return tgt
    return ""


def _ps_decoy(host, salt, extra_procs=None, fam=""):
    """Plausible www-data / apache process list; varies slightly per family."""
    pid_base = 1200 + (salt * 17)
    extra = ""
    if salt == 1:
        extra = (
            "www-data  %d  0.0  0.5 312440 21488 ?  S  09:14  0:00 "
            "php-fpm: pool www\n" % (pid_base + 40)
        )
    elif salt == 2:
        extra = (
            "www-data  %d  0.0  0.2  18944  3456 ?  S  10:02  0:00 "
            "/usr/sbin/apache2 -k start\n" % (pid_base + 55)
        )
    out = (
        "USER         PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   "
        "TIME COMMAND\n"
        "root        %d  0.0  0.1  16356  2048 ?  Ss   08:01  0:01 "
        "/usr/sbin/apache2 -k start\n"
        "www-data    %d  0.0  0.6 362880 24832 ?  S    08:01  0:03 "
        "/usr/sbin/apache2 -k start\n"
        "www-data    %d  0.1  0.7 364112 28960 ?  S    08:01  0:05 "
        "/usr/sbin/apache2 -k start\n"
        "www-data    %d  0.0  0.5 361200 22112 ?  S    09:12  0:01 "
        "/usr/sbin/apache2 -k start\n"
        "%s"
        "www-data    %d  0.0  0.1   7336  3200 pts/0  S+   12:04  0:00 "
        "ps aux\n"
    ) % (pid_base, pid_base + 1, pid_base + 2, pid_base + 3, extra,
         pid_base + 9)
    if extra_procs:
        sticky = 4000 + (sum(ord(ch) for ch in (fam or "x")) % 500)
        lines = []
        for i, proc in enumerate(list(extra_procs)[:2]):
            lines.append(
                "www-data    %d  0.3  1.2  98200 48960 ?  Sl   12:10  0:12 "
                "%s\n" % (sticky + i, proc)
            )
        out = out.rstrip("\n") + "\n" + "".join(lines)
    return out


def _ss_decoy(c2_peer, salt=0):
    """Fake ss/netstat table — one ESTABLISHED to c2_peer if set. No sockets."""
    if salt == 1:
        header = (
            "Proto Recv-Q Send-Q Local Address           Foreign Address"
            "         State       PID/Program name\n"
        )
        listen = (
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*"
            "               LISTEN      1200/apache2\n"
            "tcp        0      0 0.0.0.0:443             0.0.0.0:*"
            "               LISTEN      1200/apache2\n"
        )
        if c2_peer:
            local_port = 40000 + (sum(ord(ch) for ch in c2_peer) % 20000)
            listen += (
                "tcp        0      0 10.0.0.21:%d         %s"
                "           ESTABLISHED 33/www-data\n"
                % (local_port, c2_peer)
            )
        return header + listen
    header = (
        "Netid State      Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
    )
    listen = (
        "tcp   LISTEN     0      128          0.0.0.0:80         0.0.0.0:*\n"
        "tcp   LISTEN     0      128          0.0.0.0:443        0.0.0.0:*\n"
    )
    if c2_peer:
        local_port = 40000 + (sum(ord(ch) for ch in c2_peer) % 20000)
        listen += (
            "tcp   ESTAB      0      0      10.0.0.21:%d     %s\n"
            % (local_port, c2_peer)
        )
    return header + listen


def _fake_persist_cat(c, fam, extras, trailer):
    """Serve overlay file / crontab content for cat/head. Never real FS."""
    m = re.match(
        r"^(?:cat|head|nl|more|less)\s+([~\w./\-]+)$", c or "")
    if not m:
        return None
    path = m.group(1)
    ov = _overlay_snapshot(fam)
    # crontab paths
    if _CRON_PATH_RE.search(path):
        body = ov["files"].get(path)
        if body is None and ov.get("crontab") is not None and (
                "crontab" in path or path.endswith("www-data")):
            body = ov["crontab"]
        if body is not None:
            extras["bait_fake_persist"] = True
            extras["fake_shell_persist"] = "cron"
            if body and not body.endswith("\n"):
                body += "\n"
            return (body or "\n") , extras
    # ssh / generic overlay files
    candidates = [path, _normalize_ssh_path(path)]
    for cand in candidates:
        if cand in ov["files"]:
            extras["bait_fake_persist"] = True
            if _is_ssh_key_path(cand):
                extras["fake_shell_persist"] = "ssh_keys"
            elif _is_webshell_path(cand):
                extras["fake_shell_persist"] = "webshell"
            body = ov["files"][cand]
            if body and not str(body).endswith("\n"):
                body = str(body) + "\n"
            return (body or "\n"), extras
    return None


def _fake_persist_crontab(c, cmd, fam, extras, trailer):
    """Handle crontab -l / crontab install. Overlay only."""
    if re.match(r"(?i)^crontab\s+-l\b", c) or c in (
            "crontab -l", "crontab -l -u www-data"):
        ov = _overlay_snapshot(fam)
        extras["bait_fake_persist"] = True
        extras["fake_shell_persist"] = "cron"
        if ov.get("crontab") is None:
            return "no crontab for www-data\n", extras
        body = ov["crontab"] or ""
        if body and not body.endswith("\n"):
            body += "\n"
        return body if body else "\n", extras

    cron_tgt = _cron_write_target(c, cmd)
    if not cron_tgt:
        return None
    payload = _extract_echo_payload(cmd)
    if not payload and "|" in (cmd or "") and "crontab" in c:
        # echo 'line' | crontab -  — payload already attempted; allow empty
        payload = _extract_echo_payload(cmd)
    if cron_tgt == "crontab":
        _overlay_set_crontab(fam, payload or "")
    else:
        _overlay_set_file(fam, cron_tgt, payload or "")
        # also mirror into crontab text for -l convenience
        prev = _overlay_snapshot(fam).get("crontab") or ""
        if payload:
            merged = (prev + ("\n" if prev and not prev.endswith("\n") else "")
                      + payload)
            _overlay_set_crontab(fam, merged)
    extras["bait_fake_persist"] = True
    extras["fake_shell_persist"] = "cron"
    extras["fake_shell_write_claimed"] = sanitize_marker(cron_tgt, 120)
    return "\n", extras


def _fake_shell_decoy(cmd, st=None, hostname=None):
    """Allowlisted decoy output only. No exec/outbound/include.

    Returns (output_text, extras_dict). extras may include
    fake_shell_fetch_url for research logging.
    """
    host = hostname or CLINIC_HOSTNAME
    st = st or {}
    fam = st.get("sess_family") or sess_family(st.get("sessid") or "")
    salt = sum(ord(ch) for ch in (fam or "x")) % 3
    trailer = "\n" * (1 + (salt % 2))
    c = (cmd or "").strip().lower()
    c = " ".join(c.split())
    extras = {}
    persist_on = fake_persist_enabled()

    if c in ("whoami", "/usr/bin/whoami"):
        return "www-data" + trailer, extras
    if c in ("sudo whoami", "sudo /usr/bin/whoami"):
        return "root" + trailer, extras
    if c in ("id", "/usr/bin/id"):
        return ("uid=33(www-data) gid=33(www-data) groups=33(www-data)"
                + trailer), extras
    if c in ("sudo id", "sudo /usr/bin/id", "sudo -i", "sudo -i id",
             "sudo su", "sudo su -"):
        return ("uid=0(root) gid=0(root) groups=0(root)" + trailer), extras
    if c in ("uname", "uname -a", "/bin/uname -a", "uname -m"):
        if c.endswith("-m"):
            return "x86_64" + trailer, extras
        return (
            "Linux %s 6.8.0-1017-aws #19-Ubuntu SMP "
            "x86_64 x86_64 x86_64 GNU/Linux%s" % (host, trailer)), extras
    if c in ("pwd",):
        return "/var/www/html" + trailer, extras

    # hostname
    if c in ("hostname", "cat /etc/hostname", "cat /etc/hostname.txt"):
        return host + trailer, extras

    # /etc/passwd bait (never real host)
    if c in ("cat /etc/passwd", "head /etc/passwd", "nl /etc/passwd"):
        body = _BAIT_PASSWD
        if salt == 1:
            body = body + "backup:x:1002:1002::/home/backup:/bin/bash\n"
        elif salt == 2:
            body = body.replace(
                "clinic:x:1001:1001:Clinic App:/home/clinic:/bin/bash\n", "")
        return body, extras

    # --- fake persist overlay (flag default OFF) ---
    if persist_on:
        hit = _fake_persist_crontab(c, cmd, fam, extras, trailer)
        if hit is not None:
            return hit
        hit = _fake_persist_cat(c, fam, extras, trailer)
        if hit is not None:
            return hit

    # ps / ps aux (+ optional planted miner procs when flag on)
    if c in ("ps", "ps aux", "ps -ef", "ps auxww", "ps -aux"):
        procs = None
        if persist_on:
            procs = _overlay_snapshot(fam).get("procs") or None
        return _ps_decoy(host, salt, extra_procs=procs, fam=fam), extras

    # ss / netstat — fake table only; never open sockets
    if persist_on and _SS_NETSTAT_RE.match(c):
        peer = _overlay_snapshot(fam).get("c2_peer")
        extras["bait_fake_c2"] = True
        return _ss_decoy(peer, salt=salt), extras

    # curl / wget — never fetch; log URL via extras
    if (c.startswith("curl") or c.startswith("wget")
            or c.startswith("/usr/bin/curl")
            or c.startswith("/usr/bin/wget")):
        url = _extract_fetch_url(cmd)
        if url:
            extras["fake_shell_fetch_url"] = sanitize_marker(url, 200)
            if persist_on:
                peer = _peer_from_url(url)
                if peer:
                    _overlay_set_c2_peer(fam, peer)
                    extras["bait_fake_c2"] = True
        if salt == 0:
            return "OK\n", extras
        if salt == 1:
            return (
                "  % Total    % Received % Xferd  Average Speed\n"
                "100   128  100   128    0     0   9999      0 --:--:-- "
                "--:--:-- --:--:--  9999\n"
                "HTTP/1.1 200 OK\n"), extras
        return "200 OK\nsaved\n", extras

    # reverse-shell one-liners → fake connected; no socket
    if _REV_SHELL_RE.search(cmd or "") or _REV_SHELL_RE.search(c):
        banners = (
            "connected\n",
            "Connection established to remote.\n",
            "bash: connect: Success\n",
        )
        return banners[salt], extras

    # chmod / nohup / ./bot quiet success (flag on) — never exec
    if persist_on and _is_chmod_cmd(c):
        target = _write_target_path(c) or ""
        extras["fake_shell_write_claimed"] = sanitize_marker(
            target or "chmod", 120)
        extras["bait_fake_persist"] = True
        return "\n", extras
    if persist_on and _is_run_plant_cmd(c, cmd):
        proc = _plant_proc_name(cmd)
        _overlay_add_proc(fam, proc)
        leaf = proc.rstrip("/").split("/")[-1]
        extras["fake_shell_exec_claimed"] = sanitize_marker(leaf or proc, 80)
        extras["bait_fake_c2"] = True
        extras["bait_fake_persist"] = True
        extras["fake_shell_persist"] = "proc"
        return "\n", extras

    # echo/redirect/write to bait paths — claim written; no real FS write
    if _looks_like_write(c):
        target = _write_target_path(c)
        # Fake-persist: sticky authorized_keys / cron file / webshell
        if persist_on and target and _is_ssh_key_path(target):
            path_n = _normalize_ssh_path(target)
            payload = _extract_echo_payload(cmd) or ""
            _overlay_set_file(fam, path_n, payload)
            extras["fake_shell_write_claimed"] = sanitize_marker(path_n, 120)
            extras["bait_fake_persist"] = True
            extras["fake_shell_persist"] = "ssh_keys"
            return "\n", extras
        if persist_on and target and _CRON_PATH_RE.search(target):
            payload = _extract_echo_payload(cmd) or ""
            _overlay_set_file(fam, target, payload)
            prev = _overlay_snapshot(fam).get("crontab") or ""
            if payload:
                merged = (prev + ("\n" if prev and not prev.endswith("\n")
                                  else "") + payload)
                _overlay_set_crontab(fam, merged)
            extras["fake_shell_write_claimed"] = sanitize_marker(target, 120)
            extras["bait_fake_persist"] = True
            extras["fake_shell_persist"] = "cron"
            return "\n", extras
        baitish = (
            not target
            or target.startswith("/uploads")
            or target.startswith("/tmp")
            or target.startswith("/var/tmp")
            or target.startswith("/var/www")
            or "shell" in target
            or target.endswith(".php")
            or target.endswith(".bin")
        )
        if baitish:
            extras["fake_shell_write_claimed"] = sanitize_marker(
                target or "bait", 120)
            if persist_on and target and _is_webshell_path(target):
                payload = _extract_echo_payload(cmd) or ""
                _overlay_add_webshell(fam, target)
                _overlay_set_file(fam, target, payload)
                extras["bait_fake_persist"] = True
                extras["fake_shell_persist"] = "webshell"
            if salt == 0:
                return "written\n", extras
            if salt == 1:
                return "wrote %s\n" % (target or "/uploads/shell.php"), extras
            return "\n", extras  # quiet success vibe

    if c.startswith("ls"):
        listing = [
            "shell.php",
            "p2s.php",
            "sess_canary.php",
            ".well-known-up.php",
            "upload.bin",
        ]
        if salt == 1:
            listing.append("index.html")
        elif salt == 2:
            listing.insert(0, ".")
            listing.insert(1, "..")
        if persist_on:
            ov = _overlay_snapshot(fam)
            for w in ov.get("webshells") or []:
                leaf = w.rstrip("/").split("/")[-1]
                if leaf and leaf not in listing:
                    listing.append(leaf)
            for fpath in (ov.get("files") or {}):
                if _is_webshell_path(fpath):
                    leaf = fpath.rstrip("/").split("/")[-1]
                    if leaf and leaf not in listing:
                        listing.append(leaf)
        return "\n".join(listing) + trailer, extras

    # Unknown cmds: generic empty / error (varies by sess_family)
    if salt == 0:
        return "", extras
    if salt == 1:
        tok = (cmd.strip().split() or ["?"])[0][:40]
        return "sh: 1: %s: not found\n" % tok, extras
    return "\n", extras



def s3_shell_stub(st=None, include_marker=False, hostname=None):
    """Default allowlist stub (no cmd). Used when gate/cmd absent."""
    host = hostname or CLINIC_HOSTNAME
    lines = [
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
        host,
        "PHP 8.4.26 (cli) (built: Sep 10 2026)",
    ]
    if include_marker and st and st.get("marker"):
        lines.append("marker=%s" % sanitize_marker(st.get("marker")))
    return "\n".join(lines) + "\n"


def s3_fake_shell_response(st, query="", body=b"", hostname=None):
    """Gated felt-win fake shell.

    Returns (body, used_fake_shell, cmd_raw, extras).
    """
    cmd = _extract_shell_cmd(query, body)
    if not cmd or not _fake_shell_gate_ok(st):
        include_marker = bool(st and st.get("stage") in (
            "s2_done", "s3_seen", "s4_seen"))
        return (s3_shell_stub(st, include_marker=include_marker,
                              hostname=hostname), False, cmd, {})
    out, extras = _fake_shell_decoy(cmd, st=st, hostname=hostname)
    return out, True, cmd, extras or {}


def s4_allow_url_fopen_reject():
    """PHP-ish reject with allow_url_fopen=On (matches phpinfo P1).

    Never claim download OK / never claim allow_url_fopen=0 (contradicts
    clinic phpinfo). Decoy: fopen tried, remote connect failed — matches
    firewalled outbound without contradicting On.
    """
    return (
        "<br />\n<b>Warning</b>:  file_get_contents(http://…): Failed to "
        "open stream: Connection refused in "
        "<b>/var/www/html/upload.php</b> on line <b>41</b><br />\n"
    )


def php2shell_oom_fatal_html():
    """Canned OOM fatal. Mix Unknown / upload.php — never /opt/anglerfish."""
    # Alternate path shape for realism; both clinic-shaped.
    if random.randint(0, 1) == 0:
        where = "<b>Unknown</b> on line <b>0</b>"
    else:
        where = "<b>/var/www/html/upload.php</b> on line <b>0</b>"
    return (
        "<br />\n"
        "<b>Fatal error</b>:  Allowed memory size of 134217728 bytes exhausted"
        " (tried to allocate 65536 bytes) in %s<br />\n" % where
    )


def apache_404_html(hostname=None):
    """Apache-shaped 404 consistent with phpapp.apache_error / clinic host."""
    host = hostname or CLINIC_HOSTNAME
    return (
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
        "<html><head>\n"
        "<title>404 Not Found</title>\n"
        "</head><body>\n"
        "<h1>Not Found</h1>\n"
        "<p>The requested URL was not found on this server.</p>\n"
        "<hr>\n"
        "<address>Apache/2.4.58 (Ubuntu) Server at %s Port 80</address>\n"
        "</body></html>\n" % host
    )


def _s2_sess_path_sid(clean):
    m = _S2_SESS_PATH_RE.match(clean or "")
    return m.group(1) if m else None


def _lfi_param_target(query):
    """Profile P1: extract ?page= / ?file= value; never opens FS."""
    q = query or ""
    if not q:
        return ""
    for part in q.split("&"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.lower() in ("page", "file", "path", "include", "doc", "pg"):
            v = v.replace("+", " ")
            try:
                from urllib.parse import unquote
                v = unquote(v)
            except Exception:
                pass
            return v.strip()
    return ""


def _s4_should_trigger(clean, query, body):
    """Narrow S4: upload/php2shell routes with url=, or body indicators."""
    on_route = (
        clean in _UPLOAD_ROUTES
        or clean in _S2_PROGRESS_PATHS
        or clean.startswith("/uploads/")
        or clean in SHELL_ALLOWLIST
    )
    q = query or ""
    if on_route and "url=" in q:
        return True
    raw = body or b""
    if isinstance(raw, str):
        raw = raw.encode("latin-1", "replace")
    low = bytes(raw[:4096]).lower()
    if (b"file_get_contents" in low
            or b"curl|bash" in low
            or b"curl | bash" in low
            or b"wget " in low and b"| bash" in low
            or b"allow_url_fopen" in low):
        return True
    return False


def note_drop_probe(sessid, path):
    """Record drop-path probe (allowlist or dictionary) for research."""
    if not path:
        return None
    sid = sessid or ""
    st = get_state(sid) if sid else None
    probed = list((st or {}).get("drop_paths_probed") or [])
    if path not in probed:
        probed.append(path[:200])
        probed = probed[-32:]
    if sid:
        return touch_state(sid, drop_paths_probed=probed)
    return {"drop_paths_probed": probed}


def is_drop_probe_path(path):
    clean = (path or "/").split("?", 1)[0]
    if clean in DROP_PROBE_PATHS:
        return True
    # Heuristic: uploads/*.php that aren't clinic app pages
    if clean.startswith("/uploads/") and clean.endswith(".php"):
        return True
    return False


# --- research capture: multipart meta + quarantine sample --------------------

def extract_multipart_meta(body_prefix, content_type=""):
    """Parse field names / filenames / part types from a capped prefix."""
    text = ""
    if isinstance(body_prefix, (bytes, bytearray)):
        text = bytes(body_prefix).decode("latin-1", "replace")
    else:
        text = body_prefix or ""
    field_names = re.findall(r'(?i)name="([^"]{1,128})"', text)
    filenames = re.findall(r'(?i)filename="([^"]{0,200})"', text)
    part_types = re.findall(r"(?im)^Content-Type:\s*([^\r\n]+)", text)
    boundary = ""
    m = re.search(r"(?i)boundary=([^\s;]+)", content_type or "")
    if m:
        boundary = m.group(1).strip().strip('"')
    if not boundary:
        m2 = re.search(r"(?m)^--([A-Za-z0-9'()+_,-./:=?]{4,70})\r?$", text)
        if m2:
            boundary = m2.group(1)
    # Dedupe preserve order
    def _uniq(seq):
        seen = set()
        out = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
    return {
        "multipart_field_names": _uniq(field_names)[:32],
        "multipart_filenames": _uniq(filenames)[:16],
        "multipart_part_types": _uniq([p.strip() for p in part_types])[:16],
        "multipart_boundary": boundary[:80],
    }


def persist_body_sample(body_prefix, when=None):
    """
    Quarantine capped sample under non-webroot SAMPLE_DIR.
    Keep first 64KiB OR up to 3×32KiB part slices. Never full 140MB.
    Returns dict with sha256/path/len or error; never raises to caller path.
    """
    raw = body_prefix or b""
    if isinstance(raw, str):
        raw = raw.encode("latin-1", "replace")
    raw = bytes(raw)
    if not raw:
        return None
    # Prefer whole prefix up to 64KiB; if larger inspect buffer, still store ≤64KiB
    # unless we can slice ≤3 parts at 32KiB each (whichever smaller total).
    sample = raw[:SAMPLE_KEEP_CAP]
    try:
        text = raw[:INSPECT_PREFIX_CAP].decode("latin-1", "replace")
        parts = re.split(r"(?m)^--[A-Za-z0-9'()+_,-./:=?]{4,70}(?:--)?\r?$", text)
        slices = []
        for p in parts:
            if "filename=" in p.lower() or "name=" in p.lower():
                chunk = p.encode("latin-1", "replace")[:SAMPLE_PART_CAP]
                if chunk:
                    slices.append(chunk)
            if len(slices) >= SAMPLE_MAX_PARTS:
                break
        if slices:
            joined = b"\n".join(slices)
            if len(joined) <= SAMPLE_KEEP_CAP or len(slices) > 1:
                sample = joined[: SAMPLE_PART_CAP * SAMPLE_MAX_PARTS]
    except Exception:
        pass
    digest = hashlib.sha256(sample).hexdigest()
    day = time.strftime("%Y%m%d", time.localtime(when or time.time()))
    base = sample_dir()
    dest_dir = os.path.join(base, day)
    dest = os.path.join(dest_dir, "%s.bin" % digest)
    try:
        os.makedirs(dest_dir, mode=0o700, exist_ok=True)
        if not os.path.exists(dest):
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, sample)
            finally:
                os.close(fd)
        else:
            try:
                os.chmod(dest, 0o600)
            except OSError:
                pass
        return {
            "body_sample_sha256": digest,
            "body_sample_path": dest,
            "body_sample_len": len(sample),
        }
    except OSError as exc:
        return {
            "body_sample_sha256": digest,
            "body_sample_path": "",
            "body_sample_len": len(sample),
            "body_sample_error": str(exc)[:160],
        }


def research_event_fields(st=None, p2s=None, meta=None, sample=None,
                          stage_delta_ms=None, drop_path=None):
    """Extras for campaign clustering / research (safe, no payload exec)."""
    st = st or {}
    p2s = p2s or {}
    meta = meta or {}
    sample = sample or {}
    sid = st.get("sessid") or p2s.get("phpsessid_echo") or ""
    out = {
        "phpsessid_sha256": phpsessid_sha256(sid) or None,
        "phpsessid_head_tail": phpsessid_head_tail(sid) or None,
        "campaign_key": st.get("campaign_key") or None,
        "sess_family": st.get("sess_family") or sess_family(sid) or None,
        "drop_paths_probed": list(st.get("drop_paths_probed") or []) or None,
        "multipart_filenames": meta.get("multipart_filenames") or None,
        "multipart_field_names": meta.get("multipart_field_names") or None,
        "multipart_part_types": meta.get("multipart_part_types") or None,
        "multipart_boundary": meta.get("multipart_boundary") or None,
        "body_sample_sha256": sample.get("body_sample_sha256") or None,
        "body_sample_path": sample.get("body_sample_path") or None,
        "body_sample_len": sample.get("body_sample_len"),
        "stage_delta_ms": stage_delta_ms,
    }
    if drop_path:
        out["php2shell_drop_probe"] = drop_path
    return {k: v for k, v in out.items() if v is not None}


def s1_delay_sec():
    lo, hi = S1_DELAY_MS
    return random.randint(lo, hi) / 1000.0


def route(path, method="GET", query="", sessid="", body=b"", p2s=None,
          company="Example Clinic", declared_length=0, hostname=None,
          src_ip="", ua="", apply_s1_delay=False):
    """
    Return (body, content_type, status, set_cookie_value, shape, stage,
            research_meta) or None if this module should not handle.

    set_cookie_value is raw 'PHPSESSID=...; path=/' or ''.
    Only active when fullchain_enabled().
    """
    if not fullchain_enabled():
        return None

    clean = (path or "/").split("?", 1)[0]
    method = (method or "GET").upper()
    query = query or ""
    p2s = p2s or {}
    host = hostname or CLINIC_HOSTNAME
    declared = int(declared_length or p2s.get("declared_length") or 0)

    # Resolve B1 junk / truncated leak cookie → original sid before any gating.
    raw_in = sessid or p2s.get("phpsessid_echo") or ""
    sid = resolve_sessid(raw_in)
    if not sid:
        sid = mint_sessid()
    cookie = "PHPSESSID=%s; path=/" % sid

    # Drop-path dictionary logging (even when we 404).
    research = {}
    if is_drop_probe_path(clean):
        note_drop_probe(sid, clean)
        research["php2shell_drop_probe"] = clean

    # S1: upload POST with progress indicators
    if method == "POST" and clean in _UPLOAD_ROUTES:
        if p2s.get("has_upload_progress") or p2s.get("hit") or (
                b"PHP_SESSION_UPLOAD_PROGRESS" in (body or b"")):
            meta = extract_multipart_meta(
                body or b"", p2s.get("content_type") or "")
            sample = persist_body_sample(body or b"")
            st = note_s1(
                sid,
                progress_name=p2s.get("progress_name") or "",
                body_prefix=body or b"",
                payload_urls=p2s.get("payload_urls"),
                declared_length=declared,
                src_ip=src_ip,
                ua=ua,
            )
            if apply_s1_delay:
                try:
                    time.sleep(s1_delay_sec())
                except Exception:
                    pass
            # OOM sticky-once when flag on + huge CL + progress
            if (oom_shape_enabled()
                    and declared >= OOM_SHAPE_CL
                    and not st.get("oom_fired")):
                st = touch_state(sid, oom_fired=True)
                research.update(research_event_fields(st, p2s, meta, sample))
                cookie, research = maybe_attach_fake_leak(st, cookie, research)
                return (php2shell_oom_fatal_html(), "text/html; charset=utf-8",
                        500, cookie, "oom_fatal_500", "oom_producer_shape",
                        research)
            html = s1_soft_fail_html(
                company, st.get("progress_name") or "", sid)
            research.update(research_event_fields(st, p2s, meta, sample))
            # S4 body indicators on same POST still soft-fail (prefer continue)
            if _s4_should_trigger(clean, query, body) and p2s.get("payload_urls"):
                # Log-only; body stays soft-fail for research prefer-continue.
                research["s4_urls_logged_not_fetched"] = list(
                    p2s.get("payload_urls") or [])[:5]
            # B1 fake-leak (default ON): sticky-once huge PHPSESSID cookie
            cookie, research = maybe_attach_fake_leak(st, cookie, research)
            return (html, "text/html; charset=utf-8", 200, cookie,
                    "soft_fail_200", "s1_upload", research)

    # S4: scoped second-stage fetch attempt
    if _s4_should_trigger(clean, query, body):
        st = touch_state(sid, stage="s4_seen")
        delta = None
        if st.get("s1_at"):
            delta = int((time.time() - float(st["s1_at"])) * 1000)
        research.update(research_event_fields(st, p2s, stage_delta_ms=delta))
        return (s4_allow_url_fopen_reject(), "text/html; charset=utf-8", 200,
                cookie, "allow_url_fopen_reject",
                "s4_callback_logged_not_fetched", research)

    # Profile P1 LFI: ?page= / ?file= → S2 sess map if sid matches else
    # drop_probe. Never touches the filesystem.
    lfi_target = _lfi_param_target(query)
    sess_path_sid_from_lfi = None
    if lfi_target:
        lt = lfi_target if lfi_target.startswith("/") else ("/" + lfi_target)
        lfi_sess_sid = _s2_sess_path_sid(lt)
        if not lfi_sess_sid:
            m = re.search(r"(?:^|/)sess_([A-Za-z0-9,-]{1,128})$", lt)
            if m:
                lfi_sess_sid = m.group(1)
        if lfi_sess_sid and lfi_sess_sid == sid:
            sess_path_sid_from_lfi = lfi_sess_sid
        else:
            probe = ("lfi:" + lfi_target)[:200]
            note_drop_probe(sid, probe)
            research["php2shell_drop_probe"] = probe
            research["lfi_param"] = True
            research.update(research_event_fields(
                get_state(sid), p2s, drop_path=probe))
            return (apache_404_html(), "text/html; charset=iso-8859-1", 404,
                    "", "apache_404", "lfi_drop_probe", research)

    # S2: progress endpoints OR sess_* path map (sid must match)
    sess_path_sid = _s2_sess_path_sid(clean) or sess_path_sid_from_lfi
    is_progress = (
        clean in _S2_PROGRESS_PATHS
        or (clean in ("/upload.php", "/index.php") and (
            "progress=" in query or query == "progress"
            or "progress" in query.split("&")[0]))
    )
    if is_progress or sess_path_sid:
        if sess_path_sid and sess_path_sid != sid:
            # Unknown / mismatched sess → Apache 404 (no arbitrary LFI)
            return (apache_404_html(), "text/html; charset=iso-8859-1", 404,
                    cookie, "apache_404", "s2_sess_mismatch", research)
        st = get_state(sid)
        if not st or st.get("stage") not in (
                "s1_done", "s2_done", "s3_seen", "s4_seen"):
            return (apache_404_html(), "text/html; charset=iso-8859-1", 404,
                    cookie, "apache_404", "s2_no_state", research)
        # Race flake: first probe / within 300ms of S1
        if _should_race_flake(st):
            touch_state(sid, s2_attempted=True)
            research.update(research_event_fields(st, p2s))
            research["race_flake"] = True
            return (apache_404_html(), "text/html; charset=iso-8859-1", 404,
                    cookie, "apache_404", "s2_race_flake", research)
        st = _advance_s2_progress(sid, st)
        delta = None
        if st.get("s1_at"):
            delta = int((time.time() - float(st["s1_at"])) * 1000)
        blob = s2_session_blob(st)
        # Red Delta B: raw sess_* → bare text/plain; omit X-Powered-By upstream
        if sess_path_sid:
            ctype = "text/plain"
            research["omit_x_powered_by"] = True
            research["raw_sess_file"] = True
        else:
            ctype = "text/plain; charset=utf-8"
        research.update(research_event_fields(st, p2s, stage_delta_ms=delta))
        return (blob, ctype, 200, cookie, "session_blob",
                "s2_marker_reflect", research)

    # S3: shell allowlist — gated on prior S1; felt-win cmds after leak/>=s2
    if clean in SHELL_ALLOWLIST:
        note_drop_probe(sid, clean)
        st = get_state(sid)
        if not st or st.get("stage") not in (
                "s1_done", "s2_done", "s3_seen", "s4_seen"):
            research.update(research_event_fields(st, p2s, drop_path=clean))
            return (apache_404_html(), "text/html; charset=iso-8859-1", 404,
                    "", "apache_404", "s3_gated_404", research)
        body_out, used_fake, cmd_raw, shell_extras = s3_fake_shell_response(
            st, query=query, body=body, hostname=host)
        if cmd_raw:
            # Quarantine cmd input bytes as .bin — never exec
            sample = persist_body_sample(
                (cmd_raw if isinstance(cmd_raw, (bytes, bytearray))
                 else str(cmd_raw).encode("utf-8", "replace")))
            if sample:
                research.update({k: v for k, v in sample.items()
                                 if v is not None})
        st = touch_state(sid, stage="s3_seen")
        delta = None
        if st.get("s1_at"):
            delta = int((time.time() - float(st["s1_at"])) * 1000)
        research.update(research_event_fields(
            st, p2s, stage_delta_ms=delta, drop_path=clean))
        if used_fake:
            research["php2shell_fake_shell"] = True
            research["fake_shell_cmd"] = sanitize_marker(cmd_raw, 80)
            if shell_extras:
                for ek, ev in shell_extras.items():
                    if ev is not None:
                        research[ek] = ev
            shape, stage = "fake_shell", "s3_fake_shell"
        else:
            shape, stage = "shell_stub", "s3_shell_stub"
        return (body_out, "text/plain; charset=utf-8", 200, cookie,
                shape, stage, research)

    # Non-allowlisted drop dictionary path → log + 404 (no stub)
    if clean in DROP_PROBE_PATHS:
        research.update(research_event_fields(
            get_state(sid), p2s, drop_path=clean))
        return (apache_404_html(), "text/html; charset=iso-8859-1", 404,
                "", "apache_404", "drop_probe_404", research)

    return None


def reset_state_for_tests():
    with _lock:
        _STATE.clear()
        _LEAKED_FAMILIES.clear()
        _LEAK_BY_HASH.clear()
        _LEAK_BY_PREFIX.clear()
        _PERSIST_OVERLAY.clear()
