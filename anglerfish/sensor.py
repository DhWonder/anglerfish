"""
The honeypot itself: a machine that looks real, and writes down everything.

This is the door with something worth stealing behind it. When somebody knocks
it does not just log the knock, it lets them in to a machine that looks
ordinary and lived-in, and records every move they make: what they type, what
they read, what they try to take.

Ways in, because attackers try all of them:

  - SSH-2 on ports mapped to ssh: a real handshake, then a password prompt.
    Only the planted credentials open the shell. Everything else is refused
    with a short delay and logged.
  - a plain login (telnet-style) on telnet ports only. An SSH port that
    receives non-SSH bytes gets OpenSSH's "Protocol mismatch." and closes —
    it never falls through to a login prompt or the web page.
  - a web page that looks like a small NAS appliance on http ports.
  - thin SMTP and FTP banners on their ports: enough that a probe gets a
    real-looking greeting, attempts are logged, and nothing useful is given.

Every connection is a probe. Even a scanner that only opens the socket and
leaves is recorded with source IP, port, and the first bytes they sent. The
sensor writes a local status file of recent probe counts so you can see it is
catching traffic, and reports sessions to the console when one is configured.

The single most important thing about this file, and the reason it is safe to
run: it never executes anything the attacker sends. Not once. Every command
gets a scripted, believable answer from the fake filesystem in bait.py. The
attacker is typing into a puppet show. Whatever they run, the real machine does
nothing but write it down. The SSH code does not forward ports and does not
open any connection of its own.
"""

import json
import os
import random
import select
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import urllib.request
import weakref
import base64
import binascii
import shlex

from . import bait
from . import dsm
from . import vhosts
from . import phpapp
from . import events as events_module
from . import persona as persona_module
from . import shellfake
from . import sshproto
from . import tlsfp

_EPHEMERAL_KEYS = None  # lazy HostKeys for tests (persona=False)


BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
READ_LIMIT = 4096
SESSION_IDLE = 120
HTTP_GLANCE = 0.35
PRELUDE_WAIT = 2.0
AUTH_FAIL_DELAY = 1.2  # overridden per-attempt with 2.0-3.5s jitter
AUTH_FAIL_DELAY_MIN = 2.0
AUTH_FAIL_DELAY_MAX = 3.5
AUTH_LOCK_AFTER = 8
AUTH_LOCK_SECONDS = 20
MAX_CONN_TOTAL = 256
MAX_CONN_PER_IP = 12
STATUS_WRITE_MIN_GAP = 0.5
LOG_ROTATE_BYTES = 50 * 1024 * 1024
TLS_PORTS = {443, 8443, 465}
# HTTP-over-TLS ports get ClientHello fingerprinting (JA3/JA3S/SNI/ALPN) via
# tlsfp + MemoryBIO on the connection's own thread. Other TLS_PORTS (465
# SMTPS) keep the plain stdlib wrap so SMTP over TLS stays simple.
HTTPS_PORTS = {443, 8443}
# Budget of TLS handshakes per source IP per minute, enforced *before*
# handshake so TLS cannot pin threads past normal backpressure.
TLS_HANDSHAKES_PER_IP_MIN = int(os.environ.get("ANGLERFISH_TLS_PER_IP_MIN", "60"))

# nginx large_client_header_buffers is ~8k; longer request lines get 414.
MAX_URI_LEN = 8190
# Capture caps (Blue hard-ask #1: >=2048 with true-length counters).
FIRST_BYTES_CAP = 2048
# Bound the cookie table so anonymous DSM cookie minting cannot grow forever.
MAX_WEB_SESSIONS = 4096

SERVICE_BY_PORT = {
    22: "ssh", 2222: "ssh",
    80: "http", 8080: "http", 8000: "http", 8888: "http",
    443: "http", 8443: "http",
    25: "smtp", 2525: "smtp", 587: "smtp", 465: "smtp",
    21: "ftp", 2121: "ftp",
    23: "telnet", 2323: "telnet",
    # Optional UDP DNS facade. Not in DEFAULT_PORTS / the live unit --ports;
    # only listens when 53 or 5353 is passed explicitly.
    53: "dns", 5353: "dns",
}

DEFAULT_PORTS = [2222, 8080, 2525, 2121, 2323]
DEFAULT_PORTS_PRIVILEGED = [22, 80, 443, 25, 21, 23, 53]

# Extra names treated as "ours" beyond the persona hostname/FQDN/domain.
KNOWN_HOST_EXTRA = ("localhost",)

# Opening any of these is a "GOTCHA": the visitor reached the prize bait.
REVEAL_EXACT = {
    "vault-staging.b64", "vault-cleartext.txt", "verify.b64.txt",
    "verify.rot13", "drop-channel.hex",
}
REVEAL_PREFIXES = ("domainadmin-creds-backup", "password-vault-export", "session-verify.")

# Guestbook lives on the IT share (post-auth only). Its header is the soft prompt.
GUESTBOOK_PATH = "/srv/shares/IT/guestbook.txt"
GUESTBOOK_HEADER = (
    "# IT share visitor log\n"
    "# one line each, newest last.\n"
)
GUESTBOOK_HEADER_CLASSROOM = (
    "# IT share visitor log - if you made it this far, sign below.\n"
    "# one line each, newest last. be nice.\n"
)
GUESTBOOK_NOTE_LIMIT = 500
GUESTBOOK_MAX_ENTRIES = 200

SHELL_GUESTBOOK_PROMPT = (
    "\n# leave a note for the next operator:\n"
    "#   echo \"<your note>\" >> %s\n" % GUESTBOOK_PATH
)
SHELL_GUESTBOOK_PROMPT_CLASSROOM = (
    "\n# psst - you found the good stuff. leave an 'I was here' for the next one:\n"
    "#   echo \"<your note>\" >> %s\n" % GUESTBOOK_PATH
)
WEB_GUESTBOOK_PROMPT = (
    "\n# --\n# leave a note in File Station (Guestbook form), "
    "or POST note=... to /guestbook\n"
)
WEB_GUESTBOOK_PROMPT_CLASSROOM = (
    "\n# --\n# you found it. leave an 'I was here' in File Station "
    "(Guestbook form), or POST note=... to /guestbook\n"
)


def is_reveal_path(path):
    leaf = (path or "").rsplit("/", 1)[-1]
    if leaf in REVEAL_EXACT:
        return True
    return any(leaf.startswith(prefix) for prefix in REVEAL_PREFIXES)


def _clean_note(text):
    """Keep a guestbook note printable, one line, and bounded."""
    text = (text or "").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch for ch in text if ch.isprintable())
    return text.strip()[:GUESTBOOK_NOTE_LIMIT]


class Sensor(object):
    """One honeypot machine, listening on one or more ports."""

    def __init__(self, name="", console="", log_path="", ports=None, bind="0.0.0.0",
                 status_path="", persona=None, classroom=False, console_token="",
                 state_dir="", drop_user="", config_path="", https_redirect=None):
        self.name = name or socket.gethostname()
        self.console = console.rstrip("/")
        self.log_path = log_path or os.path.expanduser("~/.anglerfish/sessions.log")
        self.status_path = status_path or os.path.expanduser("~/.anglerfish/status.json")
        self.bind = bind or "0.0.0.0"
        self.ports = ports or list(DEFAULT_PORTS)
        self.classroom = bool(classroom)
        self.state_dir = state_dir or os.path.expanduser("~/.anglerfish")
        self.drop_user = drop_user or ""
        if https_redirect is None:
            env = os.environ.get("ANGLERFISH_HTTPS_REDIRECT", "").strip().lower()
            if env in ("0", "false", "no", "off"):
                https_redirect = False
            elif env in ("1", "true", "yes", "on"):
                https_redirect = True
            else:
                https_redirect = True
        self.https_redirect = bool(https_redirect)
        # Persona: mint or load a stable identity so installs are not twins.
        # Pass persona=False to keep the built-in example persona defaults (tests).
        if persona is None:
            persona = persona_module.load_or_create(
                self.state_dir, console_host=_host_of(self.console),
                note=lambda m: None, config_path=config_path)
        elif persona is False:
            persona = {}
        self.persona = persona or {}
        self.console_token = console_token or self.persona.get("console_token") or ""
        if self.persona.get("rsa") and self.persona.get("ed25519_seed"):
            self.host_keys = sshproto.HostKeys(
                persona_module.rsa_tuple(self.persona),
                persona_module.ed25519_seed(self.persona))
        else:
            # Ephemeral keys for tests / classroom without a persisted persona.
            # Cached so the suite does not mint a 2048-bit RSA key per Sensor().
            global _EPHEMERAL_KEYS
            if _EPHEMERAL_KEYS is None:
                _EPHEMERAL_KEYS = sshproto.HostKeys(
                    persona_module.generate_rsa(2048), os.urandom(32))
            self.host_keys = _EPHEMERAL_KEYS
        self.boot_time = self.persona.get("boot_time") or (time.time() - 47 * 86400)
        self.world, self.tokens = bait.build(
            console_host=_host_of(self.console), sensor_name=self.name,
            persona=self.persona or None, classroom=self.classroom)
        self.world["mac"] = self.persona.get("mac") or "06:3a:1f:9c:2d:88"
        self.world["boot_time"] = self.boot_time
        shellfake.seed_synthetic_dirs(self.world)
        self.logins = list(self.world.get("logins") or bait.PLANTED_LOGINS)
        self.running = False
        self.sessions = []
        self.probes = []
        self._lock = threading.Lock()
        self._threads = []
        self._counter = 0
        self._fail_counts = {}
        self._probe_seen = set()
        self._web_sessions = {}  # cookie -> {user, at, sid, synotoken, ...}
        self._open_conns = 0
        self._conns_per_ip = {}
        self._tls_hits = {}  # peer_ip -> [timestamps] for pre-handshake rate
        self._last_status_write = 0.0
        self.events = events_module.EventLog(
            path=os.environ.get("ANGLERFISH_EVENTS_PATH") or "",
            sensor=self.name,
            host=(self.world.get("fqdn") or self.world.get("hostname")
                  or self.name),
        )
        self._ssl_ctx = None
        self._tls_cert = self._tls_key = self._tls_fp = ""
        cert, key = persona_module.tls_paths(self.state_dir)
        if cert and key:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(cert, key)
                # nginx without http2 answers ALPN with http/1.1; this facade
                # speaks only that.
                try:
                    ctx.set_alpn_protocols(["http/1.1"])
                except (NotImplementedError, ssl.SSLError, AttributeError):
                    pass
                self._ssl_ctx = ctx
                self._tls_cert, self._tls_key = cert, key
                self._install_sni_contexts(ctx)
                try:
                    with open(cert, "rb") as fh:
                        der = ssl.PEM_cert_to_DER_cert(fh.read().decode("ascii"))
                    import hashlib as _hl
                    self._tls_fp = _hl.sha256(der).hexdigest()
                except Exception:
                    self._tls_fp = ""
            except Exception:
                self._ssl_ctx = None
        self._stats = {
            "started": time.time(),
            "probes_total": 0,
            "by_port": {},
            "by_protocol": {},
            "auth_ok": 0,
            "auth_fail": 0,
            "recent": [],
            "gotcha_total": 0,
            "gotchas": [],
            "guestbook_total": 0,
            "guestbook": [],
        }
        base, _ext = os.path.splitext(self.log_path)
        self.reveals_path = base + "-reveals.log"
        self._seed_guestbook()
        self._register()

    def start(self):
        self.running = True
        for port in self.ports:
            if self.service_for(port) == "dns":
                target = self._serve_dns
            else:
                target = self._serve
            thread = threading.Thread(target=target, args=(port,), daemon=True)
            thread.start()
            self._threads.append(thread)
        return self._threads

    def stop(self):
        self.running = False
        self._write_status()

    def service_for(self, port):
        return SERVICE_BY_PORT.get(port, "ssh")

    def _serve(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind, port))
            server.listen(64)
            server.settimeout(1.0)
        except OSError as exc:
            self._note("could not open port %d: %s" % (port, exc))
            return

        tls = bool(self._ssl_ctx and port in TLS_PORTS)
        self._note("listening on %s:%d (%s%s)" % (
            self.bind, port, self.service_for(port), ", tls" if tls else ""))
        while self.running:
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                if self._open_conns >= MAX_CONN_TOTAL:
                    try: conn.close()
                    except OSError: pass
                    continue
                per = self._conns_per_ip.get(addr[0], 0)
                if per >= MAX_CONN_PER_IP:
                    try: conn.close()
                    except OSError: pass
                    continue
                self._open_conns += 1
                self._conns_per_ip[addr[0]] = per + 1
            # HTTPS: fingerprint ClientHello (JA3/SNI/ALPN) then handshake on
            # the connection's own thread so a slow client cannot stall accept().
            # Non-HTTPS TLS (SMTPS 465) keeps the plain wrap_socket path.
            if tls and port in HTTPS_PORTS:
                threading.Thread(target=self._handle_tls,
                                 args=(conn, addr, port, self._ssl_ctx),
                                 daemon=True).start()
                continue
            if tls:
                try:
                    conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
                except Exception:
                    self._release_conn(addr[0])
                    try: conn.close()
                    except OSError: pass
                    continue
            threading.Thread(target=self._handle, args=(conn, addr, port),
                             daemon=True).start()
        server.close()

    def _release_conn(self, ip):
        with self._lock:
            self._open_conns = max(0, self._open_conns - 1)
            n = self._conns_per_ip.get(ip, 1) - 1
            if n <= 0:
                self._conns_per_ip.pop(ip, None)
            else:
                self._conns_per_ip[ip] = n

    def _tls_rate_allow(self, peer_ip):
        """Soft per-IP TLS-handshake budget before spending a BIO handshake."""
        now = time.time()
        with self._lock:
            hits = [t for t in self._tls_hits.get(peer_ip, []) if now - t < 60.0]
            if len(hits) >= TLS_HANDSHAKES_PER_IP_MIN:
                self._tls_hits[peer_ip] = hits
                return False
            hits.append(now)
            self._tls_hits[peer_ip] = hits
            # Bound the map so scanners cannot grow it forever.
            if len(self._tls_hits) > 5000:
                cutoff = now - 60.0
                self._tls_hits = {
                    ip: ts for ip, ts in self._tls_hits.items()
                    if any(t >= cutoff for t in ts)
                }
            return True

    def _handle_tls(self, conn, addr, port, ctx):
        """Fingerprint the ClientHello, finish TLS, then hand off to _handle.

        Primary path: MSG_PEEK the ClientHello, parse (JA3/SNI/ALPN), then
        drive the handshake via ssl.SSLObject + MemoryBIO so the real
        ServerHello can be read for JA3S. If the peek is not a valid
        ClientHello, fall back to plain ctx.wrap_socket (nothing consumed)
        and leave ja3/sni absent. Never raises. Per-IP TLS rate limits run
        before the handshake. Uses the persona TLS cert already loaded into
        ctx (no self-generated cert).
        """
        if not self._tls_rate_allow(addr[0]):
            self._release_conn(addr[0])
            try:
                conn.close()
            except OSError:
                pass
            return
        try:
            self._handle_tls_inner(conn, addr, port, ctx)
        except Exception:
            pass

    def _handle_tls_inner(self, conn, addr, port, ctx):
        base = dict(service="https", src_ip=addr[0], src_port=addr[1],
                    dst_port=port, listen_port=port, session_id="",
                    transport="tcp", tls=True)
        hello = None
        server_hello = None
        fp_path = "fallback"
        try:
            hello, hello_len = tlsfp.peek_client_hello(conn)
            if hello is not None and hello_len:
                fp_path = "memory_bio"
                tconn, server_hello = tlsfp.memory_bio_handshake(
                    ctx, conn, hello_len)
                tconn.server_hostname = hello.get("sni") or ""
                tls_conn = tconn
            else:
                conn.settimeout(tlsfp.HANDSHAKE_TIMEOUT)
                tls_conn = ctx.wrap_socket(conn, server_side=True)
        except Exception as exc:
            try:
                fields = dict(base)
                fields.update(tls_handshake_ok=False, tags=["tls-fail"],
                              tls_fp_path=fp_path,
                              tls_error=type(exc).__name__)
                fields.update(self._tls_hello_fields(hello))
                self.events.emit("tls", **fields)
            except Exception:
                pass
            self._release_conn(addr[0])
            try:
                conn.close()
            except OSError:
                pass
            return
        try:
            cipher = tls_conn.cipher() or ("", "", 0)
            fields = dict(base)
            fields.update(
                tls_version=tls_conn.version() or "",
                tls_cipher=cipher[0] or "",
                tls_cert_fp_sha256=self._tls_fp,
                tls_handshake_ok=True,
                tls_fp_path=fp_path,
            )
            try:
                fields["tls_alpn_selected"] = tls_conn.selected_alpn_protocol()
            except Exception:
                pass
            fields.update(self._tls_hello_fields(hello))
            if server_hello:
                fields["tls_ja3s"] = server_hello["ja3s"]
                fields["tls_ja3s_str"] = server_hello["ja3s_str"]
            self.events.emit("tls", **fields)
        except Exception:
            pass
        # Hand off: _handle's finally releases the connection slot and closes.
        self._handle(tls_conn, addr, port)

    @staticmethod
    def _tls_hello_fields(hello):
        if not hello:
            return {}
        out = {
            "tls_ja3": hello["ja3"],
            "tls_ja3_str": hello["ja3_str"],
            "tls_alpn": list(hello.get("alpn") or []) or None,
            "tls_client_versions": [
                v for v in (hello.get("supported_versions") or [])
                if not tlsfp.is_grease(v)
            ] or None,
        }
        if hello.get("sni"):
            out["tls_sni"] = hello["sni"]
        return out

    def _handle(self, conn, addr, port):
        conn.settimeout(SESSION_IDLE)
        with self._lock:
            self._counter += 1
            session_id = "%s-%d-%d" % (self.name, int(time.time()), self._counter)

        service = self.service_for(port)
        session = {
            "id": session_id, "sensor": self.name, "peer_ip": addr[0],
            "peer_port": addr[1], "local_port": port, "started": time.time(),
            "protocol": service, "service": service, "events": [],
            "credentials": [], "read_files": [], "commands": [],
            "first_bytes": "", "auth_ok": False,
            "ssh_client": "", "hassh": "", "pubkeys": [],
        }

        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        self._record_probe(session, note="accepted")

        try:
            if service == "http":
                session["protocol"] = "http"
                try:
                    first = conn.recv(READ_LIMIT)
                except (socket.timeout, OSError):
                    first = b""
                self._capture_first(session, first)
                if first:
                    self._web(conn, first, session)
            elif service == "smtp":
                session["protocol"] = "smtp"
                self._smtp(conn, session)
            elif service == "ftp":
                session["protocol"] = "ftp"
                self._ftp(conn, session)
            elif service == "telnet":
                session["protocol"] = "telnet"
                self._telnet(conn, session)
            else:
                # SSH ports speak SSH only. Banner immediately (no delay),
                # then Protocol mismatch for anything that is not SSH-2.
                try:
                    conn.sendall((BANNER + "\r\n").encode("ascii"))
                except OSError:
                    return
                intro = _read_prelude(conn)
                self._capture_first(session, intro)
                if intro.startswith(b"SSH-"):
                    session["protocol"] = "ssh"
                    self._ssh(conn, intro, session)
                else:
                    session["protocol"] = "ssh-reject"
                    session["events"].append(_event("ssh-reject", "protocol mismatch"))
                    try:
                        conn.sendall(b"Protocol mismatch.\r\n")
                    except OSError:
                        pass
        except (OSError, socket.timeout, EOFError, ssl.SSLError, sshproto.ProtocolError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._release_conn(addr[0])
            session["ended"] = time.time()
            session["duration"] = round(session["ended"] - session["started"], 1)
            self._finish(session)

    def _capture_first(self, session, data):
        if not data:
            return
        text, encoding, true_len, truncated = events_module.capture_bytes(
            data, FIRST_BYTES_CAP)
        # sessions.log stays backward-compatible: first_bytes is still a string.
        # True length + truncation live alongside it and in events.jsonl.
        session["first_bytes"] = text[:FIRST_BYTES_CAP]
        session["first_bytes_encoding"] = encoding
        session["first_bytes_len"] = true_len
        session["first_bytes_truncated"] = truncated
        session["events"].append(_event("first-bytes", session["first_bytes"][:200]))
        try:
            self.events.emit(
                "first_bytes",
                service=session.get("service") or "",
                session=session,
                first_bytes=session["first_bytes"][:512],
                first_bytes_encoding=encoding,
                first_bytes_len=true_len,
                first_bytes_truncated=truncated,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # GOTCHA reveals and the guestbook
    # ------------------------------------------------------------------
    def _seed_guestbook(self):
        files = self.world["files"]
        if GUESTBOOK_PATH not in files:
            header = GUESTBOOK_HEADER_CLASSROOM if self.classroom else GUESTBOOK_HEADER
            files[GUESTBOOK_PATH] = header
        self._refresh_tree()

    def _refresh_tree(self):
        files = self.world["files"]
        # Rebuild from files, but keep any synthetic dirs seed_synthetic_dirs
        # planted (empty /tmp, /proc, /sys, ...) so they are not wiped.
        derived = set(bait._directories_for(files))
        existing = set(self.world.get("dirs") or [])
        self.world["dirs"] = sorted(derived | existing)
        self.world["shares"] = bait._share_index(files)

    def _append_reveal_log(self, record):
        """One JSON line per GOTCHA / guestbook note, written immediately."""
        try:
            folder = os.path.dirname(self.reveals_path)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder)
            with open(self.reveals_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError:
            pass

    def _gotcha(self, session, path, via):
        """Record that a visitor opened prize bait. Returns True on the
        first reveal in this session, which is when the soft prompt shows."""
        now = time.time()
        record = {
            "kind": "gotcha",
            "at": now,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "sensor": self.name,
            "session": session.get("id", ""),
            "peer_ip": session.get("peer_ip", "?"),
            "username": session.get("username", ""),
            "path": path,
            "via": via,
        }
        gotchas = session.setdefault("gotchas", [])
        first = not gotchas
        gotchas.append(record)
        session.setdefault("events", []).append(
            _event("gotcha", "%s via %s" % (path, via)))
        with self._lock:
            self._stats["gotcha_total"] += 1
            self._stats["gotchas"] = (self._stats["gotchas"] + [record])[-40:]
        self._append_reveal_log(record)
        self._note("GOTCHA %s opened %s via %s (session %s)"
                   % (record["peer_ip"], path, via, record["session"] or "-"))
        self._write_status()
        return first

    def _sign_guestbook(self, session, note, via):
        """Append a visitor note to the fake guestbook and log it. Returns the
        cleaned note, or "" when there was nothing to write."""
        note = _clean_note(note)
        if not note:
            return ""
        now = time.time()
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(now))
        # The file other visitors can read carries no IP; the log does.
        line = "[%s] %s\n" % (stamp, note)
        with self._lock:
            files = self.world["files"]
            current = files.get(GUESTBOOK_PATH, GUESTBOOK_HEADER)
            entries = current.splitlines(True)
            header = [ln for ln in entries if ln.startswith("#")]
            body = [ln for ln in entries if not ln.startswith("#")]
            body = (body + [line])[-GUESTBOOK_MAX_ENTRIES:]
            files[GUESTBOOK_PATH] = "".join(header + body)
        self._refresh_tree()
        record = {
            "kind": "guestbook",
            "at": now,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "sensor": self.name,
            "session": session.get("id", ""),
            "peer_ip": session.get("peer_ip", "?"),
            "username": session.get("username", ""),
            "via": via,
            "note": note,
        }
        session.setdefault("guestbook", []).append(record)
        session.setdefault("events", []).append(_event("guestbook", note))
        with self._lock:
            self._stats["guestbook_total"] += 1
            self._stats["guestbook"] = (self._stats["guestbook"] + [record])[-20:]
        self._append_reveal_log(record)
        self._note("GUESTBOOK %s signed via %s: %s" % (record["peer_ip"], via, note))
        self._write_status()
        return note

    def _shell_read(self, session, target):
        """Bookkeeping for a shell file read. Returns the prompt suffix to show."""
        session.setdefault("read_files", []).append(target)
        session.setdefault("events", []).append(_event("read-file", target))
        try:
            self.events.emit(
                "path_read",
                service=session.get("service") or session.get("protocol") or "shell",
                session=session, path_read=target,
                username=session.get("username") or "",
                auth_ok=bool(session.get("auth_ok")),
                cred_source=session.get("cred_source") or "session",
                gotcha_id=target if is_reveal_path(target) else None,
            )
        except Exception:
            pass
        if is_reveal_path(target):
            if self._gotcha(session, target, "shell"):
                return (SHELL_GUESTBOOK_PROMPT_CLASSROOM if self.classroom
                        else SHELL_GUESTBOOK_PROMPT)
        return ""

    def _record_probe(self, session, note=""):
        peer = session["peer_ip"]
        port = session["local_port"]
        with self._lock:
            self._stats["probes_total"] += 1
            self._stats["by_port"][str(port)] = self._stats["by_port"].get(str(port), 0) + 1
            proto = session.get("protocol") or session.get("service") or "?"
            self._stats["by_protocol"][proto] = self._stats["by_protocol"].get(proto, 0) + 1
            is_new = peer not in self._probe_seen
            if is_new:
                self._probe_seen.add(peer)
                if len(self._probe_seen) > 5000:
                    # Drop an arbitrary half; set has no order, just bound memory.
                    self._probe_seen = set(list(self._probe_seen)[-2500:])
            entry = {
                "at": time.time(), "peer_ip": peer, "port": port,
                "protocol": proto, "new_ip": is_new, "note": note,
            }
            self._stats["recent"] = (self._stats["recent"] + [entry])[-40:]
            self.probes.append(entry)
        session["events"].append(_event("probe", "%s:%s %s" % (peer, port, note)))
        if is_new:
            self._note("new probe from %s on port %d (%s)" % (peer, port, proto))
        self._write_status()

    def _check_login(self, username, password):
        for user, pw in self.logins:
            if username == user and password == pw:
                return True
        return False

    def _record_password(self, session, service, username, password):
        """Log one try. Only planted / canary credentials are accepted.

        On success emit auth_ok=true as the highest-signal structured event
        (Blue Team R-rules). On failure keep live's per-attempt jittered
        delay (and the lock-after-N slowdown). Fail counts stay per-IP
        (live behaviour); do not share a lock clock across services by
        changing that here.
        """
        session["events"].append(_event("login-user", username))
        session["events"].append(_event("login-pass", password))
        session["credentials"].append({
            "username": username, "password": password, "service": service,
        })
        peer = session["peer_ip"]
        ok = self._check_login(username, password)
        source = "attacker"
        if ok:
            fixed = dict(bait.planted_password_map())
            if fixed.get(username) == password:
                source = "planted"
            else:
                source = "canary"
        if ok:
            with self._lock:
                self._fail_counts[peer] = 0
                self._stats["auth_ok"] += 1
            session["events"].append(_event("login-result", "ok"))
            session["auth_ok"] = True
            session["cred_source"] = source
            try:
                self.events.emit(
                    "auth", service=service, session=session,
                    username=username, password=password, auth_ok=True,
                    cred_source=source, auth_method="password",
                )
            except Exception:
                pass
            return True

        with self._lock:
            fails = self._fail_counts.get(peer, 0) + 1
            self._fail_counts[peer] = fails
            self._stats["auth_fail"] += 1
        session["events"].append(_event("login-result", "fail"))
        delay = random.uniform(AUTH_FAIL_DELAY_MIN, AUTH_FAIL_DELAY_MAX)
        reason = "fail"
        if fails >= AUTH_LOCK_AFTER:
            delay = AUTH_LOCK_SECONDS
            reason = "lock"
            session["events"].append(_event("auth-slowdown",
                                            "%d fails from %s" % (fails, peer)))
        time.sleep(delay)
        try:
            self.events.emit(
                "auth", service=service, session=session,
                username=username, password=password, auth_ok=False,
                cred_source="attacker", auth_method="password",
                tarpit_ms=int(delay * 1000), tarpit_reason=reason,
            )
        except Exception:
            pass
        return False

    def _telnet(self, conn, session):
        """Telnet port: IAC negotiate, then a login prompt. Never on SSH ports."""
        # Refuse options politely so telnet clients settle.
        try:
            # IAC WONT ECHO / IAC WONT SUPPRESS-GO-AHEAD / IAC DO TERMINAL-TYPE
            conn.sendall(bytes([255, 252, 1, 255, 252, 3, 255, 253, 24]))
        except OSError:
            pass
        issue = self.world["files"].get("/etc/issue", "Ubuntu 22.04.4 LTS\n")
        issue = (issue.replace("\\n", self.world["hostname"])
                      .replace("\\l", "tty1")
                      .replace("\\m", "x86_64")
                      .replace("\\r", "5.15.0-101-generic")
                      .replace("\\s", "Linux")
                      .replace("\\v", "5.15.0"))
        _send(conn, "\r\n%s\r\n" % issue.strip())
        self._console(conn, b"", session, banner_first=True)

    def _console(self, conn, intro, session, banner_first=True):
        """A serial-console / telnet login (telnet ports only)."""
        send = lambda text: _send(conn, text)
        if not banner_first:
            send("\r\n%s\r\n\r\n" % self.world["files"].get("/etc/issue", "").strip())
        pending = intro
        while self.running:
            send("%s login: " % self.world["hostname"])
            username = _line(conn, pending)
            pending = b""
            if username is None:
                return
            send("Password: ")
            password = _line(conn)
            if password is None:
                return
            if not self._record_password(session, session.get("protocol") or "console",
                                         username, password):
                send("\r\nLogin incorrect\r\n")
                continue
            session["username"] = username
            send("\r\n" + self._live_motd(session, username) + "\r\n")
            self._console_shell(conn, session, username=username)
            return

    def _console_shell(self, conn, session, username="deploy"):
        send = lambda text: _send(conn, text)
        home = "/home/%s" % username if username in ("deploy", "admin") else "/home/deploy"
        if home not in self.world["dirs"] and home + "/" not in "".join(self.world["dirs"]):
            home = "/home/deploy"
        cwd = home if home in self.world["dirs"] else "/home/deploy"
        session["username"] = username
        while self.running:
            send(self._prompt(cwd, username=username))
            line = _line(conn)
            if line is None:
                break
            reply, cwd, done = self._shell_answer(line, cwd, session, username=username)
            if reply:
                send(reply if reply.endswith("\n") else reply + "\n")
            if done:
                send("logout\r\n")
                break

    def _prompt(self, cwd, username="deploy"):
        return "%s@%s:%s$ " % (username, self.world["hostname"], _short(cwd, username=username))

    def _shell_answer(self, line, cwd, session, username="deploy"):
        line = line.strip()
        if not line:
            return "", cwd, False
        if len(line) > 2000:
            line = line[:2000]
        session["commands"].append(line)
        session["events"].append(_event("command", line))
        return self._run_fake(line, cwd, session, username=username)

    def _ssh(self, conn, intro, session):
        state = {"cwd": "/home/deploy", "user": "deploy"}

        def banner(ident):
            session["ssh_client"] = ident
            session["events"].append(_event("ssh-client", ident))

        def kexinit(info):
            # Live sshproto already computes HASSH and passes a dict; keep that
            # crypto stack and only emit the structured event on top.
            session["hassh"] = info.get("hassh") or ""
            session["ssh_kex_algs"] = list(info.get("kex") or [])
            session["events"].append(_event("ssh-hassh", session["hassh"]))
            session["events"].append(
                _event("ssh-kex", ",".join((info.get("kex") or [])[:6])))
            try:
                self.events.emit(
                    "ssh_kex", service="ssh", session=session,
                    ssh_client_version=session.get("ssh_client") or "",
                    ssh_kex_algs=",".join(info.get("kex") or []),
                    ssh_host_key_algs=",".join(info.get("host_key") or []),
                    ssh_enc_algs_ctos=",".join(info.get("ciphers_c2s") or []),
                    ssh_mac_algs_ctos=",".join(info.get("macs_c2s") or []),
                    ssh_comp_algs_ctos=",".join(info.get("comp_c2s") or []),
                    hassh=session["hassh"],
                )
            except Exception:
                pass

        def pubkey(username, algo, fp):
            session.setdefault("pubkeys", []).append(
                {"username": username, "algo": algo, "fingerprint": fp})
            session["events"].append(_event("ssh-pubkey", "%s %s %s" % (username, algo, fp)))

        def password(username, password):
            ok = self._record_password(session, "ssh", username, password)
            if ok:
                state["user"] = username or "deploy"
                session["username"] = state["user"]
                home = "/home/%s" % state["user"]
                if home in self.world["dirs"]:
                    state["cwd"] = home
            return ok

        def greeting():
            return self._live_motd(session, state["user"])

        def prompt():
            return self._prompt(state["cwd"], username=state["user"])

        def line(text):
            reply, cwd, done = self._shell_answer(
                text, state["cwd"], session, username=state["user"])
            state["cwd"] = cwd
            return reply, done

        def exec_cmd(command):
            reply, cwd, _done = self._shell_answer(
                command, state["cwd"], session, username=state["user"])
            state["cwd"] = cwd
            return reply or ""

        sshproto.serve(conn, intro, BANNER, {
            "banner": banner,
            "kexinit": kexinit,
            "pubkey": pubkey,
            "password": password,
            "greeting": greeting,
            "prompt": prompt,
            "line": line,
            "exec": exec_cmd,
        }, keys=self.host_keys)

    def _smtp(self, conn, session):
        fqdn = self.world.get("fqdn") or self.world["hostname"]
        _send(conn, "220 %s ESMTP Postfix (Ubuntu)\r\n" % fqdn)
        while self.running:
            line = _line(conn)
            if line is None:
                return
            session["events"].append(_event("smtp", line[:200]))
            if not session["first_bytes"]:
                session["first_bytes"] = line[:120]
            upper = line.upper().strip()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                _send(conn, "250-%s\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
                            "250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n"
                            "250-8BITMIME\r\n250 CHUNKING\r\n" % fqdn)
            elif upper.startswith("MAIL"):
                session["events"].append(_event("smtp-mail", line[:200]))
                session["_smtp_mail"] = True
                # Accept MAIL, refuse at RCPT — matches a real closed relay.
                _send(conn, "250 2.1.0 Ok\r\n")
            elif upper.startswith("RCPT"):
                if session.get("_smtp_mail"):
                    _send(conn, "554 5.7.1 <%s>: Relay access denied\r\n"
                          % (line.split(":", 1)[-1].strip() or "unknown"))
                else:
                    _send(conn, "503 5.5.1 Error: need MAIL command\r\n")
            elif upper.startswith("DATA"):
                if session.get("_smtp_mail"):
                    _send(conn, "554 5.7.1 Error: no valid recipients\r\n")
                else:
                    _send(conn, "503 5.5.1 Error: need MAIL command\r\n")
            elif upper.startswith("STARTTLS"):
                # On non-TLS listeners, refuse; on 465 the socket is already TLS.
                _send(conn, "454 4.7.0 TLS not available due to local problem\r\n")
            elif upper.startswith("AUTH"):
                session["credentials"].append({"service": "smtp", "raw": line[:200]})
                _send(conn, "535 5.7.8 Error: authentication failed\r\n")
            elif upper in ("QUIT",):
                _send(conn, "221 2.0.0 Bye\r\n")
                return
            elif upper in ("RSET", "NOOP"):
                _send(conn, "250 2.0.0 Ok\r\n")
            else:
                _send(conn, "502 5.5.2 Error: command not recognized\r\n")

    def _ftp(self, conn, session):
        fqdn = self.world.get("fqdn") or self.world["hostname"]
        _send(conn, "220 %s FTP server (vsftpd 3.0.5) ready.\r\n" % fqdn)
        user = ""
        while self.running:
            line = _line(conn)
            if line is None:
                return
            session["events"].append(_event("ftp", line[:200]))
            if not session["first_bytes"]:
                session["first_bytes"] = line[:120]
            parts = line.strip().split(None, 1)
            cmd = (parts[0] if parts else "").upper()
            arg = parts[1] if len(parts) > 1 else ""
            if not cmd:
                # vsftpd >= 2.0.8 silently ignores blank lines (nmap keys on this).
                continue
            if cmd == "USER":
                user = arg
                session["events"].append(_event("login-user", user))
                _send(conn, "331 Please specify the password.\r\n")
            elif cmd == "PASS" and not user:
                _send(conn, "503 Login with USER first.\r\n")
                self._emit_ftp(session, cmd, arg, 503)
            elif cmd == "PASS":
                # Planted/canary creds record auth_ok for Blue; transfer is still
                # refused below (no real files leave the box). Pre-auth FEAT/
                # SYST/blank-line behaviour is unchanged (realism #4c).
                ok = self._record_password(session, "ftp", user, arg)
                if ok:
                    _send(conn, "230 Login successful.\r\n")
                    self._emit_ftp(session, cmd, arg, 230)
                    session["_ftp_user"] = user
                else:
                    _send(conn, "530 Login incorrect.\r\n")
                    self._emit_ftp(session, cmd, arg, 530)
                user = ""
            elif cmd == "FEAT":
                # Stock vsftpd 3.0.5 feature list (answered pre-login).
                _send(conn, "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n"
                            " REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n")
            elif cmd == "OPTS" and arg.upper().startswith("UTF8"):
                _send(conn, "200 Always in UTF8 mode.\r\n")
            elif cmd == "AUTH":
                _send(conn, "530 Please login with USER and PASS.\r\n")
            elif cmd in ("QUIT",):
                _send(conn, "221 Goodbye.\r\n")
                self._emit_ftp(session, cmd, arg, 221)
                return
            else:
                if session.get("auth_ok"):
                    # Authed but we never open a data channel or serve files.
                    _send(conn, "550 Failed to open file.\r\n")
                    self._emit_ftp(session, cmd, arg, 550)
                else:
                    # Real vsftpd refuses SYST/PWD/LIST/anything else until login.
                    _send(conn, "530 Please login with USER and PASS.\r\n")
                    self._emit_ftp(session, cmd, arg, 530)

    def _emit_ftp(self, session, cmd, arg, reply):
        try:
            self.events.emit(
                "ftp", service="ftp", session=session,
                ftp_cmd=cmd, ftp_arg=(arg or "")[:200], ftp_reply_code=reply,
            )
        except Exception:
            pass

    def _run_fake(self, line, cwd, session, username="deploy"):
        """Answer a shell command from the fake filesystem. Runs nothing."""
        sh = shellfake.FakeShell(
            self.world, self.ports, classroom=self.classroom,
            peer_ip=session.get("peer_ip") or "",
            read_hook=lambda path: self._shell_read(session, path),
            sign_guestbook=self._sign_guestbook,
            event_hook=lambda kind, detail: None,
            boot_time=self.boot_time,
        )
        # Replay sudo state across calls within a session
        pending = session.get("_sudo_pending")
        if pending:
            sh._sudo_pending = pending
        reply, cwd, done = sh.run_line(line, cwd, session, username=username)
        if sh._sudo_pending:
            session["_sudo_pending"] = sh._sudo_pending
        else:
            session.pop("_sudo_pending", None)
        return reply, cwd, done

    def _live_motd(self, session, username):
        """MOTD that reflects the live session (user count, peer, uptime)."""
        days, pretty = persona_module.uptime_fields(
            {"boot_time": self.boot_time})
        ip = self.world.get("internal_ip") or "10.0.0.21"
        return (
            "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)\n\n"
            " * Support:        https://ubuntu.com/advantage\n\n"
            "  System load:  0.08              Processes:             128\n"
            "  Usage of /:   61.2%% of 78.4GB  Users logged in:       1\n"
            "  IP address:   %s               Hostname:              %s\n\n"
            "  %s file share — NAS UI on https://%s/\n\n"
            "Last login: %s from %s\n"
            % (ip, self.world["hostname"], self.world.get("company") or "",
               self.world.get("fqdn") or self.world["hostname"],
               time.strftime("%a %b %d %H:%M:%S %Y"),
               session.get("peer_ip") or "10.0.0.14")
        )

    def _list(self, path):
        files = self.world["files"]
        dirs = self.world["dirs"]
        entries = set()
        base = path.rstrip("/") or ""
        for other in dirs:
            if other != base and other.rsplit("/", 1)[0] == (base or ""):
                entries.add(other.rsplit("/", 1)[1] + "/")
        for path_name in files:
            if path_name.rsplit("/", 1)[0] == (base or ""):
                entries.add(path_name.rsplit("/", 1)[1])
        if not entries:
            return ""
        return "  ".join(sorted(entries))

    def _issue_web_session(self, username, provisional=False):
        """Mint a session cookie. provisional=True: pre-auth tracking cookie
        (DSM issues id= on the login GET before anyone authenticates)."""
        token = binascii.hexlify(os.urandom(16)).decode("ascii")
        sid = binascii.hexlify(os.urandom(8)).decode("ascii").upper()
        synotoken = binascii.hexlify(os.urandom(8)).decode("ascii").upper()
        with self._lock:
            self._web_sessions[token] = {
                "user": username or "",
                "at": time.time(),
                "sid": sid,
                "synotoken": synotoken,
                "provisional": bool(provisional),
                "auth_ok": bool(username) and not provisional,
            }
            # Drop sessions older than a day; also bound total size.
            cutoff = time.time() - 86400
            stale = [k for k, v in self._web_sessions.items() if v["at"] < cutoff]
            for k in stale:
                self._web_sessions.pop(k, None)
            if len(self._web_sessions) > MAX_WEB_SESSIONS:
                # Drop oldest half of provisional sessions first.
                items = sorted(self._web_sessions.items(), key=lambda kv: kv[1]["at"])
                for k, _ in items[:len(items) // 2]:
                    self._web_sessions.pop(k, None)
        return token

    def _web_user_from_headers(self, head):
        """Return (username, nas_session_token, row). Empty user when provisional."""
        cookie = ""
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"cookie:"):
                cookie = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
                break
        token = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("nas_session="):
                token = part.split("=", 1)[1].strip()
                break
            if part.startswith("id=") and not token:
                sid = part.split("=", 1)[1].strip()
                with self._lock:
                    for tok, row in self._web_sessions.items():
                        if row.get("sid") == sid:
                            token = tok
                            break
        if not token:
            return "", "", {}
        with self._lock:
            row = dict(self._web_sessions.get(token) or {})
        if not row:
            return "", "", {}
        if row.get("provisional") and not row.get("auth_ok"):
            return "", token, row
        if row.get("user") and row.get("auth_ok"):
            return row["user"], token, row
        return "", token, row

    def _install_sni_contexts(self, default_ctx):
        """Per-role certs (separate LE lineages so one cert doesn't list every
        name in CT). SNI picks the context; IP/unknown/no SNI keeps the
        default (apex+www) cert."""
        self._sni_ctx = {}
        for role, stem in (("files", "tls-files"), ("staff", "tls-staff")):
            c = os.path.join(self.state_dir, stem + "-cert.pem")
            k = os.path.join(self.state_dir, stem + "-key.pem")
            if not (os.path.exists(c) and os.path.exists(k)):
                continue
            try:
                x = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                x.minimum_version = ssl.TLSVersion.TLSv1_2
                x.load_cert_chain(c, k)
                try:
                    x.set_alpn_protocols(["http/1.1"])
                except (NotImplementedError, ssl.SSLError, AttributeError):
                    pass
                self._sni_ctx[role] = x
            except Exception:
                pass
        if not self._sni_ctx:
            return
        domain = (self.world.get("domain") or "").lower()
        label_ctx = {"files": "files", "srv-files": "files",
                     "portal": "staff", "billing": "staff", "mail": "staff"}

        def _pick(sslobj, server_name, _ctx):
            try:
                name = (server_name or "").lower().rstrip(".")
                # No SNI / IP-literal SNI = someone hitting the box by IP ->
                # the NAS (files/srv-files) cert, same as files.*.
                if (not name or all(c in "0123456789." for c in name)
                        or ":" in name):
                    if "files" in self._sni_ctx:
                        sslobj.context = self._sni_ctx["files"]
                    return None
                if domain and name.endswith("." + domain):
                    role = label_ctx.get(name[: -(len(domain) + 1)])
                    if role and role in self._sni_ctx:
                        sslobj.context = self._sni_ctx[role]
            except Exception:
                pass
            return None

        try:
            default_ctx.sni_callback = _pick
        except Exception:
            pass

    def _plain_server_host(self, host_header):
        """apex/www and every NAS-facing Host (files/srv-files, fqdn, bare IP,
        no Host, dotless LAN name) run with server_tokens off -> 'nginx'."""
        host = (host_header or "").strip().lower()
        if host.startswith("["):
            return True  # IPv6 literal
        host = host.split(":")[0].rstrip(".")
        if not host or "." not in host or all(c in "0123456789." for c in host):
            return True
        domain = (self.world.get("domain") or "").lower()
        fqdn = (self.world.get("fqdn") or "").lower()
        if fqdn and host == fqdn:
            return True
        if not domain:
            return False
        if host in (domain, "www." + domain):
            return True
        if host.endswith("." + domain):
            return host[: -(len(domain) + 1)] in vhosts.SERVED_LABELS
        return False

    def _known_host(self, host_header):
        """True when Host looks like this NAS; False -> nginx default-server."""
        if not host_header:
            return True
        host = host_header.split(":")[0].strip().lower()
        if not host or host in KNOWN_HOST_EXTRA or host in ("127.0.0.1", "::1"):
            return True
        if "." not in host:
            return True
        if all(c in "0123456789." for c in host):
            return True
        fqdn = (self.world.get("fqdn") or "").lower()
        hostname = (self.world.get("hostname") or "").lower()
        domain = (self.world.get("domain") or "").lower()
        if host == fqdn or host == hostname or host.startswith(hostname + "."):
            return True
        if domain and host == domain:
            return True
        # Only the vhosts we actually serve; other *.domain -> nginx default-server
        # (matches a real nginx with explicit server_names).
        if domain and host.endswith("." + domain):
            label = host[: -(len(domain) + 1)]
            if label in vhosts.SERVED_LABELS:
                return True
        return False

    def _web(self, conn, first, session):
        _hb = _http_head_and_body(conn, first)
        if len(_hb) == 6:
            head, body, declared_length, _drained, _drain_capped, _hb_meta = _hb
        else:  # pragma: no cover
            head, body, declared_length, _drained, _drain_capped = _hb
            _hb_meta = {}
        session["http_declared_length"] = declared_length
        session["body_drained_bytes"] = _drained
        session["body_drain_capped"] = _drain_capped
        session["http_body_meta"] = _hb_meta or {}
        request_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        session["events"].append(_event("http", request_line[:500]))
        ua = host_header = referer = content_type = ""
        for line in head.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"user-agent:"):
                ua = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
                session["http_user_agent"] = ua
                session["events"].append(_event("http-ua", ua[:200]))
            elif low.startswith(b"host:"):
                host_header = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
                session["http_host"] = host_header
            elif low.startswith(b"referer:"):
                referer = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
            elif low.startswith(b"content-type:"):
                content_type = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
            elif low.startswith(b"cookie:"):
                session["http_cookie"] = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
        try:
            method, path, version = request_line.split(" ", 2)
        except ValueError:
            parts = request_line.split(" ", 2)
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else request_line
            version = parts[2] if len(parts) > 2 else "HTTP/1.0"
            if len(request_line) > MAX_URI_LEN:
                path = request_line
        method = method.upper()
        uri_len = len(path)

        # 414 before anything else (nginx large_client_header_buffers).
        if uri_len > MAX_URI_LEN or len(request_line) > MAX_URI_LEN + 32:
            payload = dsm.nginx_414_html().encode("utf-8")
            _send_raw(conn, _http_response(414, "text/html", payload, head_only=False))
            try:
                self.events.emit(
                    "http", service="http", session=session,
                    http_method=method, http_path=path[:200], http_status=414,
                    uri_len=uri_len, request_line=request_line[:512],
                    request_line_truncated=True, user_agent=ua[:200],
                    host_header=host_header,
                )
            except Exception:
                pass
            return

        # CONNECT must never look like an open proxy.
        if method == "CONNECT":
            session["events"].append(_event("http-connect", path[:120]))
            payload = _nginx_error(400, "Bad Request")
            _send_raw(conn, _http_response(400, "text/html", payload, head_only=False))
            return
        if method == "TRACE":
            payload = _nginx_error(405, "Method Not Allowed")
            _send_raw(conn, _http_response(405, "text/html", payload, head_only=False,
                                           extra="Allow: GET, POST, HEAD\r\n"))
            return
        if method not in ("GET", "POST", "HEAD", "OPTIONS"):
            payload = _nginx_error(400, "Bad Request")
            _send_raw(conn, _http_response(400, "text/html", payload, head_only=False))
            return

        # Unknown Host -> Apache/nginx default-server.
        # Stock default_server serves welcome at "/" only and 404s elsewhere
        # (Nmap http-enum tell when every path returns 200).
        if not self._known_host(host_header):
            ds_path = path.split("?", 1)[0]
            if method in ("GET", "HEAD") and ds_path in ("/", "/index.html", "/index.htm"):
                payload = phpapp.default_server_html().encode("utf-8")
                ds_status = 200
            else:
                payload = phpapp.apache_error(404, "Not Found")
                ds_status = 404
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            _send_raw(conn, _http_response(ds_status, "text/html", payload,
                                           head_only=(method == "HEAD"),
                                           server=phpapp.APACHE_SERVER))
            try:
                self.events.emit(
                    "http", service="http", session=session,
                    http_method=method, http_path=path[:200], http_status=ds_status,
                    uri_len=uri_len, host_header=host_header, user_agent=ua[:200],
                    tags=["default-server"],
                )
            except Exception:
                pass
            return

        # Domain Host over plain HTTP -> 301 to HTTPS (bare IP stays on HTTP).
        _h = (host_header or "").split(":")[0].strip().lower()
        _dom = (self.world.get("domain") or "").lower()
        if (self.https_redirect and self._ssl_ctx is not None
                and session.get("local_port") not in HTTPS_PORTS and _dom
                and (_h == _dom or _h.endswith("." + _dom))):
            payload = _nginx_error(301, "Moved Permanently")
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            _srv = _SERVER_FULL
            if self._plain_server_host(host_header):
                _srv = "nginx"
                payload = _plain_server_payload(payload)
            _send_raw(conn, _http_response(301, "text/html", payload,
                                           head_only=(method == "HEAD"),
                                           extra="Location: https://%s%s\r\n" % (_h, path or "/"),
                                           server=_srv))
            try:
                self.events.emit(
                    "http", service="http", session=session,
                    http_method=method, http_path=path[:200], http_status=301,
                    uri_len=uri_len, host_header=host_header, user_agent=ua[:200],
                    tags=["https-redirect"],
                )
            except Exception:
                pass
            return

        if method == "POST" and body:
            posted = body.decode("latin-1", "replace")
            session["events"].append(_event(
                "http-post", "%s %s" % (path, posted[:200])))
            user, pw = _form_user_pass(posted)
            if user is not None or pw is not None:
                session["credentials"].append({
                    "username": user or "", "password": pw or "", "service": "web",
                    "raw": posted[:200],
                })
            _tag_http_exploit(session, path, posted)

        # PHP2Shell lure: flag session-upload-progress / oversized PHPSESSID.
        # Log payload URLs but NEVER fetch them / never contact attacker infra.
        try:
            p2s = phpapp.inspect_php2shell(
                head.decode("latin-1", "replace"),
                body,
                declared_length=session.get("http_declared_length") or 0,
                cookies=session.get("http_cookie") or "",
            )
            # Profile P1: chunked-without-CL + incomplete worker-hold tags
            _meta = session.get("http_body_meta") or {}
            if _meta.get("chunked_no_cl"):
                tags = list(p2s.get("tags") or [])
                if "php2shell-chunked-no-cl" not in tags:
                    tags.append("php2shell-chunked-no-cl")
                p2s["tags"] = tags
                reasons = list(p2s.get("reasons") or [])
                if "chunked_no_cl" not in reasons:
                    reasons.append("chunked_no_cl")
                p2s["reasons"] = reasons
                p2s["hit"] = True
                session["events"].append(_event(
                    "php2shell-chunked-no-cl",
                    "te=chunked; no content-length"))
            if _meta.get("worker_hold"):
                tags = list(p2s.get("tags") or [])
                if "php2shell-worker-hold" not in tags:
                    tags.append("php2shell-worker-hold")
                p2s["tags"] = tags
                p2s["hit"] = True
                session["events"].append(_event(
                    "php2shell-worker-hold",
                    (_meta.get("worker_hold_reason")
                     or "idle_timeout")[:80]))
            session["php2shell"] = p2s
            if p2s.get("hit"):
                session["events"].append(_event(
                    "php2shell", ",".join(p2s.get("reasons") or [])[:200]))
                for u in (p2s.get("payload_urls") or [])[:3]:
                    session["events"].append(_event(
                        "php2shell-url-logged", u[:200]))
                if p2s.get("stage"):
                    session["events"].append(_event(
                        "php2shell-stage", (p2s.get("stage") or "")[:80]))
        except Exception:
            p2s = {"hit": False, "tags": [], "stages": []}

        # S5 / drop-path dictionary: log ALL probes (allowlist + broader set),
        # even when response will be 404. Never execute.
        try:
            from . import php2shell_chain as _p2s_chain
        except Exception:
            _p2s_chain = None
        try:
            _cpath = (path or "").split("?", 1)[0]
            _is_canary = _cpath in getattr(phpapp, "PHP2SHELL_CANARY_PATHS", ())
            _is_drop = False
            if _p2s_chain is not None:
                _is_drop = _p2s_chain.is_drop_probe_path(_cpath)
            if _is_canary or _is_drop:
                p2s = dict(session.get("php2shell") or p2s or {})
                tags = list(p2s.get("tags") or [])
                for t in ("php2shell-post-rce-probe", "php2shell-canary-hit",
                          "php2shell-drop-probe"):
                    if t not in tags:
                        # canary-hit only for allowlisted paths
                        if t == "php2shell-canary-hit" and not _is_canary:
                            continue
                        tags.append(t)
                stages = list(p2s.get("stages") or [])
                if "post_rce_probe" not in stages:
                    stages.append("post_rce_probe")
                if "drop_probe" not in stages:
                    stages.append("drop_probe")
                probed = list(p2s.get("drop_paths_probed") or [])
                if _cpath not in probed:
                    probed.append(_cpath[:200])
                p2s.update({
                    "hit": True,
                    "tags": tags,
                    "stages": stages,
                    "stage": "post_rce_probe" if _is_canary else "drop_probe",
                    "response_shape": (
                        "canary_stub" if _is_canary else "drop_probe_404"),
                    "canary_path": _cpath if _is_canary else None,
                    "drop_paths_probed": probed[-32:],
                    "php2shell_drop_probe": _cpath,
                })
                session["php2shell"] = p2s
                session["events"].append(_event(
                    "php2shell_drop_probe", _cpath[:200]))
                if _is_canary:
                    session["events"].append(_event(
                        "php2shell-canary", _cpath[:200]))
                if _p2s_chain is not None:
                    _p2s_chain.note_drop_probe(
                        (p2s.get("phpsessid_echo") or "")[:128], _cpath)
        except Exception:
            pass

        _tag_http_exploit(session, path, "")

        web_user, web_token, web_row = self._web_user_from_headers(head)
        if web_user:
            session["auth_ok"] = True
            session["username"] = web_user

        if method == "OPTIONS":
            _send_raw(conn, _http_response(204, "text/plain", b"", head_only=True,
                                           extra="Allow: GET, POST, HEAD, OPTIONS\r\n"))
            return

        page, ctype, code, set_cookie, extra_headers = self._page(
            path, session, method, body, web_user=web_user,
            web_token=web_token, web_row=web_row,
            host_header=host_header)

        clean_path = path.split("?", 1)[0]
        query = path.split("?", 1)[1] if "?" in path else ""
        syno_api = syno_method = syno_version = ""
        if "/webapi/" in clean_path or clean_path.startswith("/webman/"):
            qs = urllib.parse.parse_qs(query, keep_blank_values=True)
            syno_api = (qs.get("api") or [""])[0]
            syno_method = (qs.get("method") or [""])[0]
            syno_version = (qs.get("version") or [""])[0]
        _dsm_surface = bool(session.get("dsm_surface"))
        _http_tags = []
        if "/webapi/" in clean_path or "/webman/" in clean_path:
            # Page-load assets must not trip high-signal (login.js / login.cgi GET).
            if method in ("GET", "HEAD") and (
                    clean_path in ("/webman/login.js", "/webman/login.cgi",
                                   "/scripts/synology/dist/login.js")
                    or clean_path.startswith("/scripts/synology/")):
                _http_tags.append("dsm-page-asset")
            elif _dsm_surface:
                _http_tags.append("high-synology-webapi")
            else:
                _http_tags.append("synology-probe-offsurface")
        if phpapp.is_page_asset(clean_path, method):
            _http_tags.append("php-page-asset")
        p2s = session.get("php2shell") or {}
        if p2s.get("hit"):
            _http_tags.extend(p2s.get("tags") or ["php2shell-probe"])
        # Public->privesc bait tags (from phpapp/public_privesc adapter)
        for _bt in (session.get("bait_tags") or []):
            if _bt and _bt not in _http_tags:
                _http_tags.append(_bt)
        if ((method == "POST" and clean_path in (
                "/login.php", "/upload.php", "/admin/login.php",
                "/webman/login.cgi")) or (
                method in ("GET", "POST") and "/webapi/auth.cgi" in clean_path)):
            if "php-page-asset" not in _http_tags and "dsm-page-asset" not in _http_tags:
                _http_tags.append("high-login-or-api")
        _http_tags = _http_tags or None
        req_line_cap = request_line[:events_module.REQUEST_LINE_CAP]
        body_text, body_enc, body_len, _body_trunc = events_module.capture_bytes(
            body or b"", events_module.BODY_CAP)
        try:
            self.events.emit(
                "syno_api" if syno_api else "http",
                service=session.get("service") or "http", session=session,
                http_method=method, http_path=clean_path[:500],
                http_query=query[:500], http_version=version,
                host_header=host_header, user_agent=ua[:300],
                referer=referer[:300], content_type=content_type,
                content_length=len(body or b""), http_status=code,
                uri_len=uri_len, request_line=req_line_cap,
                request_line_truncated=(
                    len(request_line) > events_module.REQUEST_LINE_CAP),
                body_len=body_len, body_first_bytes=body_text[:256],
                body_encoding=body_enc,
                syno_api=syno_api or None,
                syno_method=syno_method or None,
                syno_version=syno_version or None,
                session_cookie=web_token or None,
                syno_token=(web_row or {}).get("synotoken") if web_row else None,
                session_material_presented=bool(web_token),
                session_material_valid=bool(web_user),
                session_material_known=bool(web_row),
                http_vhost_role=session.get("http_vhost_role") or None,
                dsm_surface=_dsm_surface,
                dsm_page_asset=("dsm-page-asset" in (_http_tags or [])),
                php2shell=bool(p2s.get("hit")),
                php2shell_reasons=p2s.get("reasons") or None,
                php2shell_stage=(
                    session.get("php2shell_stage") or p2s.get("stage") or None),
                php2shell_stages=p2s.get("stages") or None,
                php2shell_t_array_count=p2s.get("t_array_count"),
                php2shell_file_parts=p2s.get("file_parts"),
                php2shell_progress_name=(p2s.get("progress_name") or None),
                php2shell_payload_urls=p2s.get("payload_urls") or None,
                php2shell_response_shape=(
                    session.get("php2shell_response_shape")
                    or p2s.get("response_shape") or None),
                php2shell_canary_path=p2s.get("canary_path") or None,
                php2shell_sessid_len=p2s.get("phpsessid_len"),
                php2shell_drop_probe=p2s.get("php2shell_drop_probe") or None,
                drop_paths_probed=p2s.get("drop_paths_probed") or None,
                campaign_key=(session.get("php2shell_research") or {}).get(
                    "campaign_key") or p2s.get("campaign_key"),
                sess_family=(session.get("php2shell_research") or {}).get(
                    "sess_family") or p2s.get("sess_family"),
                stage_delta_ms=(session.get("php2shell_research") or {}).get(
                    "stage_delta_ms"),
                body_sample_sha256=(session.get("php2shell_research") or {}).get(
                    "body_sample_sha256"),
                body_sample_path=(session.get("php2shell_research") or {}).get(
                    "body_sample_path"),
                body_sample_len=(session.get("php2shell_research") or {}).get(
                    "body_sample_len"),
                multipart_filenames=(session.get("php2shell_research") or {}).get(
                    "multipart_filenames"),
                multipart_field_names=(
                    session.get("php2shell_research") or {}).get(
                    "multipart_field_names"),
                phpsessid_sha256=(session.get("php2shell_research") or {}).get(
                    "phpsessid_sha256"),
                phpsessid_head_tail=(
                    session.get("php2shell_research") or {}).get(
                    "phpsessid_head_tail"),
                content_length_declared=session.get("http_declared_length") or 0,
                body_prefix_len=len(body or b""),
                body_drained_bytes=session.get("body_drained_bytes") or 0,
                body_drain_capped=bool(session.get("body_drain_capped")),
                tls_ja3=session.get("tls_ja3") or None,
                tags=_http_tags,
            )
        except Exception:
            pass

        extra = ""
        if session.get("http_vhost_role") in ("clinic", "portal", "billing", "mail"):
            set_cookie = ""  # DSM cookies only on the NAS hosts
        if set_cookie:
            row = {}
            with self._lock:
                row = dict(self._web_sessions.get(set_cookie) or {})
            sid = row.get("sid") or set_cookie[:16]
            extra += "Set-Cookie: id=%s; Path=/; HttpOnly\r\n" % sid
            extra += "Set-Cookie: nas_session=%s; Path=/; HttpOnly\r\n" % set_cookie
            if row.get("auth_ok"):
                extra += "Set-Cookie: stay_login=1; Path=/\r\n"
        if code == 302:
            _has_loc = any(
                (h or "").lower().startswith("location:")
                for h in (extra_headers or []))
            if not _has_loc:
                extra += "Location: /files/\r\n"
        for hdr in (extra_headers or []):
            extra += hdr if hdr.endswith("\r\n") else (hdr + "\r\n")
        if isinstance(page, (bytes, bytearray)):
            payload = bytes(page)
        else:
            payload = page.encode("utf-8")
        role_now = session.get("http_vhost_role") or ""
        if role_now in ("clinic", "portal", "billing", "mail", "files", "php"):
            _srv = phpapp.APACHE_SERVER
            # Ensure X-Powered-By on PHP surfaces when handler didn't set it.
            # Red Delta B: raw sess_* omit it (bare text/plain / research flag).
            _omit_xpb = (
                session.get("php2shell_response_shape") == "session_blob"
                and (
                    (session.get("php2shell_research") or {}).get(
                        "omit_x_powered_by")
                    or ((ctype or "").strip() == "text/plain")
                )
            )
            if not _omit_xpb and "X-Powered-By:" not in extra:
                extra += "X-Powered-By: %s\r\n" % phpapp.X_POWERED_BY
        else:
            _srv = _SERVER_FULL
            if self._plain_server_host(host_header):
                _srv = "Apache"
        _send_raw(conn, _http_response(code, ctype, payload,
                                       head_only=(method == "HEAD"), extra=extra,
                                       server=_srv))

    def _web_revealed(self, token):
        if not token:
            return False
        with self._lock:
            row = self._web_sessions.get(token)
            return bool(row and row.get("revealed"))

    def _mark_web_revealed(self, token):
        if not token:
            return
        with self._lock:
            row = self._web_sessions.get(token)
            if row is not None:
                row["revealed"] = True

    def _page(self, path, session, method="GET", body=b"", web_user="",
              web_token="", web_row=None, host_header=""):
        """Return (body, content_type, status_code, set_cookie_token, extra_headers).

        set_cookie_token is our internal nas_session token (or "" if none);
        _web turns it into DSM-style Set-Cookie headers (id= + nas_session=).
        Live realism: /api/status stays gated; unknown paths stay nginx 404.
        """
        clean = path.split("?", 1)[0]
        query = path.split("?", 1)[1] if "?" in path else ""
        qs = urllib.parse.parse_qs(query, keep_blank_values=True)
        files = self.world["files"]
        shares = self.world.get("shares") or {}
        authed = bool(web_user) or bool(session.get("auth_ok"))
        set_cookie = ""
        web_row = web_row or {}

        # ---- Per-Host decoy sites (clinic / portal / billing / mail) ----
        # files./srv-files. (and bare IP) fall through to Synology DSM below.
        # Soft-fail hosts never mint File Station sessions.
        role = vhosts.role_for_host(
            host_header,
            domain=self.world.get("domain") or "",
            fqdn=self.world.get("fqdn") or "",
            hostname=self.world.get("hostname") or "",
        )
        # Sunday overhaul: Synology NAS cover retired (NAS-on-AWS-IP tell).
        # Opt back in with ANGLERFISH_ALLOW_DSM=1.
        allow_dsm = os.environ.get("ANGLERFISH_ALLOW_DSM", "").strip().lower() in (
            "1", "true", "yes", "on")
        if role == "files" and not allow_dsm:
            role = "php"  # staff PHP portal instead of DSM
        session["http_vhost_role"] = role
        # DSM surface only when explicitly allowed and role is files.
        session["dsm_surface"] = bool(allow_dsm and role == "files")
        if (role == "clinic" and method == "POST"
                and clean in vhosts.CONTACT_PATHS):
            fields = {}
            try:
                for k, v in urllib.parse.parse_qsl(
                        (body or b"").decode("utf-8", "replace"),
                        keep_blank_values=True):
                    if k in ("name", "email", "message") and k not in fields:
                        fields[k] = v
            except Exception:
                pass
            session["events"].append(_event(
                "http-contact-form", (fields.get("email") or "")[:120]))
            try:
                self.events.emit(
                    "contact_form", service="http", session=session,
                    http_method=method, http_path=clean[:200],
                    host_header=host_header, tags=["contact-form"],
                    contact_name=(fields.get("name") or "")[:200],
                    contact_email=(fields.get("email") or "")[:200],
                    contact_message=(fields.get("message") or "")[:2000],
                    contact_message_len=len(fields.get("message") or ""),
                )
            except Exception:
                pass
            return vhosts.contact_thanks(self.world)
        if role == "php":
            failed = (method == "POST" and phpapp.PHP_LOGIN in (clean, path.split("?",1)[0]))
            if failed:
                session["events"].append(_event("http-softfail-login", "php %s" % path[:120]))
            world = dict(self.world or {})
            world["http_declared_length"] = session.get("http_declared_length") or 0
            world["http_cookie"] = session.get("http_cookie") or ""
            world["php2shell"] = session.get("php2shell") or {}
            world["src_ip"] = session.get("peer_ip") or ""
            world["http_ua"] = session.get("http_user_agent") or session.get("user_agent") or ""
            world["http_hostname"] = (
                self.world.get("hostname") or "ip-10-0-0-21")
            handled = phpapp.staff_files_portal(
                path, method=method, body=body, world=world, failed=failed)
            if handled is not None:
                if isinstance(world.get("php2shell_research"), dict):
                    session["php2shell_research"] = world["php2shell_research"]
                if world.get("php2shell_stage"):
                    session["php2shell_stage"] = world["php2shell_stage"]
                if world.get("php2shell_response_shape"):
                    session["php2shell_response_shape"] = world[
                        "php2shell_response_shape"]
                if world.get("bait_tags"):
                    session["bait_tags"] = list(world.get("bait_tags") or [])
                if world.get("bait_events"):
                    session["bait_events"] = list(world.get("bait_events") or [])
                page, ctype, code, set_cookie, extra_headers = handled
                return page, ctype, code, set_cookie, extra_headers
            # Unknown path on php surface -> Apache 404
            return (phpapp.apache_error(404, "Not Found"), "text/html", 404, "",
                    phpapp.apache_headers())
        if role == "clinic":
            # Prefer PHP clinic surfaces (login/upload/phpinfo/.env) over static-only.
            failed = (method == "POST" and clean in (
                phpapp.PHP_LOGIN, "/login", "/admin/login.php"))
            world = dict(self.world or {})
            world["http_declared_length"] = session.get("http_declared_length") or 0
            world["http_cookie"] = session.get("http_cookie") or ""
            world["php2shell"] = session.get("php2shell") or {}
            world["src_ip"] = session.get("peer_ip") or ""
            world["http_ua"] = session.get("http_user_agent") or session.get("user_agent") or ""
            world["http_hostname"] = (
                self.world.get("hostname") or "ip-10-0-0-21")
            world["php2shell_apply_delay"] = True
            handled = phpapp.handle(
                path, method=method, body=body, world=world, failed=failed,
                role="clinic")
            if handled is not None:
                # Pull research capture / stage back onto the session.
                if isinstance(world.get("php2shell_research"), dict):
                    session["php2shell_research"] = world["php2shell_research"]
                if world.get("php2shell_stage"):
                    session["php2shell_stage"] = world["php2shell_stage"]
                if world.get("php2shell_response_shape"):
                    session["php2shell_response_shape"] = world[
                        "php2shell_response_shape"]
                if world.get("bait_tags"):
                    session["bait_tags"] = list(world.get("bait_tags") or [])
                if world.get("bait_events"):
                    session["bait_events"] = list(world.get("bait_events") or [])
                page, ctype, code, set_cookie, extra_headers = handled
                return page, ctype, code, set_cookie, extra_headers
        if role != "unknown":
            failed = (method == "POST" and role in ("portal", "billing", "mail")
                      and vhosts.soft_fail_login(path, method, body))
            if failed:
                session["events"].append(_event("http-softfail-login", "%s %s" % (role, path[:120])))
            handled = vhosts.handle(
                role, path, method=method, body=body,
                world=self.world, failed=failed)
            if handled is not None:
                return handled

        # ---- Synology DSM webapi / webman (deception: Synology surface) ----
        if clean in ("/webapi/query.cgi", "/webapi/entry.cgi",
                     "/webapi/auth.cgi", "/webman/login.cgi",
                     "/webapi/auth.cgi/", "/webapi/query.cgi/"):
            return self._dsm_api(clean, qs, method, body, session,
                                web_user, web_token, web_row)

        if clean in ("/webman/login.js", "/scripts/synology/dist/login.js"):
            return (dsm.login_js(), "application/javascript; charset=utf-8",
                    200, "", [])
        if clean == "/webman/login.cgi" and (qs.get("css") or [""])[0]:
            return dsm.login_css(), "text/css; charset=utf-8", 200, "", []

        # Health probe stays public but says nothing about the box (like a
        # load-balancer check). Full status (internal IP, services, ports) is
        # session-only: a real NAS never hands that to an anonymous visitor.
        if clean == "/health":
            return '{"status":"ok"}\n', "application/json", 200, "", []
        if clean in ("/api/status", "/api/system"):
            if not authed:
                session.setdefault("events", []).append(
                    _event("http-unauth", "%s without session" % clean))
                return ('{"success":false,"error":{"code":401,'
                        '"message":"authentication required"}}\n',
                        "application/json", 401, "", [])
            return _status_json(self.world, self.ports), "application/json", 200, "", []

        # Share file download: /files/<share>/<name> — share tree only.
        if clean.startswith("/files/") and clean not in ("/files/", "/files"):
            if not authed:
                set_cookie = web_token or self._issue_web_session(
                    "", provisional=True)
                return (dsm.login_page_html(self.world, session_id=set_cookie),
                        "text/html; charset=utf-8", 200, set_cookie, [])
            rel = clean[len("/files/"):]
            target = _resolve_share_path(rel, files, shares)
            if target and target in files:
                session["read_files"].append(target)
                session["events"].append(_event("read-file", target))
                try:
                    self.events.emit(
                        "path_read", service="http", session=session,
                        path_read=target,
                        username=web_user or session.get("username"),
                        auth_ok=True,
                        cred_source=session.get("cred_source") or "session",
                        gotcha_id=target if is_reveal_path(target) else None,
                    )
                except Exception:
                    pass
                content = files[target]
                if is_reveal_path(target):
                    self._gotcha(session, target, "web")
                    self._mark_web_revealed(web_token)
                    if isinstance(content, str):
                        prompt = (WEB_GUESTBOOK_PROMPT_CLASSROOM
                                  if self.classroom else WEB_GUESTBOOK_PROMPT)
                        content = content.rstrip("\n") + "\n" + prompt
                if target.endswith(".png"):
                    ctype = "image/png"
                elif target.endswith(".csv"):
                    ctype = "text/csv; charset=utf-8"
                else:
                    ctype = "text/plain; charset=utf-8"
                return content, ctype, 200, "", []
            return (_not_found_page(self.world),
                    "text/html; charset=utf-8", 404, "", [])

        posted = body.decode("latin-1", "replace") if body else ""
        if clean == "/guestbook":
            if not authed:
                set_cookie = web_token or self._issue_web_session(
                    "", provisional=True)
                return (dsm.login_page_html(self.world, session_id=set_cookie),
                        "text/html; charset=utf-8", 200, set_cookie, [])
            if method == "POST":
                note = ""
                for pair in posted.split("&"):
                    key, _eq, value = pair.partition("=")
                    if urllib.parse.unquote_plus(key) in ("note", "message", "msg"):
                        note = urllib.parse.unquote_plus(value)
                        break
                signed = self._sign_guestbook(session, note, "web")
                return (_dashboard_page(self.world, guestbook_form=True,
                                        signed=bool(signed)),
                        "text/html; charset=utf-8", 200, "", [])
            return (_dashboard_page(self.world, guestbook_form=True),
                    "text/html; charset=utf-8", 200, "", [])

        if method == "POST" and clean in ("/", "/login", "/admin"):
            user, pw = _form_user_pass(posted)
            if user is not None and pw is not None:
                if self._record_password(session, "web", user, pw):
                    session["username"] = user
                    set_cookie = self._issue_web_session(user, provisional=False)
                    return (_dashboard_page(self.world),
                            "text/html; charset=utf-8", 200, set_cookie, [])
                set_cookie = web_token or self._issue_web_session(
                    "", provisional=True)
                return (dsm.login_page_html(self.world, failed=True,
                                            session_id=set_cookie),
                        "text/html; charset=utf-8", 200, set_cookie, [])
            set_cookie = web_token or self._issue_web_session(
                "", provisional=True)
            return (dsm.login_page_html(self.world, failed=True,
                                        session_id=set_cookie),
                    "text/html; charset=utf-8", 200, set_cookie, [])

        if clean in ("/dashboard", "/admin/dashboard", "/files", "/files/",
                     "/shares"):
            if authed:
                return (_dashboard_page(
                            self.world,
                            guestbook_form=self._web_revealed(web_token)),
                        "text/html; charset=utf-8", 200, "", [])
            set_cookie = web_token or self._issue_web_session(
                "", provisional=True)
            return (dsm.login_page_html(self.world, session_id=set_cookie),
                    "text/html; charset=utf-8", 200, set_cookie, [])

        if clean in ("/", "/login", "/admin", "/index.html"):
            if authed:
                return (_dashboard_page(
                            self.world,
                            guestbook_form=self._web_revealed(web_token)),
                        "text/html; charset=utf-8", 200, "", [])
            # DSM issues a session cookie on the login GET.
            set_cookie = web_token or self._issue_web_session(
                "", provisional=True)
            return (dsm.login_page_html(self.world, session_id=set_cookie),
                    "text/html; charset=utf-8", 200, set_cookie, [])

        # Real nginx: unknown paths are 404, not the login page.
        return _nginx_error(404, "Not Found"), "text/html", 404, "", []

    def _dsm_api(self, clean, qs, method, body, session, web_user, web_token,
                 web_row):
        """Scripted Synology DSM webapi/webman answers. Never executes input;
        planted/canary creds mint a sandboxed File Station session only."""
        api = (qs.get("api") or [""])[0]
        meth = (qs.get("method") or [""])[0]
        posted = {}
        if body:
            posted = urllib.parse.parse_qs(
                body.decode("latin-1", "replace"), keep_blank_values=True)
            api = api or (posted.get("api") or [""])[0]
            meth = meth or (posted.get("method") or [""])[0]

        if clean.startswith("/webman/login.cgi") and not (qs.get("css") or [""])[0]:
            set_cookie = web_token or self._issue_web_session(
                "", provisional=True)
            html = dsm.login_page_html(self.world, session_id=set_cookie)
            return html, "text/html; charset=utf-8", 200, set_cookie, []

        if clean.endswith("query.cgi") or api == "SYNO.API.Info":
            query = (qs.get("query") or posted.get("query") or ["all"])[0]
            payload = json.dumps(dsm.api_info_response(query))
            return payload, "application/json; charset=utf-8", 200, "", []

        if clean.endswith("auth.cgi") or api == "SYNO.API.Auth":
            if meth.lower() == "logout":
                return (json.dumps(dsm.auth_logout_response()),
                        "application/json; charset=utf-8", 200, "", [])
            account = ((qs.get("account") or posted.get("account")
                        or qs.get("username") or posted.get("username")
                        or [""])[0])
            passwd = ((qs.get("passwd") or posted.get("passwd")
                       or qs.get("password") or posted.get("password")
                       or [""])[0])
            if account or passwd:
                ok = self._record_password(session, "http", account, passwd)
                if ok:
                    session["username"] = account
                    set_cookie = self._issue_web_session(
                        account, provisional=False)
                    with self._lock:
                        row = self._web_sessions.get(set_cookie) or {}
                    resp = dsm.auth_login_response(
                        True, sid=row.get("sid"),
                        synotoken=row.get("synotoken"))
                    return (json.dumps(resp),
                            "application/json; charset=utf-8", 200,
                            set_cookie, [])
                resp = dsm.auth_login_response(False)
                set_cookie = web_token or self._issue_web_session(
                    "", provisional=True)
                return (json.dumps(resp),
                        "application/json; charset=utf-8", 200, set_cookie, [])
            return (json.dumps(dsm.auth_login_response(False)),
                    "application/json; charset=utf-8", 200, "", [])

        if clean.endswith("entry.cgi"):
            if not web_user:
                return (json.dumps(dsm.entry_need_auth()),
                        "application/json; charset=utf-8", 200, "", [])
            if api == "SYNO.Core.System" or meth.lower() in ("info", "get"):
                if "System" in api or meth.lower() == "info":
                    return (json.dumps(dsm.system_info(self.world)),
                            "application/json; charset=utf-8", 200, "", [])
            if (api.startswith("SYNO.FileStation")
                    or meth.lower() in ("list", "list_share")):
                folder = ((qs.get("folder_path") or posted.get("folder_path")
                           or ["/"])[0])
                if folder in ("/", ""):
                    return (json.dumps(dsm.entry_list_shares(self.world)),
                            "application/json; charset=utf-8", 200, "", [])
                return (json.dumps(dsm.filestation_list(
                            self.world, folder,
                            self.world.get("shares") or {})),
                        "application/json; charset=utf-8", 200, "", [])
            return (json.dumps(dsm.system_info(self.world)),
                    "application/json; charset=utf-8", 200, "", [])

        return (json.dumps({"success": False, "error": {"code": 105}}),
                "application/json; charset=utf-8", 404, "", [])


    def _finish(self, session):
        session["credential_count"] = len(session["credentials"])
        with self._lock:
            self.sessions.append(session)
            proto = session.get("protocol") or "?"
            self._stats["by_protocol"][proto] = self._stats["by_protocol"].get(proto, 0)
        self._write_local(session)
        self._write_status()
        self._report(session)
        session["gotcha_count"] = len(session.get("gotchas", []))
        taken = ", ".join(f.rsplit("/", 1)[1] for f in session["read_files"]) or "nothing"
        self._note("session %s from %s on port %d (%s): %d commands, read %s"
                   % (session["id"], session["peer_ip"], session["local_port"],
                      session.get("protocol"), len(session["commands"]), taken))

    def _write_local(self, session):
        try:
            folder = os.path.dirname(self.log_path)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder)
            try:
                if os.path.exists(self.log_path) and os.path.getsize(self.log_path) > LOG_ROTATE_BYTES:
                    os.replace(self.log_path, self.log_path + ".1")
            except OSError:
                pass
            # Cap in-memory session history so a long-lived sensor cannot grow forever.
            with self._lock:
                if len(self.sessions) > 500:
                    self.sessions = self.sessions[-250:]
                if len(self.probes) > 1000:
                    self.probes = self.probes[-400:]
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(session, default=str) + "\n")
        except OSError:
            pass

    def _write_status(self):
        """Local probe counters so you can see the sensor is catching traffic."""
        now = time.time()
        if now - self._last_status_write < STATUS_WRITE_MIN_GAP:
            return
        self._last_status_write = now
        try:
            folder = os.path.dirname(self.status_path)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder)
            with self._lock:
                payload = {
                    "sensor": self.name,
                    "bind": self.bind,
                    "ports": self.ports,
                    "updated": time.time(),
                    "uptime_seconds": round(time.time() - self._stats["started"], 1),
                    "probes_total": self._stats["probes_total"],
                    "by_port": dict(self._stats["by_port"]),
                    "by_protocol": dict(self._stats["by_protocol"]),
                    "auth_ok": self._stats["auth_ok"],
                    "auth_fail": self._stats["auth_fail"],
                    "sessions": len(self.sessions),
                    "recent": list(self._stats["recent"][-20:]),
                    "gotcha_total": self._stats["gotcha_total"],
                    "gotchas": list(self._stats["gotchas"][-20:]),
                    "guestbook_total": self._stats["guestbook_total"],
                    "guestbook": list(self._stats["guestbook"][-20:]),
                    "reveals_log": self.reveals_path,
                }
            temporary = self.status_path + ".tmp"
            with open(temporary, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(temporary, self.status_path)
        except OSError:
            pass

    def _report(self, session):
        if not self.console:
            return
        self._post("/api/report", {"kind": "session", "sensor": self.name,
                                   "session": session})

    def _register(self):
        if not self.console:
            return
        light = [{"id": t["id"], "kind": t["kind"], "label": t["label"]}
                 for t in self.tokens]
        self._post("/api/register", {"sensor": self.name, "tokens": light,
                                     "hostname": self.world["hostname"]})

    def _post(self, path, payload):
        try:
            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json",
                       "User-Agent": "python-urllib3/1.26"}
            if self.console_token:
                headers["X-Decoy-Token"] = self.console_token
            request = urllib.request.Request(
                self.console + path, data=data, headers=headers)
            urllib.request.urlopen(request, timeout=5).read()
        except Exception:
            pass

    def _note(self, text):
        line = "%s  %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
        print(line, flush=True)


    def _serve_dns(self, port):
        """Minimal UDP DNS facade: log queries, return canned answers.

        Not enabled by default (not in DEFAULT_PORTS / live unit). Only listens
        when 53 or 5353 is passed on --ports. Never recursively resolves.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.bind, port))
            sock.settimeout(1.0)
        except OSError as exc:
            self._note("could not open DNS port %d: %s" % (port, exc))
            return
        self._note("listening on %s:%d (dns/udp)" % (self.bind, port))
        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle_dns(sock, data, addr, port)
            except Exception as exc:
                self._note("dns handler error: %s" % exc)
        sock.close()

    def _handle_dns(self, sock, data, addr, port):
        if len(data) < 12:
            return
        dns_id = struct.unpack("!H", data[0:2])[0]
        flags = struct.unpack("!H", data[2:4])[0]
        opcode = (flags >> 11) & 0xF
        qname, qtype, offset = _dns_parse_question(data)
        session = {
            "id": "%s-dns-%d-%d" % (self.name, int(time.time()), dns_id),
            "peer_ip": addr[0], "peer_port": addr[1],
            "local_port": port, "service": "dns", "protocol": "dns",
        }
        rcode = 0
        answers = b""
        ancount = 0
        if qname.lower().rstrip(".") == "version.bind" and qtype == 16:
            txt = "dnsmasq-2.85"
            rdata = bytes([len(txt)]) + txt.encode("ascii")
            answers = _dns_rr(qname, 16, 3, 60, rdata)  # CHAOS=3
            ancount = 1
        elif qtype == 252:  # AXFR — refuse
            rcode = 5
        elif qtype in (1, 255):  # A / ANY -> bait internal IP
            ip = self.world.get("internal_ip") or "10.0.0.21"
            parts = [int(x) for x in ip.split(".")]
            rdata = struct.pack("BBBB", *parts)
            answers = _dns_rr(qname, 1, 1, 60, rdata)
            ancount = 1
        else:
            rcode = 3  # NXDOMAIN
        try:
            self.events.emit(
                "dns", service="dns", session=session, transport="udp",
                dns_qname=qname, dns_qtype=qtype, dns_opcode=opcode,
                dns_rcode=rcode, dns_id=dns_id,
            )
        except Exception:
            pass
        resp_flags = 0x8400 | (opcode << 11) | rcode
        header = struct.pack("!HHHHHH", dns_id, resp_flags, 1, ancount, 0, 0)
        question = data[12:offset] if offset > 12 else data[12:]
        try:
            sock.sendto(header + question + answers, addr)
        except OSError:
            pass




def _dns_parse_question(data):
    """Return (qname, qtype, offset_after_question)."""
    labels = []
    i = 12
    while i < len(data):
        n = data[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            i += 2
            break
        labels.append(data[i + 1:i + 1 + n].decode("latin-1", "replace"))
        i += 1 + n
    qname = ".".join(labels)
    if i + 4 > len(data):
        return qname, 0, i
    qtype, _qclass = struct.unpack("!HH", data[i:i + 4])
    return qname, qtype, i + 4


def _dns_encode_name(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii", "replace")[:63]
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _dns_rr(name, rtype, rclass, ttl, rdata):
    return (_dns_encode_name(name)
            + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata))
            + rdata)


def _event(kind, detail):
    return {"at": time.time(), "kind": kind, "detail": detail}


def _send(conn, text):
    _send_raw(conn, text.replace("\n", "\r\n").encode("latin-1", "replace")
              if "\r\n" not in text else text.encode("latin-1", "replace"))


def _send_raw(conn, data):
    try:
        conn.sendall(data)
    except OSError:
        pass


_PENDING = weakref.WeakKeyDictionary()


def _line(conn, pre=b""):
    buffer = bytearray(_PENDING.pop(conn, b""))
    if pre:
        buffer.extend(pre)
    while b"\n" not in buffer and len(buffer) < READ_LIMIT:
        try:
            chunk = conn.recv(256)
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buffer.extend(chunk)
    if b"\n" in buffer:
        raw = bytes(buffer)
        line, _, rest = raw.partition(b"\n")
        if rest:
            _PENDING[conn] = rest
        return line.decode("latin-1", "replace").rstrip("\r")
    return bytes(buffer).decode("latin-1", "replace").rstrip("\r")

def _http_head_and_body(conn, first):
    """Return (head, body_prefix, declared_length, drained_bytes, drain_capped, meta).

    meta may include: chunked_no_cl, worker_hold (incomplete POST idle timeout).
    Inspect prefix hard-capped at phpapp.BODY_PREFIX_CAP (256KiB research).
    Never buffer ~140MB. Profile P1: accept Transfer-Encoding: chunked without
    Content-Length. After prefix, drain remaining under time/byte cap (FIN).
    """
    import time as _time
    head_cap = max(READ_LIMIT, MAX_URI_LEN + 2048)
    body_cap = getattr(phpapp, "BODY_PREFIX_CAP", READ_LIMIT)
    drain_byte_cap = 8 * 1024 * 1024  # hard max discard
    drain_time_cap = 3.0
    chunked_idle_timeout = 2.0
    meta = {}
    data = bytearray(first)
    while b"\r\n\r\n" not in data and len(data) < head_cap:
        try:
            chunk = conn.recv(min(2048, head_cap - len(data)))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        data.extend(chunk)
        if b"\r\n" not in data and len(data) > MAX_URI_LEN + 32:
            break
    raw = bytes(data)
    if b"\r\n\r\n" not in raw:
        return raw, b"", 0, 0, False, meta
    head, body = raw.split(b"\r\n\r\n", 1)
    declared = 0
    te_chunked = False
    for line in head.split(b"\r\n"):
        low = line.lower()
        if low.startswith(b"content-length:"):
            try:
                declared = int(line.split(b":", 1)[1].strip() or b"0")
            except ValueError:
                declared = 0
        elif low.startswith(b"transfer-encoding:") and b"chunked" in low:
            te_chunked = True
    if declared < 0:
        declared = 0

    # Profile P1: chunked without Content-Length
    if declared == 0 and te_chunked:
        meta["chunked_no_cl"] = True
        pending = bytearray(body)
        buf = bytearray()
        drained = 0
        drain_capped = False
        incomplete = False
        t0 = _time.time()
        try:
            conn.settimeout(0.35)
        except Exception:
            pass

        def _pull(n):
            nonlocal pending, incomplete
            while len(pending) < n:
                if (_time.time() - t0) >= chunked_idle_timeout:
                    incomplete = True
                    return False
                try:
                    chunk = conn.recv(min(4096, max(1, n - len(pending))))
                except (socket.timeout, OSError):
                    incomplete = True
                    return False
                if not chunk:
                    incomplete = True
                    return False
                pending.extend(chunk)
            return True

        while len(buf) < body_cap:
            while b"\r\n" not in pending:
                if not _pull(len(pending) + 1):
                    break
            if b"\r\n" not in pending:
                break
            line, pending = pending.split(b"\r\n", 1)
            line = line.strip()
            if b";" in line:
                line = line.split(b";", 1)[0]
            try:
                size = int(line or b"0", 16)
            except ValueError:
                incomplete = True
                break
            if size == 0:
                _pull(2)
                if pending.startswith(b"\r\n"):
                    pending = pending[2:]
                break
            need = size + 2
            if not _pull(need):
                take = bytes(pending)
                pending.clear()
                room = max(0, body_cap - len(buf))
                buf.extend(take[:room])
                drained += max(0, len(take) - room)
                break
            chunk_data = bytes(pending[:size])
            pending = pending[need:]
            room = max(0, body_cap - len(buf))
            buf.extend(chunk_data[:room])
            drained += max(0, len(chunk_data) - room)
            if drained >= drain_byte_cap or (_time.time() - t0) >= drain_time_cap:
                drain_capped = True
                break
        if incomplete:
            meta["worker_hold"] = True
            meta["worker_hold_reason"] = "chunked_idle_timeout"
        return head, bytes(buf[:body_cap]), 0, drained, drain_capped, meta

    if declared == 0:
        return head, bytes(body[:body_cap]), 0, 0, False, meta
    want = min(declared, body_cap)
    body = bytearray(body)
    try:
        conn.settimeout(0.35)
    except Exception:
        pass
    incomplete = False
    while len(body) < want:
        try:
            chunk = conn.recv(min(4096, want - len(body)))
        except (socket.timeout, OSError):
            incomplete = True
            break
        if not chunk:
            incomplete = True
            break
        body.extend(chunk)
    prefix = bytes(body[:body_cap])
    drained = 0
    drain_capped = False
    remaining = max(0, declared - len(prefix))
    if remaining > 0:
        t0 = _time.time()
        try:
            conn.settimeout(0.25)
        except Exception:
            pass
        to_drain = min(remaining, drain_byte_cap)
        while drained < to_drain:
            if (_time.time() - t0) >= drain_time_cap:
                drain_capped = True
                incomplete = True
                break
            try:
                chunk = conn.recv(min(65536, to_drain - drained))
            except (socket.timeout, OSError):
                drain_capped = True
                incomplete = True
                break
            if not chunk:
                incomplete = True
                break
            drained += len(chunk)
        if remaining > drain_byte_cap:
            drain_capped = True
    if incomplete and (declared > len(prefix) + drained):
        meta["worker_hold"] = True
        meta["worker_hold_reason"] = "post_idle_timeout"
    return head, prefix, declared, drained, drain_capped, meta



def _client_looks_like_http(conn):
    ready, _write, _err = select.select([conn], [], [], HTTP_GLANCE)
    if not ready:
        return False
    try:
        peeked = conn.recv(8, socket.MSG_PEEK)
    except OSError:
        return False
    return _looks_like_http(peeked)


def _read_prelude(conn):
    conn.settimeout(PRELUDE_WAIT)
    buf = bytearray()
    try:
        while len(buf) < 512:
            try:
                chunk = conn.recv(256)
            except socket.timeout:
                break
            if not chunk:
                break
            buf.extend(chunk)
            if b"\n" in buf:
                break
            if buf and not (b"SSH-".startswith(bytes(buf)) or buf.startswith(b"SSH-")):
                break
    finally:
        conn.settimeout(SESSION_IDLE)
    return bytes(buf)


def _form_user_pass(posted):
    user = pw = None
    for pair in posted.split("&"):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        key = urllib.parse.unquote_plus(key).lower()
        value = urllib.parse.unquote_plus(value)
        if "user" in key and user is None:
            user = value
        if "pass" in key and pw is None:
            pw = value
    return user, pw


def _form_has_login(posted):
    user, pw = _form_user_pass(posted)
    return bool(user or pw)


def _looks_like_http(data):
    return data[:8].split(b" ", 1)[0] in (b"GET", b"POST", b"HEAD", b"PUT",
                                          b"OPTIONS", b"DELETE")


def _resolve(cwd, arg):
    if arg.startswith("/"):
        path = arg
    else:
        path = cwd.rstrip("/") + "/" + arg
    parts = []
    for piece in path.split("/"):
        if piece in ("", "."):
            continue
        if piece == "..":
            if parts:
                parts.pop()
            continue
        parts.append(piece)
    return "/" + "/".join(parts)


def _short(path, username="deploy"):
    home = "/home/%s" % (username if username in ("deploy", "admin") else "deploy")
    if path == home:
        return "~"
    if path.startswith(home + "/"):
        return "~" + path[len(home):]
    return path


def _resolve_share_path(rel, files, shares):
    """Map a /files/... URL path onto a bait filesystem path.

    Only paths under /srv/shares/<share>/ are served. Never /etc, /root, or
    arbitrary bait files outside the share tree — that was a fingerprint and a
    story break (File Station does not export /etc/passwd).
    """
    rel = urllib.parse.unquote(rel).lstrip("/")
    if not rel or ".." in rel.split("/"):
        return ""
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return ""
    share = parts[0]
    if share not in shares:
        return ""
    candidate = "/srv/shares/" + "/".join(parts)
    if candidate in files:
        return candidate
    # Allow bare leaf within that share only.
    if len(parts) == 2:
        leaf = parts[1]
        for row in shares[share]:
            if row["name"] == leaf:
                return row["path"]
    return ""


def _status_json(world, ports):
    shares = world.get("shares") or {}
    boot = world.get("boot_time") or (time.time() - 47 * 86400)
    uptime_days = int(max(0, (time.time() - boot) // 86400))
    payload = {
        "hostname": world["hostname"],
        "fqdn": world.get("fqdn"),
        "company": world.get("company"),
        "model": world.get("nas_model") or "DS420j",
        "firmware": world.get("nas_firmware") or "5.0.1.2376",
        "ip": world.get("internal_ip") or "10.0.0.21",
        "uptime_days": uptime_days,
        "shares_ok": True,
        "shares": sorted(shares.keys()),
        "services": {
            "nginx": "active",
            "sshd": "active",
            "postfix": "active",
            "vsftpd": "active",
            "php-fpm": "active",
        },
        # Advertise the real service ports a NAS would show, not the high-port
        # classroom remaps the sensor may be listening on.
        "listen_ports": [22, 80, 443, 25, 21],
    }
    return json.dumps(payload, indent=2) + "\n"


def _host_of(console):
    if not console:
        return ""
    host = console
    for prefix in ("http://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    return host.rstrip("/")


def _fake_processes():
    return (
        "  PID TTY          TIME CMD\n"
        "    1 ?        00:00:02 systemd\n"
        "  512 ?        00:00:01 sshd\n"
        " 1042 ?        00:00:03 nginx\n"
        " 1043 ?        00:00:00 nginx\n"
        " 1088 ?        00:04:17 puma\n"
        " 1129 ?        00:00:41 postgres\n"
        " 1201 ?        00:00:12 postfix\n"
        " 1210 ?        00:00:02 qmgr\n"
        " 1304 ?        00:00:01 vsftpd\n"
        " 2231 pts/0    00:00:00 bash\n"
        " 2240 pts/0    00:00:00 ps")


def _fake_netstat(ports=None):
    ports = ports or DEFAULT_PORTS
    lines = [
        "Active Internet connections (only servers)",
        "Proto Local Address           Foreign Address         State",
        "tcp   0.0.0.0:22              0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:80              0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:25              0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:21              0.0.0.0:*               LISTEN",
        "tcp   127.0.0.1:5432         0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:443            0.0.0.0:*               LISTEN",
    ]
    for p in ports:
        if p not in (22, 80, 25, 21, 443):
            lines.append("tcp   0.0.0.0:%-5d          0.0.0.0:*               LISTEN" % p)
    return "\n".join(lines)


def _fake_ifconfig():
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.0.21  netmask 255.255.255.0  broadcast 10.0.0.255\n"
        "        ether 06:3a:1f:9c:2d:88  txqueuelen 1000  (Ethernet)\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0")


def _fake_df():
    return (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/root        79G   48G   28G  64% /\n"
        "tmpfs           1.9G     0  1.9G   0% /dev/shm\n"
        "/dev/xvda15     105M  6.1M   99M   6% /boot/efi")


def _fake_free():
    return (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:         3923056      812440     1240880        2144     1869736     2861124\n"
        "Swap:              0           0           0")


def _fake_last():
    return (
        "deploy   pts/0        10.0.0.14        %s - %s  (01:02)\n"
        "deploy   pts/0        10.0.0.14        %s - %s  (00:18)\n"
        "reboot   system boot  5.15.0-101-gener %s   still running\n"
        % (time.strftime("%a %b %e %H:%M"), time.strftime("%H:%M"),
           time.strftime("%a %b %e %H:%M", time.localtime(time.time() - 86400)),
           time.strftime("%H:%M", time.localtime(time.time() - 86400 + 1080)),
           time.strftime("%a %b %e %H:%M", time.localtime(time.time() - 47 * 86400)))
    )


def _fake_env(world):
    return (
        "SHELL=/bin/bash\n"
        "PWD=/home/deploy\n"
        "LOGNAME=deploy\n"
        "HOME=/home/deploy\n"
        "USER=deploy\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "LANG=en_US.UTF-8\n"
        "HOSTNAME=%s\n"
        % world["hostname"]
    )




_SERVER_FULL = phpapp.APACHE_SERVER  # Sunday cover: Apache/PHP on Ubuntu EC2
_SERVER_NGINX_LEGACY = "nginx/1.18.0 (Ubuntu)"  # kept for optional DSM mode


def _plain_server_payload(payload):
    """server_tokens off: nginx error bodies say just 'nginx'."""
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload).replace(
            b"<center>nginx/1.18.0 (Ubuntu)</center>", b"<center>nginx</center>")
    return payload


def _http_response(code, ctype, payload, head_only=False, extra="",
                   server=_SERVER_FULL):
    statuses = {
        200: "200 OK", 204: "204 No Content", 302: "302 Found",
        400: "400 Bad Request", 401: "401 Unauthorized", 403: "403 Forbidden",
        404: "404 Not Found",
        405: "405 Method Not Allowed",
        414: "414 Request-URI Too Large",
        500: "500 Internal Server Error",
    }
    status = statuses.get(code, "%d" % code)
    date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    headers = ("HTTP/1.1 %s\r\n"
               "Server: %s\r\n"
               "Date: %s\r\n"
               "Content-Type: %s\r\n"
               "Content-Length: %d\r\n"
               "Connection: close\r\n"
               "%s\r\n" % (status, server, date, ctype, len(payload), extra))
    if head_only:
        return headers.encode("ascii", "replace")
    return headers.encode("ascii", "replace") + payload


def _apache_error(code, reason):
    return phpapp.apache_error(code, reason)


def _nginx_error(code, reason):
    body = (
        "<html>\r\n<head><title>%d %s</title></head>\r\n"
        "<body>\r\n<center><h1>%d %s</h1></center>\r\n"
        "<hr><center>nginx/1.18.0 (Ubuntu)</center>\r\n"
        "</body>\r\n</html>\r\n" % (code, reason, code, reason)
    )
    return body.encode("ascii")


def _tag_http_exploit(session, path, body):
    """Tag real exploitation shapes as T1190 instead of generic recon."""
    text = ("%s %s" % (path or "", body or "")).lower()
    markers = (
        ("${jndi:", "log4j JNDI"),
        ("../", "path traversal"),
        ("..%2f", "path traversal"),
        ("/etc/passwd", "path traversal"),
        ("/.env", "dotenv probe"),
        ("/wp-login.php", "wordpress probe"),
        ("/cgi-bin/", "cgi probe"),
        ("() {", "shellshock"),
        ("/vendor/phpunit", "phpunit rce probe"),
        ("/actuator", "spring actuator probe"),
    )
    for needle, label in markers:
        if needle in text:
            session.setdefault("events", []).append(
                _event("http-exploit", "%s (%s)" % (label, (path or "")[:80])))
            return

def _login_page(world, failed=False):
    company = world.get("company") or "Example Clinic"
    model = world.get("nas_model") or "DS420j"
    firmware = world.get("nas_firmware") or "5.0.1.2376"
    host = world.get("hostname") or "srv-files"
    brand = "%s NAS" % (company.split()[0] if company else "File")
    error = ""
    if failed:
        error = "<p class=err>The username or password was not recognised.</p>"
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>%s</title><style>"
        "body{margin:0;background:#e6e6e6;font-family:Verdana,sans-serif;color:#222}"
        ".top{background:#4a4a4a;color:#fff;padding:14px 22px}"
        ".top b{font-size:18px}.top span{float:right;font-size:12px;color:#ccc;padding-top:4px}"
        ".card{width:360px;margin:48px auto;background:#fff;border:1px solid #c8c8c8}"
        ".card h1{font-size:15px;font-weight:normal;margin:0;padding:12px 16px;"
        "background:#f3f3f3;border-bottom:1px solid #ddd}"
        "form{padding:8px 16px 18px}label{display:block;font-size:12px;margin:12px 0 4px}"
        "input{width:100%%;padding:7px;box-sizing:border-box;border:1px solid #bbb}"
        "button{margin-top:16px;background:#5c6b73;color:#fff;border:0;padding:8px 18px}"
        ".err{color:#8a2a2a;font-size:12px;padding:10px 16px 0}"
        ".foot{text-align:center;color:#888;font-size:11px}"
        "</style></head><body>"
        "<div class=top><b>%s</b><span>%s &nbsp; firmware %s &nbsp; %s</span></div>"
        "<div class=card><h1>Sign in</h1>"
        "%s"
        "<form method=post action=/>"
        "<label>Username</label><input name=username autocomplete=username autofocus>"
        "<label>Password</label><input name=password type=password autocomplete=current-password>"
        "<button type=submit>Log in</button></form></div>"
        "<p class=foot>%s &middot; internal storage on %s</p>"
        "</body></html>"
    ) % (brand, brand, model, firmware, host, error, company, host)


def _not_found_page(world):
    return (
        "<!doctype html><html><head><meta charset=utf-8><title>Not found</title></head>"
        "<body style='font-family:Verdana,sans-serif;padding:24px'>"
        "<h1 style='font-size:16px'>File not found</h1>"
        "<p><a href='/files/'>Back to File Station</a></p></body></html>"
    )


def _guestbook_form(signed=False):
    thanks = ""
    if signed:
        thanks = "<p style='color:#2a6a2a;font-size:13px'>Signed. Thanks for stopping by.</p>"
    return (
        "<div style='background:#fff;border:1px solid #ccc;padding:12px 16px;margin:16px 0'>"
        "<b style='font-size:13px'>Guestbook</b>"
        "<p class=meta>Found what you were looking for? Leave an &lsquo;I was here&rsquo; "
        "for the next visitor (IT share &rsaquo; guestbook.txt).</p>"
        + thanks +
        "<form method=post action=/guestbook>"
        "<input name=note maxlength=500 style='width:70%;padding:6px;border:1px solid #bbb'> "
        "<button type=submit style='background:#5c6b73;color:#fff;border:0;padding:7px 14px'>"
        "Sign</button></form></div>"
    )


def _dashboard_page(world, guestbook_form=False, signed=False):
    company = world.get("company") or "Example Clinic"
    host = world.get("hostname") or "srv-files"
    model = world.get("nas_model") or "DS420j"
    firmware = world.get("nas_firmware") or "5.0.1.2376"
    shares = world.get("shares") or {}
    sections = []
    for share in sorted(shares.keys()):
        rows = []
        for row in shares[share]:
            href = "/files/%s/%s" % (share, row["name"])
            rows.append(
                "<tr><td><a href='%s'>%s</a></td><td>%s</td><td>%d B</td></tr>"
                % (href, row["name"], row["path"], row["size"])
            )
        sections.append(
            "<h2 style='font-size:14px;font-weight:normal;margin:22px 0 8px'>"
            "Share: <b>%s</b></h2>"
            "<table><tr><th>Name</th><th>Path</th><th>Size</th></tr>%s</table>"
            % (share, "".join(rows))
        )
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>File Station — %s</title>"
        "<style>body{margin:0;background:#e6e6e6;font-family:Verdana,sans-serif;color:#222}"
        ".top{background:#4a4a4a;color:#fff;padding:14px 22px}.top b{font-size:18px}"
        ".top span{float:right;font-size:12px;color:#ccc;padding-top:4px}"
        ".wrap{margin:24px}table{background:#fff;border-collapse:collapse;width:100%%;"
        "border:1px solid #ccc}td,th{text-align:left;padding:8px 10px;border-bottom:1px solid #eee;"
        "font-size:13px}th{background:#f3f3f3;font-weight:normal}"
        "a{color:#1a4f72;text-decoration:none}"
        ".meta{color:#555;font-size:13px}</style></head><body>"
        "<div class=top><b>%s NAS</b><span>%s &nbsp; firmware %s &nbsp; %s</span></div>"
        "<div class=wrap><h1 style='font-size:16px;font-weight:normal'>File Station</h1>"
        "<p class=meta>%s shared folders on <code>%s</code>. "
        "Health: <a href='/api/status'>/api/status</a>. Handle exports with care.</p>"
        "%s%s</div></body></html>"
    ) % (host, company, model, firmware, host, company, host,
         _guestbook_form(signed) if guestbook_form else "", "".join(sections))
