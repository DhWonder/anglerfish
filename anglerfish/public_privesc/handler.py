"""Local request handler for public→privesc bait chain.

Hard stops: no real RCE, no outbound, bait bytes from bait/ store only,
allowlisted shell stubs. php2shell parallel path is NOT modified here.
"""

from __future__ import annotations

import base64
import html
import re
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import auth, paths, shell_stubs, tags
from .creds import BACKUP_PASS, BACKUP_USER, COMPANY, WEAK_PASS, WEAK_USER

# Bait layout: next to this package when embedded in the sensor
# (anglerfish/public_privesc/bait/), else pack-root/bait/ for standalone smoke.
_PKG = Path(__file__).resolve().parent
if (_PKG / "bait").is_dir():
    ROOT = _PKG
else:
    ROOT = _PKG.parent
BAIT = ROOT / "bait"
STORE = BAIT / "store"
LOOT = BAIT / "loot"
BACKUPS = BAIT / "backups"
UPLOADS_TMP = BAIT / "uploads" / "tmp"

APACHE = {
    "Server": "Apache/2.4.58 (Ubuntu)",
    "X-Powered-By": "PHP/8.4.26",
}


def _events() -> List[Dict[str, Any]]:
    if not hasattr(_events, "buf"):
        _events.buf = []  # type: ignore[attr-defined]
    return _events.buf  # type: ignore[attr-defined]


def drain_events() -> List[Dict[str, Any]]:
    buf = _events()
    out = list(buf)
    buf.clear()
    return out


def log_event(kind: str, path: str, tag: str = "", **extra: Any) -> None:
    ev = {"kind": kind, "path": path, "tag": tag}
    ev.update(extra)
    _events().append(ev)


def _clinic_shell(title: str, body: str) -> bytes:
    page = (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>%s — %s</title>"
        "<style>"
        "body{font:15px/1.45 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#222}"
        "header,footer{background:#1e3a5f;color:#fff;padding:.75rem 1.25rem}"
        "header a,footer a{color:#cde} main{max-width:720px;margin:1.5rem auto;padding:0 1rem}"
        ".card{background:#fff;border:1px solid #d8dde6;border-radius:8px;padding:1rem 1.25rem}"
        "label{display:block;margin:.6rem 0} input{width:100%%;max-width:320px;padding:.4rem}"
        "button{margin-top:.8rem;padding:.45rem 1rem;background:#2a6bb0;color:#fff;border:0;border-radius:4px}"
        ".err{color:#a33}.muted{color:#666;font-size:.92em} pre{background:#111;color:#d8ffd8;"
        "padding:1rem;overflow:auto;border-radius:6px}"
        "nav a{margin-right:1rem}"
        "</style></head><body>"
        "<header><strong>%s</strong>"
        "<nav style='display:inline;margin-left:1.5rem'>"
        "<a href=/>Home</a><a href=/portal/login.php>Staff</a>"
        "</nav></header>"
        "<main>%s</main>"
        "<footer><small>%s outpatient clinic · PHP 8.4.26</small></footer>"
        "</body></html>"
    ) % (html.escape(title), html.escape(COMPANY), html.escape(COMPANY),
         body, html.escape(COMPANY))
    return page.encode("utf-8")


def _login_html(failed: bool = False) -> bytes:
    err = "<p class=err>Invalid username or password.</p>" if failed else ""
    body = (
        "<h1>Staff portal</h1>%s"
        "<form method=post action=/portal/login.php class=card>"
        "<label>Username <input name=username autocomplete=username autofocus></label>"
        "<label>Password <input name=password type=password "
        "autocomplete=current-password></label>"
        "<button type=submit>Sign in</button>"
        "</form>"
        "<p class=muted>Sessions use LFSESSID. Staging accounts only.</p>"
    ) % err
    return _clinic_shell("Staff login", body)


def _dashboard_html(user: str, priv: str) -> bytes:
    body = (
        "<h1>Staff dashboard</h1>"
        "<div class=card>"
        "<p>Signed in as <code>%s</code> · priv <code>%s</code></p>"
        "<p>Internal docs:</p><ul>"
        "<li><a href=/staff/docs/it-handoff.txt>IT handoff (ops)</a></li>"
        "<li><a href=/staff/docs/>docs index</a></li>"
        "</ul>"
        "<p class=muted>Web identity feels like www-data / clinic app user. "
        "No shell on this page.</p>"
        "</div>"
    ) % (html.escape(user), html.escape(priv))
    return _clinic_shell("Dashboard", body)


def _uploads_index() -> bytes:
    # Apache-ish directory listing — scanners love /uploads/ and /uploads/tmp/
    rows = []
    for name, size in (
        ("portal-config.bak", (UPLOADS_TMP / "portal-config.bak").stat().st_size),
        ("staff-portal-backup.zip", (UPLOADS_TMP / "staff-portal-backup.zip").stat().st_size),
    ):
        rows.append(
            "<tr><td><a href='/uploads/tmp/%s'>%s</a></td>"
            "<td align=right>%d</td></tr>" % (name, name, size)
        )
    body = (
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
        "<html><head><title>Index of /uploads/tmp</title></head>\n"
        "<body><h1>Index of /uploads/tmp</h1>\n"
        "<table><tr><th>Name</th><th>Size</th></tr>\n"
        "<tr><td><a href='/uploads/'>Parent Directory</a></td><td></td></tr>\n"
        "%s</table></body></html>\n" % "\n".join(rows)
    )
    return body.encode("utf-8")


def _backups_index() -> bytes:
    z = BACKUPS / "staff-portal-backup.zip"
    body = (
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
        "<html><head><title>Index of /backups</title></head>\n"
        "<body><h1>Index of /backups</h1>\n"
        "<ul><li><a href='/backups/staff-portal-backup.zip'>"
        "staff-portal-backup.zip</a> (%d bytes)</li></ul>\n"
        "</body></html>\n" % z.stat().st_size
    )
    return body.encode("utf-8")




def _git_head() -> bytes:
    return b"ref: refs/heads/staging\n"


def _git_config() -> bytes:
    # Comment points at existing JS lead — no password here
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "[remote \"origin\"]\n"
        "\turl = git@internal:larkfield/clinic-portal-staging.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"staging\"]\n"
        "\tremote = origin\n"
        "\tmerge = refs/heads/staging\n"
        "# staging portal config: /assets/js/portal-config.js\n"
    ).encode("utf-8")


def _server_status_breadcrumb() -> bytes:
    return (
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
        "<html><head><title>Apache Status</title></head>\n"
        "<body>\n"
        "<!-- staging portal: /assets/js/portal-config.js -->\n"
        "<h1>Apache Server Status for ip-10-0-0-21</h1>\n"
        "<dl><dt>Server Version:</dt><dd>Apache/2.4.58 (Ubuntu)</dd>\n"
        "<dt>Current Time:</dt><dd>clinic stub</dd>\n"
        "<dt>Server uptime:</dt><dd>3 days 4 hours</dd></dl>\n"
        "<p>Scoreboard unavailable (clinic stub).</p>\n"
        "<p>See <a href=/assets/js/portal-config.js>"
        "/assets/js/portal-config.js</a> for staging notes.</p>\n"
        "</body></html>\n"
    ).encode("utf-8")


def _actuator_env_breadcrumb() -> bytes:
    # Clinic stub — no real secrets; pointer only
    return (
        "{\n"
        "  \"activeProfiles\": [\"staging\"],\n"
        "  \"propertySources\": [{\n"
        "    \"name\": \"clinic-stub\",\n"
        "    \"properties\": {\n"
        "      \"portal.config\": {\"value\": \"/assets/js/portal-config.js\"},\n"
        "      \"note\": {\"value\": \"staging creds live in portal-config.js\"}\n"
        "    }\n"
        "  }]\n"
        "}\n"
    ).encode("utf-8")


def _wp_login_breadcrumb() -> bytes:
    return (
        "<!DOCTYPE html>\n"
        "<html><head><title>Log In &lsaquo; Example Clinic &mdash; WordPress</title>\n"
        "<!-- staging creds moved to /assets/js/portal-config.js -->\n"
        "</head><body class=login>\n"
        "<h1><a href=/>Example Clinic</a></h1>\n"
        "<form name=loginform action=/wp-login.php method=post>\n"
        "<p><label>Username <input type=text name=log></label></p>\n"
        "<p><label>Password <input type=password name=pwd></label></p>\n"
        "<p><input type=submit name=wp-submit value=\"Log In\"></p>\n"
        "</form>\n"
        "</body></html>\n"
    ).encode("utf-8")


def _pma_docpath_breadcrumb(docpath_logged: str = "") -> bytes:
    """PMA importdocsql probe decoy.

    Hard stop: never open/read docpath (or any FS path from the query).
    Body only breadcrumbs humans to the existing JS lead — same weak login.
    """
    # Reflect nothing from docpath into includes; comment is static.
    _ = docpath_logged  # logged by caller only
    return (
        "<!DOCTYPE html>\n"
        "<html><head><title>phpMyAdmin — import</title></head>\n"
        "<body>\n"
        "<!-- staging creds moved to /assets/js/portal-config.js -->\n"
        "<h1>Import documentation</h1>\n"
        "<p>Documentation path unavailable. See staging portal config.</p>\n"
        "<p class=muted><a href=/assets/js/portal-config.js>"
        "/assets/js/portal-config.js</a></p>\n"
        "</body></html>\n"
    ).encode("utf-8")

def _phpmyadmin_breadcrumb() -> bytes:
    """Scanner decoy: 200 HTML with comment pointing at existing JS lead.

    No new credential. No new hop — same weak login via portal-config.js.
    """
    return (
        "<!DOCTYPE html>\n"
        "<html><head><title>phpMyAdmin</title></head>\n"
        "<body>\n"
        "<!-- staging creds moved to /assets/js/portal-config.js -->\n"
        "<h1>phpMyAdmin</h1>\n"
        "<p>This installation has been moved. Contact IT.</p>\n"
        "</body></html>\n"
    ).encode("utf-8")

def _robots() -> bytes:
    # Scanners still hit Disallow paths; hint without dumping the password
    return (
        "User-agent: *\n"
        "Disallow: /backups/\n"
        "Disallow: /uploads/\n"
        "Disallow: /uploads/tmp/\n"
        "Disallow: /staff/\n"
        "Disallow: /portal/\n"
        "# staging assets under /assets/js/\n"
    ).encode("utf-8")


def _term_html(failed: bool = False, output: str = "",
               escalated: bool = False, escalate_user: str = "") -> bytes:
    """Term form: require backup creds until escalate, then sticky UI.

    After sess.escalated, hide user/pass so empty fields don't look like
    an open shell — show who we escalated as instead.
    """
    err = "<p class=err>auth failed</p>" if failed else ""
    out = ("<pre id=out>%s</pre>" % html.escape(output)) if output else ""
    if escalated:
        who = html.escape(escalate_user or BACKUP_USER)
        auth_block = (
            "<p class=muted>escalated as <code>%s</code> · session sticky</p>"
            % who
        )
    else:
        auth_block = (
            "<label>user <input name=user autocomplete=username></label>"
            "<label>pass <input name=pass type=password "
            "autocomplete=current-password></label>"
        )
    body = (
        "<h1>maintenance term</h1>%s"
        "<form method=post action=/staff/admin/term.php class=card>"
        "%s"
        "<label>cmd <input name=cmd placeholder='ls' autofocus></label>"
        "<button type=submit>run</button>"
        "</form>%s"
    ) % (err, auth_block, out)
    return _clinic_shell("term", body)


def _read_bait(rel: Path) -> Optional[bytes]:
    """Serve only files under bait/. Refuse path escape."""
    try:
        full = rel.resolve()
        if not str(full).startswith(str(BAIT.resolve())):
            return None
        if not full.is_file():
            return None
        return full.read_bytes()
    except OSError:
        return None


def _mime(name: str, data: Optional[bytes] = None) -> str:
    """Content-Type: prefer magic bytes when body is known (juicy loot names)."""
    if data is not None:
        if len(data) >= 8 and data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
            return "image/jpeg"
        if len(data) >= 6 and data[:6] in (b"GIF87a", b"GIF89a"):
            return "image/gif"
    n = name.lower()
    if n.endswith(".png"):
        return "image/png"
    if n.endswith(".jpg") or n.endswith(".jpeg"):
        return "image/jpeg"
    if n.endswith(".gif"):
        return "image/gif"
    if n.endswith(".js"):
        return "application/javascript; charset=utf-8"
    if n.endswith(".zip"):
        return "application/zip"
    if (
        n == "passwords_old.txt"
        or n.endswith(".txt")
        or n.endswith(".bak")
        or n.endswith(".id")
    ):
        return "text/plain; charset=utf-8"
    return "application/octet-stream"


def _parse_form(handler: BaseHTTPRequestHandler) -> Dict[str, str]:
    length = int(handler.headers.get("Content-Length") or 0)
    raw = handler.rfile.read(length) if length > 0 else b""
    # Cap body — never treat as include/exec input beyond form fields
    raw = raw[:65536]
    ctype = handler.headers.get("Content-Type", "")
    out: Dict[str, str] = {}
    if "multipart/form-data" in ctype:
        # Minimal multipart: text fields only; drop file parts (hard stop)
        m = re.search(r"boundary=([^;]+)", ctype, re.I)
        if not m:
            return out
        boundary = m.group(1).strip().strip('"').encode()
        for part in raw.split(b"--" + boundary):
            if b"Content-Disposition" not in part:
                continue
            if b"filename=" in part:
                continue  # never keep upload bodies
            head, _, body = part.partition(b"\r\n\r\n")
            if not body:
                continue
            body = body.rstrip(b"\r\n-")
            nm = re.search(br'name="([^"]+)"', head)
            if nm:
                out[nm.group(1).decode()] = body.decode("utf-8", "replace")
        return out
    # default: urlencoded
    for k, v in urllib.parse.parse_qsl(raw.decode("utf-8", "replace"),
                                       keep_blank_values=True):
        out[k] = v
    return out


def handle(handler: BaseHTTPRequestHandler) -> None:
    parsed = urllib.parse.urlparse(handler.path)
    path = parsed.path or "/"
    method = handler.command.upper()
    qs = urllib.parse.parse_qs(parsed.query)
    cookie = auth.parse_cookie(handler.headers.get("Cookie", ""))
    sess = auth.get_session(cookie)

    def send(code: int, body: bytes, ctype: str = "text/html; charset=utf-8",
             extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
        handler.send_response(code)
        for k, v in APACHE.items():
            handler.send_header(k, v)
        handler.send_header("Content-Type", ctype)
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Connection", "close")
        if extra_headers:
            for k, v in extra_headers:
                handler.send_header(k, v)
        handler.end_headers()
        if method != "HEAD":
            handler.wfile.write(body)

    # --- Beat 1: public leaks (two doors → same weak cred) -----------------
    if path == paths.PUBLIC_ROBOTS:
        log_event("http", path, tag="recon")
        return send(200, _robots(), "text/plain; charset=utf-8")


    if path == paths.PUBLIC_GIT_HEAD:
        log_event("http", path, tag=tags.BAIT_SCANNER_BREADCRUMB, crumb="git-head")
        return send(200, _git_head(), "text/plain; charset=utf-8")

    if path == paths.PUBLIC_GIT_CONFIG:
        log_event("http", path, tag=tags.BAIT_SCANNER_BREADCRUMB, crumb="git-config")
        return send(200, _git_config(), "text/plain; charset=utf-8")

    if path in paths.PUBLIC_SERVER_STATUS:
        log_event("http", path, tag=tags.BAIT_SCANNER_BREADCRUMB, crumb="server-status")
        return send(200, _server_status_breadcrumb())

    if path in paths.PUBLIC_ACTUATOR_ENV:
        log_event("http", path, tag=tags.BAIT_SCANNER_BREADCRUMB, crumb="actuator-env")
        return send(200, _actuator_env_breadcrumb(),
                    "application/json; charset=utf-8")

    if path in paths.PUBLIC_WP_LOGIN:
        log_event("http", path, tag=tags.BAIT_SCANNER_BREADCRUMB, crumb="wp-login")
        return send(200, _wp_login_breadcrumb())

    if path in paths.PUBLIC_PHPMYADMIN_ALT or path == paths.PUBLIC_PHPMYADMIN:
        log_event("http", path, tag=tags.BAIT_SCANNER_BREADCRUMB)
        return send(200, _phpmyadmin_breadcrumb())

    if path in paths.PMA_DOCPATH_PATHS:
        # Observed: ?submit_show=true&do=import&docpath=../
        # NEVER read docpath / NEVER traverse — log capped value only.
        raw_doc = (qs.get("docpath") or [""])[0]
        doc_logged = raw_doc[:80].replace("\x00", "")
        log_event(
            "pma_docpath_probe", path,
            tag=tags.BAIT_PMA_DOCPATH,
            docpath=doc_logged,
            file_read=False, rce=False,
        )
        # Also keep scanner-breadcrumb tag association for humans following comment
        log_event("http", path, tag=tags.BAIT_SCANNER_BREADCRUMB)
        return send(200, _pma_docpath_breadcrumb(doc_logged))



    if path in (paths.PUBLIC_BACKUPS_INDEX, "/backups"):
        log_event("http", path, tag=tags.BAIT_PUBLIC_LEAK)
        return send(200, _backups_index())

    if path == paths.PUBLIC_ZIP:
        data = _read_bait(BACKUPS / "staff-portal-backup.zip")
        log_event("bait_zip_download", path, tag=tags.BAIT_PUBLIC_LEAK,
                  size=len(data or b""))
        if not data:
            return send(404, b"Not Found\n", "text/plain")
        return send(200, data, _mime("x.zip"))

    if path in (paths.PUBLIC_UPLOADS_INDEX, "/uploads/tmp"):
        log_event("http", path, tag=tags.BAIT_PUBLIC_LEAK)
        return send(200, _uploads_index())

    if path == "/uploads/" or path == "/uploads":
        body = (
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
            "<html><head><title>Index of /uploads</title></head>\n"
            "<body><h1>Index of /uploads</h1>\n"
            "<ul><li><a href='/uploads/tmp/'>tmp/</a></li></ul>\n"
            "</body></html>\n"
        ).encode()
        log_event("http", path, tag=tags.BAIT_PUBLIC_LEAK)
        return send(200, body)

    if path == paths.PUBLIC_UPLOADS_BAK:
        data = _read_bait(UPLOADS_TMP / "portal-config.bak")
        log_event("bait_bak_download", path, tag=tags.BAIT_PUBLIC_LEAK)
        return send(200, data or b"", _mime("x.bak"))

    if path == paths.PUBLIC_UPLOADS_ZIP:
        data = _read_bait(UPLOADS_TMP / "staff-portal-backup.zip")
        log_event("bait_zip_download", path, tag=tags.BAIT_PUBLIC_LEAK)
        return send(200, data or b"", _mime("x.zip"))

    if path == paths.PUBLIC_JS:
        data = _read_bait(STORE / "portal-config.js")
        log_event("bait_js_leak", path, tag=tags.BAIT_PUBLIC_LEAK_JS)
        return send(200, data or b"", _mime("x.js"))

    # --- Beat 2: weak login ------------------------------------------------
    if path in paths.LOGIN_PATHS:
        if method == "POST":
            form = _parse_form(handler)
            user = form.get("username") or form.get("user") or ""
            password = form.get("password") or form.get("pass") or ""
            if auth.check_weak(user, password):
                sid = auth.mint_session(priv="www-data", user=WEAK_USER)
                log_event("auth_ok", path, tag=tags.BAIT_WEAK_LOGIN,
                          user=WEAK_USER, priv="www-data")
                # Redirect to dashboard
                body = b""
                return send(
                    302, body, "text/plain",
                    extra_headers=[
                        ("Set-Cookie", auth.set_cookie_header(sid)),
                        ("Location", paths.DASHBOARD),
                    ],
                )
            log_event("auth_fail", path, tag=tags.BAIT_WEAK_LOGIN, user=user[:64])
            return send(401, _login_html(failed=True))
        return send(200, _login_html(failed=False))

    if path == paths.DASHBOARD:
        if not sess:
            return send(302, b"", "text/plain",
                        extra_headers=[("Location", "/portal/login.php")])
        log_event("dashboard", path, tag=tags.BAIT_WEAK_LOGIN,
                  user=sess.get("user"))
        return send(200, _dashboard_html(sess["user"], sess["priv"]))

    if path == "/staff/docs/" or path == "/staff/docs":
        if not sess:
            return send(302, b"", "text/plain",
                        extra_headers=[("Location", "/portal/login.php")])
        body = (
            "<h1>docs</h1><ul>"
            "<li><a href=/staff/docs/it-handoff.txt>it-handoff.txt</a></li>"
            "</ul>"
        )
        return send(200, _clinic_shell("docs", body))

    # --- Beat 3: ONE escalate ----------------------------------------------
    if path == paths.HANDOFF:
        if not sess:
            return send(401, b"auth required\n", "text/plain")
        data = _read_bait(STORE / "it-handoff.txt")
        log_event("privesc_bait_read", path, tag=tags.BAIT_PRIVESC,
                  user=sess.get("user"))
        return send(200, data or b"", _mime("x.txt"))

    if path == paths.DEPLOY_ID:
        if not sess:
            return send(401, b"auth required\n", "text/plain")
        data = _read_bait(STORE / ".deploy_id")
        log_event("privesc_bait_read", path, tag=tags.BAIT_PRIVESC)
        return send(200, data or b"", _mime("x.id"))

    if path == paths.TERM:
        if not sess:
            return send(401, _term_html(failed=True, escalated=False), "text/html; charset=utf-8")
        if method == "POST":
            form = _parse_form(handler)
            user = form.get("user") or form.get("username") or ""
            password = form.get("pass") or form.get("password") or ""
            cmd = form.get("cmd") or form.get("c") or form.get("command") or ""
            # Also allow cmd via query for kits that POST body differently
            if not cmd and "cmd" in qs:
                cmd = qs["cmd"][0]
            if not auth.check_backup(user, password) and not sess.get("escalated"):
                log_event("auth_fail", path, tag=tags.BAIT_PRIVESC, user=user[:64])
                return send(401, _term_html(failed=True, escalated=False))
            if auth.check_backup(user, password):
                auth.mark_escalated(cookie or "")
                sess = auth.get_session(cookie) or sess
            out, extras = shell_stubs.run_stub(cmd, escalated=True)
            loot_name = extras.get("loot_request")
            if loot_name and loot_name in paths.GOTCHA_NAMES:
                data = _read_bait(LOOT / loot_name)
                if data is not None:
                    as_b64 = bool(extras.get("loot_as_base64"))
                    log_event("gotcha", path, tag=tags.BAIT_GOTCHA,
                              file=loot_name,
                              via="term_base64" if as_b64 else "term_cat")
                    if as_b64:
                        # base64(1)-style text, not image/* — Red soft fix
                        text = base64.b64encode(data).decode("ascii") + "\n"
                        return send(200, text.encode("ascii"),
                                    "text/plain; charset=utf-8")
                    return send(200, data, _mime(loot_name, data))
            safe_ex = {k: v for k, v in extras.items()
                       if k not in ("loot_request", "tag")}
            log_event("fake_shell", path, tag=tags.BAIT_PRIVESC,
                      cmd=cmd[:120], **safe_ex)
            return send(200, _term_html(output=out or "(ok)\n",
                              escalated=True,
                              escalate_user=(sess or {}).get("user") or BACKUP_USER))
        # GET with ?cmd= after escalate cookie
        cmd = (qs.get("cmd") or qs.get("c") or [""])[0]
        if cmd and sess.get("escalated"):
            out, extras = shell_stubs.run_stub(cmd, escalated=True)
            loot_name = extras.get("loot_request")
            if loot_name and loot_name in paths.GOTCHA_NAMES:
                data = _read_bait(LOOT / loot_name)
                if data is not None:
                    as_b64 = bool(extras.get("loot_as_base64"))
                    log_event("gotcha", path, tag=tags.BAIT_GOTCHA, file=loot_name,
                              via="term_base64" if as_b64 else "term_cat")
                    if as_b64:
                        text = base64.b64encode(data).decode("ascii") + "\n"
                        return send(200, text.encode("ascii"),
                                    "text/plain; charset=utf-8")
                    return send(200, data, _mime(loot_name, data))
            return send(200, (out or "").encode("utf-8"), "text/plain; charset=utf-8")
        esc = bool(sess and sess.get("escalated"))
        return send(200, _term_html(
            escalated=esc,
            escalate_user=(sess or {}).get("user") or ""))

    # Gotcha GET /staff/loot/<name> — requires escalate
    if path.startswith(paths.LOOT_PREFIX):
        if not sess or not sess.get("escalated"):
            return send(403, b"forbidden\n", "text/plain")
        name = path[len(paths.LOOT_PREFIX):].lstrip("/")
        if name not in paths.GOTCHA_NAMES:
            return send(404, b"Not Found\n", "text/plain")
        data = _read_bait(LOOT / name)
        if data is None:
            return send(404, b"Not Found\n", "text/plain")
        log_event("gotcha", path, tag=tags.BAIT_GOTCHA, file=name)
        return send(200, data, _mime(name, data))

    if path in ("/", "/index.php", "/index.html"):
        body = (
            "<h1>Welcome</h1>"
            "<p>%s is a small outpatient clinic and billing office.</p>"
            "<p class=muted><a href=/portal/login.php>Staff portal</a></p>"
        ) % html.escape(COMPANY)
        return send(200, _clinic_shell("Home", body))

    # Soft 404
    body = (
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
        "<html><head><title>404 Not Found</title></head><body>\n"
        "<h1>Not Found</h1>\n"
        "<p>The requested URL was not found on this server.</p>\n"
        "</body></html>\n"
    ).encode()
    log_event("http_404", path)
    return send(404, body)


class PrivescHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Quiet; events go through log_event
        return

    def do_GET(self) -> None:
        handle(self)

    def do_HEAD(self) -> None:
        handle(self)

    def do_POST(self) -> None:
        handle(self)
