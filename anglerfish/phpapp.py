"""
Clinic Apache/PHP cover surfaces + PHP2Shell lure (Sunday overhaul).

Option 3 (2026-10-23): drop bare-metal Synology NAS cover (NAS on an AWS IP
is a tell). Present as a small clinic site on a misconfigured Ubuntu EC2
Apache/PHP 8.4.26 host that fits the IP story.

Safety: never executes attacker input, never fetches payload URLs, never
buffers multi-megabyte bodies. Multipart POSTs are accepted so scanners see
a PHP upload surface; we log headers + a size-capped body prefix only.
"""

from __future__ import print_function

import os
import re
import urllib.parse

try:
    from . import php2shell_chain as _p2s_chain
except Exception:  # pragma: no cover
    _p2s_chain = None

try:
    from .public_privesc import sensor_adapter as _public_privesc
except Exception:  # pragma: no cover
    _public_privesc = None

# Fingerprints that fit an Ubuntu 22.04/24.04 EC2 LAMP box (not a NAS).
APACHE_SERVER = "Apache/2.4.58 (Ubuntu)"
PHP_VERSION = "8.4.26"
X_POWERED_BY = "PHP/%s" % PHP_VERSION

# Body prefix kept for logging / indicator checks. Declared Content-Length may
# be enormous (PHP2Shell kits claim ~140MB); we never allocate that.
BODY_PREFIX_CAP = 256 * 1024  # research inspect cap; sample persist ≤64KiB
# PHPSESSID longer than this is a PHP2Shell / session-upload-progress tell.
PHPSESSID_OVERSIZE = 128

# Paths that look like a careless PHP app (soft-fail / decoy only).
PHP_LOGIN = "/login.php"
PHP_UPLOAD = "/upload.php"
PHP_INFO = "/phpinfo.php"
PHP_ENV = "/.env"
PHP_WP_CONFIG = "/wp-config.php"
PHP_WP_CONFIG_BAK = "/wp-config.php.bak"
PHP_ADMINER = "/adminer.php"
PHP_CONTACT = "/contact.php"

PAGE_ASSETS = frozenset({
    "/assets/app.js",
    "/assets/app.css",
    "/favicon.ico",
})

CONTACT_PATHS = frozenset({"/contact", "/contact.php", "/contact/"})


def apache_headers(extra=None):
    """Extra response headers for PHP surfaces (list of 'Name: value\\r\\n')."""
    headers = [
        "X-Powered-By: %s\r\n" % X_POWERED_BY,
    ]
    if extra:
        headers.extend(extra)
    return headers


def apache_error(code, reason, host=None):
    """Stock Apache 2.4 Ubuntu error page body (bytes).

    Host in <address> matches clinic phpinfo System hostname so recon
    fingerprints stay consistent (not 'localhost').
    """
    host = host or "ip-10-0-0-21"
    if code == 404:
        body = (
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>%d %s</title>\n"
            "</head><body>\n"
            "<h1>%s</h1>\n"
            "<p>The requested URL was not found on this server.</p>\n"
            "<hr>\n"
            "<address>%s Server at %s Port 80</address>\n"
            "</body></html>\n" % (code, reason, reason, APACHE_SERVER, host)
        )
    else:
        body = (
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>%d %s</title>\n"
            "</head><body>\n"
            "<h1>%s</h1>\n"
            "<p>%s</p>\n"
            "<hr>\n"
            "<address>%s Server at %s Port 80</address>\n"
            "</body></html>\n" % (
                code, reason, reason, reason, APACHE_SERVER, host)
        )
    return body.encode("ascii", "replace")


def default_server_html():
    """Apache Ubuntu default page (Welcome) — used only at / on unknown Host."""
    return (
        "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" "
        "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
        "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
        "<head><title>Apache2 Ubuntu Default Page: It works</title>\n"
        "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n"
        "</head><body>\n"
        "<h1>It works!</h1>\n"
        "<p>This is the default welcome page used to test the correct "
        "operation of the Apache2 server after installation on Ubuntu systems.</p>\n"
        "<hr />\n"
        "<address>%s</address>\n"
        "</body></html>\n" % APACHE_SERVER
    )


def is_page_asset(path, method="GET"):
    """True for static assets that must not trip high-signal alarms."""
    if method not in ("GET", "HEAD"):
        return False
    clean = (path or "/").split("?", 1)[0]
    if clean in PAGE_ASSETS:
        return True
    if clean.startswith("/assets/"):
        return True
    return False


# Declared size at/above this + progress → prefer canned OOM-500 shape (S4).
OOM_SHAPE_CL = 32_000_000
# How many name="t[]" parts in the capped prefix before tagging heap spray.
HEAP_SPRAY_MIN_T = 3

# Unified with php2shell_chain.SHELL_ALLOWLIST (Red): uploads/* only.
# Docroot /shell.php and /.s.php are NOT in the 200 set (drop-probe 404/log).
if _p2s_chain is not None:
    PHP2SHELL_CANARY_PATHS = _p2s_chain.SHELL_ALLOWLIST
else:  # pragma: no cover
    PHP2SHELL_CANARY_PATHS = frozenset({
        "/uploads/shell.php",
        "/uploads/p2s.php",
        "/uploads/sess_canary.php",
        "/uploads/.well-known-up.php",
    })


def inspect_php2shell(headers_text, body_prefix, declared_length=0, cookies=""):
    """
    Flag PHP2Shell / CVE-2026-109618/109619 style probes and stage-tag them.

    Returns dict with hit/reasons/tags plus stage fields for full-chain lure.
    Never fetches anything. body_prefix is already size-capped by the caller.
    Never executes progress names or multipart values.
    """
    reasons = []
    tags = []
    stages = []
    text = ""
    if isinstance(body_prefix, (bytes, bytearray)):
        text = bytes(body_prefix).decode("latin-1", "replace")
    else:
        text = body_prefix or ""
    hdr = headers_text or ""
    cookie = cookies or ""
    declared = int(declared_length or 0)

    has_progress = (
        "PHP_SESSION_UPLOAD_PROGRESS" in text
        or "PHP_SESSION_UPLOAD_PROGRESS" in hdr
        or "php_session_upload_progress" in text.lower()
    )
    progress_name = ""
    if has_progress:
        reasons.append("PHP_SESSION_UPLOAD_PROGRESS")
        tags.append("php2shell-upload-progress")
        stages.append("progress_activate")
        mprog = re.search(
            r'(?is)name="PHP_SESSION_UPLOAD_PROGRESS"[^\r\n]*\r\n\r\n([^\r\n]{0,64})',
            text)
        if mprog:
            progress_name = mprog.group(1).strip()[:64]

    sessid = ""
    m = re.search(r"(?i)PHPSESSID=([^;\s]+)", cookie) or re.search(
        r"(?i)PHPSESSID=([^;\s]+)", hdr)
    if m:
        sessid = m.group(1)
    if not sessid:
        m2 = re.search(r'(?i)name="PHPSESSID"[^\r\n]*\r\n\r\n([^\r\n]+)', text)
        if m2:
            sessid = m2.group(1).strip()
    # Cap stored sessid for cookie echo — never treat as code.
    sessid_echo = (sessid[:128] if sessid else "")
    phpsessid_len = len(sessid)
    if phpsessid_len >= PHPSESSID_OVERSIZE:
        reasons.append("oversized_PHPSESSID(%d)" % phpsessid_len)
        tags.append("php2shell-oversized-sessid")
        if "progress_activate" not in stages:
            stages.append("progress_activate")

    multipart = "multipart/form-data" in (hdr.lower())
    huge = declared >= 1_000_000
    if multipart and huge and (has_progress or phpsessid_len >= PHPSESSID_OVERSIZE):
        tags.append("php2shell-probe")
    elif has_progress or phpsessid_len >= PHPSESSID_OVERSIZE:
        tags.append("php2shell-probe")

    # S3: heap-spray style t[] parts visible in the capped prefix.
    t_array_count = len(re.findall(r'(?i)name="t\[\]"', text))
    if t_array_count == 0:
        t_array_count = len(re.findall(r'(?i)name="t\[\d*\]"', text))
    if t_array_count >= HEAP_SPRAY_MIN_T and (has_progress or multipart):
        reasons.append("t_array_parts(%d)" % t_array_count)
        tags.append("php2shell-heap-spray")
        stages.append("heap_spray")

    # S4: second file part / trigger markers.
    file_parts = len(re.findall(r'(?i)filename="[^"]*"', text))
    trigger = False
    if file_parts >= 2 and has_progress:
        trigger = True
    low = text.lower()
    if has_progress and (
            "<?php" in low or "eval(" in low
            or "zif_system" in low or "curl " in low
            or "wget " in low or "|bash" in low):
        trigger = True
    if trigger:
        reasons.append("trigger_indicators")
        tags.append("php2shell-trigger")
        stages.append("trigger")

    # Log download-looking URLs in the prefix but NEVER fetch them.
    urls = re.findall(r"https?://[^\s\"'<>]{8,200}", text)
    if urls and (has_progress or "<?php" in low or "eval(" in low or trigger):
        reasons.append("payload_url_logged_not_fetched")
        tags.append("php2shell-payload-url")
        stages.append("callback_logged_not_fetched")

    response_shape = "soft_fail_200"
    if has_progress and declared >= OOM_SHAPE_CL:
        response_shape = "oom_fatal_500"
        tags.append("php2shell-oom-shape")
        stages.append("oom_producer_shape")
        reasons.append("oom_shape_cl(%d)" % declared)

    seen = set()
    stages_u = []
    for s in stages:
        if s not in seen:
            seen.add(s)
            stages_u.append(s)
    primary = stages_u[-1] if stages_u else ""

    hit = bool(tags)
    return {
        "hit": hit,
        "reasons": reasons,
        "tags": sorted(set(tags)),
        "phpsessid_len": phpsessid_len,
        "phpsessid_echo": sessid_echo,
        "has_upload_progress": has_progress,
        "declared_length": declared,
        "body_prefix_len": len(body_prefix or b""),
        "payload_urls": urls[:5],
        "t_array_count": t_array_count,
        "file_parts": file_parts,
        "progress_name": progress_name,
        "stages": stages_u,
        "stage": primary,
        "response_shape": response_shape,
    }


def php2shell_oom_fatal_html():
    """Canned mod_php-looking OOM fatal — not a real memory exhaustion."""
    if _p2s_chain is not None:
        return _p2s_chain.php2shell_oom_fatal_html()
    return (
        "<br />\n"
        "<b>Fatal error</b>:  Allowed memory size of 134217728 bytes exhausted"
        " (tried to allocate 65536 bytes) in <b>Unknown</b> on line "
        "<b>0</b><br />\n"
    )


def php2shell_canary_stub(hostname=None):
    """Fingerprint-mode canary (flag off). No cmd parse; no maintenance tell."""
    if _p2s_chain is not None:
        return _p2s_chain.s3_shell_stub(None, include_marker=False,
                                        hostname=hostname)
    host = hostname or "ip-10-0-0-21"
    return (
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
        "%s\n"
        "PHP 8.4.26 (cli) (built: Sep 10 2026)\n"
    ) % host


def php2shell_set_cookie(sessid_echo):
    """Safe Set-Cookie value; strips CR/LF/semicolon. Never executes sid."""
    if not sessid_echo:
        return ""
    safe = re.sub(r"[\r\n;]", "", str(sessid_echo))[:128]
    if not safe:
        return ""
    return "PHPSESSID=%s; path=/" % safe


def handle(path, method="GET", body=b"", world=None, failed=False, role="clinic"):
    """
    Return (body, content_type, status, set_cookie, extra_headers) or None.
    """
    world = world or {}
    company = world.get("company") or "Example Clinic"
    domain = world.get("domain") or "example.org"
    clean = (path or "/").split("?", 1)[0]
    method = (method or "GET").upper()
    query = ""
    if path and "?" in path:
        query = path.split("?", 1)[1]

    # Merged Blue+Red full-chain state machine (flag off by default).
    if _p2s_chain is not None and _p2s_chain.fullchain_enabled():
        p2s = (world or {}).get("php2shell") or {}
        if not p2s.get("hit") and method == "POST":
            p2s = inspect_php2shell(
                (world or {}).get("http_headers_prefix")
                or "Content-Type: multipart/form-data\r\n",
                body or b"",
                declared_length=int((world or {}).get("http_declared_length") or 0),
                cookies=(world or {}).get("http_cookie") or "",
            )
        routed = _p2s_chain.route(
            clean, method=method, query=query,
            sessid=(p2s.get("phpsessid_echo") if isinstance(p2s, dict) else "")
            or "",
            body=body or b"", p2s=p2s if isinstance(p2s, dict) else {},
            company=company,
            declared_length=int((world or {}).get("http_declared_length") or 0),
            hostname=(world or {}).get("http_hostname")
            or (world or {}).get("hostname") or None,
            src_ip=(world or {}).get("src_ip") or "",
            ua=(world or {}).get("http_ua") or "",
            apply_s1_delay=bool((world or {}).get("php2shell_apply_delay")),
        )
        if routed is not None:
            # 7-tuple: + research_meta (Red research capture)
            if len(routed) == 7:
                body_out, ctype, status, cookie, shape, stage, research = routed
            else:
                body_out, ctype, status, cookie, shape, stage = routed
                research = {}
            extra = list(apache_headers())
            # Red Delta B: raw sess_* → omit X-Powered-By (bare text/plain vibe)
            omit_xpb = bool((research or {}).get("omit_x_powered_by"))
            if omit_xpb or (
                    shape == "session_blob" and (
                        clean.startswith(("/var/lib/php", "/tmp/sess_"))
                        or (ctype or "").strip() == "text/plain")):
                extra = [h for h in extra if not h.lower().startswith(
                    "x-powered-by:")]
            if cookie:
                extra.append("Set-Cookie: %s\r\n" % cookie)
            if isinstance(world, dict):
                world["php2shell_response_shape"] = shape
                world["php2shell_stage"] = stage
                world["php2shell_research"] = research or {}
            return (body_out, ctype, status, "", extra)

    # Public->privesc bait chain (human path). Parallel to php2shell; bait
    # bytes only from public_privesc/bait/. Hard stops enforced in pack.
    if _public_privesc is not None:
        if isinstance(world, dict):
            world.setdefault("http_cookie", world.get("http_cookie") or "")
        try:
            pp_path = path if (path and "?" in path) else clean
            if query and "?" not in (pp_path or ""):
                pp_path = "%s?%s" % (clean, query)
            routed_pp = _public_privesc.try_handle(
                pp_path, method=method, body=body or b"", world=world,
                cookie=(world or {}).get("http_cookie") or "",
            )
        except Exception:
            routed_pp = None
        if routed_pp is not None:
            return routed_pp

    if clean in ("/favicon.ico",):
        return (b"", "image/x-icon", 204, "", apache_headers())
    if clean in ("/assets/app.css",):
        return (_app_css(), "text/css; charset=utf-8", 200, "", apache_headers())
    if clean in ("/assets/app.js",):
        return (_app_js(), "application/javascript; charset=utf-8", 200, "",
                apache_headers())

    if clean in ("/", "/index.html", "/home") or (
            clean == "/index.php" and method != "POST"):
        return (_clinic_home(company, domain), "text/html; charset=utf-8", 200, "",
                apache_headers())
    if clean in (PHP_LOGIN, "/login", "/admin/login.php"):
        return (_login_page(company, failed=(failed or method == "POST")),
                "text/html; charset=utf-8", 200, "", apache_headers())
    if clean in PHP2SHELL_CANARY_PATHS:
        # Fingerprint-mode canary (fullchain flag off). Never parses cmd/c/+.
        host = (world or {}).get("http_hostname") or (world or {}).get(
            "hostname") or None
        return (php2shell_canary_stub(hostname=host),
                "text/plain; charset=utf-8", 200, "",
                apache_headers())

    # Profile P1: /index.php accepts the same progress/upload POST as /upload.php
    if clean in (PHP_UPLOAD, "/upload", "/admin/upload.php", "/index.php"):
        if method == "POST":
            # Full-chain lure: OOM-500 for huge progress POSTs; else soft-fail 200.
            # Never store attacker bytes. PHPSESSID echo goes in extra_headers only
            # (set_cookie slot stays empty so sensor does not treat it as nas_session).
            declared = int((world or {}).get("http_declared_length") or 0)
            cookies = (world or {}).get("http_cookie") or ""
            hdr = (world or {}).get("http_headers_prefix") or (
                "Content-Type: multipart/form-data\r\n")
            p2s = (world or {}).get("php2shell") or inspect_php2shell(
                hdr, body or b"", declared_length=declared, cookies=cookies)
            extra = list(apache_headers())
            sid_cookie = php2shell_set_cookie(
                p2s.get("phpsessid_echo") or "" if isinstance(p2s, dict) else "")
            if not sid_cookie and cookies:
                # Fall back: echo from Cookie header via inspect.
                p2s2 = inspect_php2shell(hdr, body or b"", declared_length=declared,
                                         cookies=cookies)
                sid_cookie = php2shell_set_cookie(p2s2.get("phpsessid_echo") or "")
                if not isinstance(p2s, dict) or not p2s.get("hit"):
                    p2s = p2s2
            if sid_cookie:
                extra.append("Set-Cookie: %s\r\n" % sid_cookie)
            shape = (p2s or {}).get("response_shape") if isinstance(p2s, dict) else ""
            # OOM-500: separate flag, default OFF (Red: prefer soft-fail continue).
            # Fullchain sticky-once is handled inside php2shell_chain.route.
            if (shape == "oom_fatal_500"
                    and _p2s_chain is not None
                    and _p2s_chain.oom_shape_enabled()
                    and not _p2s_chain.fullchain_enabled()):
                return (php2shell_oom_fatal_html(), "text/html; charset=utf-8",
                        500, "", extra)
            # Default S1: soft-fail 200; reflect sanitized progress when known.
            prog = ""
            if isinstance(p2s, dict):
                prog = p2s.get("progress_name") or ""
            if prog and _p2s_chain is not None:
                html = _p2s_chain.s1_soft_fail_html(
                    company, prog, (p2s.get("phpsessid_echo") or ""))
                return (html, "text/html; charset=utf-8", 200, "", extra)
            return (_upload_result(company, ok=False),
                    "text/html; charset=utf-8", 200, "", extra)
        return (_upload_page(company), "text/html; charset=utf-8", 200, "",
                apache_headers())
    if clean in (PHP_INFO, "/info.php", "/test.php"):
        return (_fake_phpinfo(domain), "text/html; charset=utf-8", 200, "",
                apache_headers())
    if clean in (PHP_ENV, "/app/.env", "/var/www/html/.env", "/.env.local"):
        return (_leaked_env(world), "text/plain; charset=utf-8", 200, "",
                apache_headers())
    if clean in (PHP_WP_CONFIG, PHP_WP_CONFIG_BAK, "/wordpress/wp-config.php"):
        return (_leaked_wp_config(world), "text/plain; charset=utf-8", 200, "",
                apache_headers())
    if clean in (PHP_ADMINER, "/adminer/index.php"):
        return (_adminer_stub(company), "text/html; charset=utf-8", 200, "",
                apache_headers())
    # Recon survival: WP + phpMyAdmin decoys with real clinic-shaped content
    if clean in ("/wp-login.php", "/wordpress/wp-login.php", "/blog/wp-login.php"):
        return (_wp_login_page(company, domain, failed=(method == "POST")),
                "text/html; charset=utf-8", 200, "", apache_headers())
    if clean in ("/phpmyadmin", "/phpmyadmin/", "/phpmyadmin/index.php",
                 "/pma/", "/pma/index.php", "/mysql/", "/mysql/index.php"):
        return (_phpmyadmin_page(company), "text/html; charset=utf-8", 200, "",
                apache_headers())
    if clean in ("/uploads", "/uploads/"):
        return (_uploads_index(), "text/html; charset=utf-8", 200, "",
                apache_headers())
    if clean in ("/uploads/tmp", "/uploads/tmp/"):
        # Nested writable-looking tmp under uploads
        body = (
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
            "<html><head><title>Index of /uploads/tmp</title></head>\n"
            "<body><h1>Index of /uploads/tmp</h1>\n"
            "<pre>drwxrwxr-x  www-data www-data     .\n"
            "drwxrwxr-x  www-data www-data     ..\n"
            "-rw-rw-r--  www-data www-data  12K phpXXXXXX\n"
            "</pre>\n"
            "<address>%s Server at ip-10-0-0-21 Port 80</address>\n"
            "</body></html>\n" % APACHE_SERVER
        )
        return (body, "text/html; charset=utf-8", 200, "", apache_headers())
    if clean in CONTACT_PATHS:
        if method == "POST":
            return (_contact_thanks(company), "text/html; charset=utf-8", 200, "",
                    apache_headers())
        return (_contact_page(company), "text/html; charset=utf-8", 200, "",
                apache_headers())
    if clean in ("/robots.txt",):
        return (_robots(domain), "text/plain; charset=utf-8", 200, "",
                apache_headers())
    if clean in ("/sitemap.xml",):
        return (_sitemap(domain), "application/xml; charset=utf-8", 200, "",
                apache_headers())

    # Plausible PHP error for unknown .php — not a 404 blank.
    if clean.endswith(".php"):
        return (_php_warning(clean), "text/html; charset=utf-8", 500, "",
                apache_headers())

    return None  # fall through to caller 404


def staff_files_portal(path, method="GET", body=b"", world=None, failed=False):
    """Replacement for DSM on files./bare-IP: boring staff docs PHP login."""
    world = world or {}
    company = world.get("company") or "Example Clinic"
    clean = (path or "/").split("?", 1)[0]
    # Public->privesc paths take priority over the generic staff soft-login.
    if _public_privesc is not None:
        try:
            routed_pp = _public_privesc.try_handle(
                path, method=method, body=body or b"", world=world,
                cookie=(world or {}).get("http_cookie") or "",
            )
        except Exception:
            routed_pp = None
        if routed_pp is not None:
            return routed_pp
    if clean in ("/", "/index.php", "/login.php", "/login"):
        return (_staff_login(company, failed=(method == "POST")),
                "text/html; charset=utf-8", 200, "", apache_headers())
    if clean.endswith(".php") or clean in ("/files", "/files/"):
        return (_staff_login(company, failed=False),
                "text/html; charset=utf-8", 200, "", apache_headers())
    handled = handle(path, method=method, body=body, world=world, failed=failed,
                     role="files")
    return handled


# ----- page builders ---------------------------------------------------------

def _shell(company, title, body_html):
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>%s — %s</title>"
        "<link rel=stylesheet href=/assets/app.css>"
        "<script src=/assets/app.js defer></script>"
        "</head><body>"
        "<header><div class=wrap><strong>%s</strong>"
        "<nav><a href=/>Home</a> <a href=/login.php>Staff</a> "
        "<a href=/contact.php>Contact</a></nav></div></header>"
        "<main class=wrap>%s</main>"
        "<footer class=wrap><small>%s outpatient clinic · "
        "site powered by PHP %s</small></footer>"
        "</body></html>"
    ) % (title, company, company, body_html, company, PHP_VERSION)


def _clinic_home(company, domain):
    body = (
        "<h1>Welcome</h1>"
        "<p>%s is a small outpatient clinic and billing office.</p>"
        "<ul>"
        "<li>Hours: Mon–Fri 8:30–17:00</li>"
        "<li>Phone: (555) 010-0140</li>"
        "<li>Billing: (555) 010-0141</li>"
        "</ul>"
        "<p class=muted>For referring providers use the "
        "<a href=/login.php>staff portal</a>. "
        "Patients: please call; we do not collect PHI through this site.</p>"
        "<p class=muted>IT notes (internal): "
        "<a href=/upload.php>forms dropbox</a> · "
        "<a href=/phpinfo.php>phpinfo</a></p>"
    ) % company
    return _shell(company, "Home", body)


def _login_page(company, failed=False):
    err = ""
    if failed:
        err = "<p class=err>Invalid username or password.</p>"
    body = (
        "<h1>Staff sign-in</h1>%s"
        "<form method=post action=/login.php class=card>"
        "<label>Username <input name=username autocomplete=username autofocus></label>"
        "<label>Password <input name=password type=password "
        "autocomplete=current-password></label>"
        "<button type=submit>Sign in</button>"
        "</form>"
        "<p class=muted>Session cookies use PHPSESSID. Do not share accounts.</p>"
    ) % err
    return _shell(company, "Staff login", body)


def _upload_page(company):
    body = (
        "<h1>Internal forms dropbox</h1>"
        "<p class=muted>For scanning paper intake forms. "
        "PHP upload_max_filesize=128M · post_max_size=140M · "
        "upload_tmp_dir=/tmp · save under <code>/var/www/html/uploads/</code> "
        "(www-data writable).</p>"
        "<form method=post action=/upload.php enctype=multipart/form-data class=card>"
        "<label>Title <input name=title></label>"
        "<label>File <input type=file name=file></label>"
        "<button type=submit>Upload</button>"
        "</form>"
        "<p class=muted>Recent: <a href=/uploads/>/uploads/</a> · "
        "tmp probe <code>/tmp</code> (Apache Alias disabled; use upload form).</p>"
    )
    return _shell(company, "Upload", body)


def _upload_result(company, ok=False):
    msg = ("Upload failed: temporary directory full. Try again later."
           if not ok else "Saved.")
    body = "<h1>Upload</h1><p class=err>%s</p><p><a href=/upload.php>Back</a></p>" % msg
    return _shell(company, "Upload", body)


def _fake_phpinfo(domain):
    # Profile P1 kit-alignment: fuller fake phpinfo so scanners survive
    # mid-recon and continue into exploit stages (not a thin honeypot tell).
    rows = [
        ("System", "Linux ip-10-0-0-21 6.8.0-1017-aws #19-Ubuntu SMP x86_64"),
        ("Build Date", "Sep 10 2026 12:04:11"),
        ("Build System", "Linux"),
        ("Server API", "Apache 2.0 Handler"),
        ("Virtual Directory Support", "disabled"),
        ("Configuration File (php.ini) Path", "/etc/php/8.4/apache2"),
        ("Loaded Configuration File", "/etc/php/8.4/apache2/php.ini"),
        ("Scan this dir for additional .ini files",
         "/etc/php/8.4/apache2/conf.d"),
        ("Additional .ini files parsed",
         "/etc/php/8.4/apache2/conf.d/10-opcache.ini, "
         "/etc/php/8.4/apache2/conf.d/20-mysqli.ini, "
         "/etc/php/8.4/apache2/conf.d/20-curl.ini, "
         "/etc/php/8.4/apache2/conf.d/20-gd.ini, "
         "/etc/php/8.4/apache2/conf.d/20-mbstring.ini"),
        ("PHP API", "20240924"),
        ("PHP Extension", "20240924"),
        ("Zend Extension", "420240924"),
        ("Zend Extension Build", "API420240924,NTS"),
        ("PHP Extension Build", "API20240924,NTS"),
        ("Debug Build", "no"),
        ("Thread Safety", "disabled"),
        ("Zend Signal Handling", "enabled"),
        ("Zend Memory Manager", "enabled"),
        ("Zend Multibyte Support", "provided by mbstring"),
        ("Zend Max Execution Timers", "disabled"),
        ("IPv6 Support", "enabled"),
        ("DTrace Support", "disabled"),
        ("Registered PHP Streams",
         "https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar"),
        ("Registered Stream Socket Transports", "tcp, udp, unix, udg, ssl, tls, tlsv1.0, tlsv1.1, tlsv1.2, tlsv1.3"),
        ("Registered Stream Filters",
         "zlib.*, string.rot13, string.toupper, string.tolower, string.strip_tags, convert.*, consumed, dechunk"),
        ("Architecture", "x86_64"),
        ("Core", ""),
        ("PHP Version", "8.4.26"),
        ("allow_url_fopen", "On"),
        ("allow_url_include", "Off"),
        ("disable_functions",
         "pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,"
         "pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,"
         "pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,"
         "pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,"
         "pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,"
         "pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals"),
        ("disable_classes", "no value"),
        ("display_errors", "Off"),
        ("display_startup_errors", "Off"),
        ("error_reporting", "22527"),
        ("expose_php", "On"),
        ("file_uploads", "On"),
        ("max_execution_time", "30"),
        ("max_file_uploads", "20"),
        ("max_input_time", "60"),
        ("max_input_vars", "1000"),
        ("memory_limit", "128M"),
        ("open_basedir", "no value"),
        ("post_max_size", "140M"),
        ("upload_max_filesize", "128M"),
        ("upload_tmp_dir", "/tmp"),
        ("doc_root", "no value"),
        ("user_dir", "no value"),
        ("DOCUMENT_ROOT", "/var/www/html"),
        ("SCRIPT_FILENAME", "/var/www/html/phpinfo.php"),
        ("SERVER_NAME", domain),
        ("SERVER_SOFTWARE", APACHE_SERVER),
        ("SERVER_ADDR", "10.0.0.21"),
        ("SERVER_PORT", "80"),
        ("REMOTE_ADDR", "127.0.0.1"),
        ("Request Method", "GET"),
        ("session.auto_start", "Off"),
        ("session.cookie_httponly", "1"),
        ("session.cookie_lifetime", "0"),
        ("session.cookie_path", "/"),
        ("session.gc_maxlifetime", "1440"),
        ("session.name", "PHPSESSID"),
        ("session.save_handler", "files"),
        ("session.save_path", "/var/lib/php/sessions"),
        ("session.serialize_handler", "php"),
        ("session.use_cookies", "1"),
        ("session.use_only_cookies", "1"),
        ("session.use_strict_mode", "0"),
        ("session.use_trans_sid", "0"),
        ("session.upload_progress.enabled", "On"),
        ("session.upload_progress.cleanup", "On"),
        ("session.upload_progress.name", "PHP_SESSION_UPLOAD_PROGRESS"),
        ("session.upload_progress.freq", "1%"),
        ("session.upload_progress.min_freq", "1"),
        ("session.upload_progress.prefix", "upload_progress_"),
        ("apache2handler", ""),
        ("Apache Version", APACHE_SERVER),
        ("Apache API Version", "20120211"),
        ("Server Root", "/etc/apache2"),
        ("Loaded Modules",
         "core mod_so mod_watchdog http_core mod_log_config mod_logio "
         "mod_version mod_unixd mod_access_compat mod_alias mod_auth_basic "
         "mod_authn_core mod_authn_file mod_authz_core mod_authz_host "
         "mod_authz_user mod_autoindex mod_deflate mod_dir mod_env "
         "mod_filter mod_mime prefork mod_negotiation mod_php "
         "mod_reqtimeout mod_setenvif mod_status"),
        ("curl", "enabled"),
        ("cURL Information", "8.5.0"),
        ("gd", "enabled"),
        ("GD Support", "enabled"),
        ("libXML", "enabled"),
        ("mbstring", "enabled"),
        ("mysqli", "enabled"),
        ("Client API library version", "mysqlnd 8.4.26"),
        ("openssl", "enabled"),
        ("OpenSSL Library Version", "OpenSSL 3.0.13 30 Jan 2024"),
        ("pdo_mysql", "enabled"),
        ("zlib", "enabled"),
        ("Zend OPcache", "enabled"),
        ("opcache.enable", "On"),
        ("opcache.memory_consumption", "128"),
    ]
    # Extension summary block (scanners often grep for these names)
    ext_names = (
        "Core, ctype, curl, date, dom, fileinfo, filter, gd, hash, iconv, "
        "json, libxml, mbstring, mysqli, mysqlnd, openssl, pcre, PDO, "
        "pdo_mysql, Phar, posix, Reflection, session, SimpleXML, SPL, "
        "standard, tokenizer, xml, xmlreader, xmlwriter, Zend OPcache, zlib"
    )
    rows.append(("Loaded Extensions", ext_names))
    tr = "".join(
        "<tr><td class=e>%s</td><td class=v>%s</td></tr>" % (k, v)
        for k, v in rows)
    return (
        "<!doctype html><html><head><title>phpinfo()</title>"
        "<style>body{background:#fff;color:#000;font-family:sans-serif}"
        "h1{font-size:18px}h2{font-size:16px;background:#999;color:#fff;"
        "padding:4px}table{border-collapse:collapse;width:80%%}"
        "td{border:1px solid #000;padding:4px 8px}.e{background:#ccf;"
        "font-weight:bold}.v{background:#ccc}a{color:#009}</style></head>"
        "<body>"
        "<div class=center><table>"
        "<tr class=h><td><h1 class=p>PHP Version %s</h1></td></tr>"
        "</table></div>"
        "<h2>Configuration</h2>"
        "<table>%s</table>"
        "<h2>PHP Credits</h2>"
        "<p>PHP Group · Zend Technologies · Configuration</p>"
        "</body></html>"
    ) % (PHP_VERSION, tr)


def _leaked_env(world):
    company = world.get("company") or "Example Clinic"
    domain = world.get("domain") or "example.org"
    # Canary-shaped secrets — never real. Tokens.py canaries preferred when present.
    return (
        "# %s clinic app — DO NOT COMMIT\n"
        "APP_ENV=production\n"
        "APP_DEBUG=true\n"
        "APP_URL=https://%s\n"
        "DB_HOST=127.0.0.1\n"
        "DB_DATABASE=larkfield_clinic\n"
        "DB_USERNAME=clinic_app\n"
        "DB_PASSWORD=ChangeMe_ClinicApp_2024!\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFAKEEXAMPLE01\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "AWS_DEFAULT_REGION=us-east-1\n"
        "MAIL_HOST=localhost\n"
        "MAIL_FROM=noreply@%s\n"
        "SESSION_DRIVER=file\n"
        "# canary: open /login.php with deploy / see IT handover note\n"
    ) % (company, domain, domain)


def _leaked_wp_config(world):
    domain = world.get("domain") or "example.org"
    return (
        "<?php\n"
        "// ** MySQL settings - %s ** //\n"
        "define('DB_NAME', 'wordpress_clinic');\n"
        "define('DB_USER', 'wp_clinic');\n"
        "define('DB_PASSWORD', 'WP_Cl1nic_Staging!');\n"
        "define('DB_HOST', '127.0.0.1');\n"
        "define('AUTH_KEY',         'put your unique phrase here');\n"
        "define('SECURE_AUTH_KEY',  'put your unique phrase here');\n"
        "define('LOGGED_IN_KEY',    'put your unique phrase here');\n"
        "define('NONCE_KEY',        'put your unique phrase here');\n"
        "$table_prefix = 'wp_';\n"
        "define('WP_DEBUG', true);\n"
        "define('WP_HOME', 'https://%s');\n"
        "define('WP_SITEURL', 'https://%s');\n"
        "require_once ABSPATH . 'wp-settings.php';\n"
    ) % (domain, domain, domain)


def _adminer_stub(company):
    return _shell(company, "Adminer",
                  "<h1>Adminer 4.8.1</h1>"
                  "<p class=err>Login failed. Too many connections.</p>"
                  "<form method=post class=card>"
                  "<label>System <input value=MySQL disabled></label>"
                  "<label>Server <input name=server value=127.0.0.1></label>"
                  "<label>Username <input name=username></label>"
                  "<label>Password <input name=password type=password></label>"
                  "<button type=submit>Login</button></form>")


def _contact_page(company):
    return _shell(company, "Contact",
                  "<h1>Contact</h1>"
                  "<form method=post action=/contact.php class=card>"
                  "<label>Name <input name=name></label>"
                  "<label>Email <input name=email></label>"
                  "<label>Message <textarea name=message rows=5></textarea></label>"
                  "<button type=submit>Send</button></form>")


def _contact_thanks(company):
    return _shell(company, "Thanks",
                  "<h1>Thanks</h1><p>We received your message. "
                  "Do not include clinical details by email.</p>")


def _staff_login(company, failed=False):
    err = "<p class=err>Invalid username or password.</p>" if failed else ""
    return _shell(company, "Staff files",
                  "<h1>Staff documents</h1>%s"
                  "<p class=muted>Internal only. Use clinic SSO credentials.</p>"
                  "<form method=post action=/login.php class=card>"
                  "<label>Username <input name=username></label>"
                  "<label>Password <input name=password type=password></label>"
                  "<button type=submit>Sign in</button></form>" % err)


def _wp_login_page(company, domain, failed=False):
    """Clinic-shaped WordPress login decoy — scanners should continue, not bounce."""
    err = ""
    if failed:
        err = (
            "<div id=login_error><strong>Error:</strong> The username "
            "<strong>admin</strong> is not registered on this site. "
            "If you are unsure of your username, try your email "
            "address instead.</div>"
        )
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>Log In &lsaquo; %s &mdash; WordPress</title>"
        "<style>"
        "body{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"
        "\"Segoe UI\",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"
        "\"Helvetica Neue\",sans-serif;font-size:14px}"
        "#login{width:320px;padding:8%% 0 0;margin:auto}"
        ".login form{background:#fff;border:1px solid #c3c4c7;padding:26px 24px;"
        "box-shadow:0 1px 3px rgba(0,0,0,.04)}"
        "label{display:block;margin-bottom:3px;font-size:14px}"
        "input[type=text],input[type=password]{width:100%%;padding:8px;"
        "box-sizing:border-box;border:1px solid #8c8f94;margin:0 0 16px}"
        ".button{background:#2271b1;border:1px solid #2271b1;color:#fff;"
        "padding:6px 14px;cursor:pointer;float:right}"
        "#login_error{border-left:4px solid #d63638;padding:12px;margin:0 0 16px;"
        "background:#fff;box-shadow:0 1px 1px rgba(0,0,0,.04)}"
        ".message{border-left:4px solid #72aee6;padding:12px;margin:0 0 16px;"
        "background:#fff}"
        "a{color:#2271b1;text-decoration:none}"
        "</style></head><body class=login>"
        "<div id=login><h1><a href=https://%s/>%s</a></h1>"
        "%s"
        "<form name=loginform method=post action=/wp-login.php>"
        "<p><label>Username or Email Address"
        "<input type=text name=log id=user_login autocomplete=username></label></p>"
        "<p><label>Password"
        "<input type=password name=pwd id=user_pass "
        "autocomplete=current-password></label></p>"
        "<p class=submit><input type=submit name=wp-submit class=button "
        "value=\"Log In\"></p>"
        "</form>"
        "<p id=nav><a href=/wp-login.php?action=lostpassword>"
        "Lost your password?</a></p>"
        "<p id=backtoblog><a href=/>&larr; Go to %s</a></p>"
        "</div></body></html>"
    ) % (company, domain, company, err, company)


def _phpmyadmin_page(company):
    """phpMyAdmin login decoy — real-looking clinic DB admin, not empty 404."""
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>phpMyAdmin</title>"
        "<style>"
        "body{font-family:sans-serif;background:#eee;margin:0}"
        ".header{background:#222;color:#fff;padding:10px 16px}"
        ".box{width:420px;margin:40px auto;background:#fff;border:1px solid #aaa;"
        "padding:20px;border-radius:4px}"
        "label{display:block;margin:10px 0 4px}input{width:100%%;padding:8px;"
        "box-sizing:border-box}"
        "button{margin-top:14px;background:#2c5aa0;color:#fff;border:0;"
        "padding:8px 16px}"
        ".warn{color:#844;font-size:13px;margin-top:12px}"
        "</style></head><body>"
        "<div class=header><b>phpMyAdmin 5.2.1</b> · %s clinic DB</div>"
        "<div class=box>"
        "<h2>Welcome to phpMyAdmin</h2>"
        "<form method=post action=/phpmyadmin/index.php>"
        "<label>Server <input name=pma_servername value=127.0.0.1 readonly></label>"
        "<label>Username <input name=pma_username value=clinic_app "
        "autocomplete=username></label>"
        "<label>Password <input name=pma_password type=password "
        "autocomplete=current-password></label>"
        "<button type=submit>Log in</button>"
        "</form>"
        "<p class=warn>Cannot log in to the MySQL server "
        "(server is running, credentials rejected).</p>"
        "<p style=font-size:12px;color:#666>Default MySQL port 3306 · "
        "database <code>larkfield_clinic</code> · "
        "docroot <code>/var/www/html</code></p>"
        "</div></body></html>"
    ) % company


def _uploads_index():
    """Directory-index lookalike — implies /uploads is writable webroot."""
    return (
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
        "<html>\n<head>\n<title>Index of /uploads</title>\n</head>\n"
        "<body>\n<h1>Index of /uploads</h1>\n"
        "<table>\n"
        "<tr><th valign=top><img src=/icons/blank.gif alt=\"[ICO]\"></th>"
        "<th><a href=\"?C=N;O=D\">Name</a></th>"
        "<th><a href=\"?C=M;O=A\">Last modified</a></th>"
        "<th><a href=\"?C=S;O=A\">Size</a></th>"
        "<th><a href=\"?C=D;O=A\">Description</a></th></tr>\n"
        "<tr><th colspan=5><hr></th></tr>\n"
        "<tr><td valign=top><img src=/icons/back.gif alt=\"[PARENTDIR]\"></td>"
        "<td><a href=/>Parent Directory</a></td>"
        "<td>&nbsp;</td><td align=right>  - </td><td>&nbsp;</td></tr>\n"
        "<tr><td valign=top><img src=/icons/unknown.gif alt=\"[   ]\"></td>"
        "<td><a href=\"intake_2026-10-12.pdf\">intake_2026-10-12.pdf</a></td>"
        "<td align=right>2026-10-12 14:22  </td>"
        "<td align=right>184K</td><td>&nbsp;</td></tr>\n"
        "<tr><td valign=top><img src=/icons/unknown.gif alt=\"[   ]\"></td>"
        "<td><a href=\"referral_scan.bin\">referral_scan.bin</a></td>"
        "<td align=right>2026-10-18 09:01  </td>"
        "<td align=right> 2.1M</td><td>&nbsp;</td></tr>\n"
        "<tr><td valign=top><img src=/icons/folder.gif alt=\"[DIR]\"></td>"
        "<td><a href=\"tmp/\">tmp/</a></td>"
        "<td align=right>2026-10-20 11:40  </td>"
        "<td align=right>  - </td><td>&nbsp;</td></tr>\n"
        "<tr><th colspan=5><hr></th></tr>\n"
        "</table>\n"
        "<address>%s Server at ip-10-0-0-21 Port 80</address>\n"
        "</body></html>\n" % APACHE_SERVER
    )


def _php_warning(path):
    return (
        "<br />\n"
        "<b>Warning</b>:  require(/var/www/html%s): Failed to open stream: "
        "No such file or directory in <b>/var/www/html/index.php</b> "
        "on line <b>14</b><br />\n"
        "<br />\n"
        "<b>Fatal error</b>:  Uncaught Error: Failed opening required "
        "'/var/www/html%s' in /var/www/html/index.php:14\n"
        "Stack trace:\n#0 {main}\n  thrown in "
        "<b>/var/www/html/index.php</b> on line <b>14</b><br />\n"
    ) % (path, path)


def _robots(domain):
    return (
        "User-agent: *\n"
        "Disallow: /login.php\n"
        "Disallow: /upload.php\n"
        "Disallow: /uploads/\n"
        "Disallow: /admin/\n"
        "Disallow: /phpmyadmin/\n"
        "Disallow: /adminer.php\n"
        "Disallow: /wp-login.php\n"
        "Disallow: /wp-admin/\n"
        "Disallow: /.env\n"
        "Disallow: /phpinfo.php\n"
        "Allow: /\n"
        "\nSitemap: https://%s/sitemap.xml\n" % domain
    )


def _sitemap(domain):
    urls = ["/", "/contact.php", "/login.php"]
    items = "".join(
        "<url><loc>https://%s%s</loc></url>\n" % (domain, u) for u in urls)
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
            "%s</urlset>\n" % items)


def _app_css():
    return (
        "body{margin:0;font-family:system-ui,sans-serif;background:#f6f8fb;color:#1a1a1a}"
        "header{background:#0b3d5c;color:#fff;padding:12px 0}header a{color:#cde}"
        ".wrap{max-width:860px;margin:0 auto;padding:12px 16px}nav a{margin-left:12px}"
        "main{background:#fff;border:1px solid #dde;margin:16px auto;padding:20px;"
        "max-width:860px;border-radius:6px}.card label{display:block;margin:10px 0}"
        "input,textarea{width:100%;padding:8px;box-sizing:border-box}"
        "button{background:#0b3d5c;color:#fff;border:0;padding:8px 14px;margin-top:8px}"
        ".err{color:#8a1f1f}.muted{color:#666;font-size:14px}footer{color:#666;font-size:12px}\n"
    )


def _app_js():
    return "/* clinic staff ui */\ndocument.documentElement.classList.add('js');\n"
