"""Sunday cover overhaul: clinic Apache/PHP + PHP2Shell lure + 404 fix.

Run: python3 tests/test_sunday_overhaul.py
Local only — no AWS, no network egress to attacker URLs.
"""
from __future__ import print_function

import json
import os
import socket
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from anglerfish import phpapp
import anglerfish.sensor as sensor_module
from anglerfish.sensor import Sensor, _http_head_and_body

sensor_module.AUTH_FAIL_DELAY = 0.02
sensor_module.AUTH_FAIL_DELAY_MIN = 0.02
sensor_module.AUTH_FAIL_DELAY_MAX = 0.02
sensor_module.AUTH_LOCK_SECONDS = 0.02
sensor_module.STATUS_WRITE_MIN_GAP = 0.0


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_http_sensor():
    port = free_port()
    sensor_module.SERVICE_BY_PORT[port] = "http"
    events = tempfile.mktemp(prefix="af-sun-ev-")
    os.environ["ANGLERFISH_EVENTS_PATH"] = events
    # Ensure DSM stay retired for these tests.
    os.environ.pop("ANGLERFISH_ALLOW_DSM", None)
    sensor = Sensor(
        name="sunday", ports=[port], bind="127.0.0.1",
        persona=False, classroom=True,
        log_path=tempfile.mktemp(prefix="af-sun-log-"),
        state_dir=tempfile.mkdtemp(prefix="af-sun-state-"),
    )
    sensor.start()
    time.sleep(0.15)
    return sensor, port, events


def http_exchange(port, request, timeout=2.0):
    if isinstance(request, str):
        request = request.encode()
    c = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    c.sendall(request)
    c.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = c.recv(8192)
        except Exception:
            break
        if not chunk:
            break
        data += chunk
    c.close()
    return data


def status_line(resp):
    return resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")


def check(name, cond, detail=""):
    print(("OK  " if cond else "FAIL"), name, detail)
    return 0 if cond else 1


def load_events(path):
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


class OneShot(object):
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, n, flags=0):
        if not self.chunks:
            return b""
        return self.chunks.pop(0)


def main():
    failures = 0

    # --- unit: php2shell inspector (never fetches) ---
    hit = phpapp.inspect_php2shell(
        "Content-Type: multipart/form-data\r\n",
        b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        b"http://evil.example/payload.bin\r\n",
        declared_length=140000000,
        cookies="PHPSESSID=" + ("A" * 200),
    )
    failures += check("p2s_hit", hit["hit"])
    failures += check("p2s_progress", hit["has_upload_progress"])
    failures += check("p2s_sessid", hit["phpsessid_len"] >= 128)
    failures += check("p2s_urls_logged", bool(hit["payload_urls"]))
    failures += check("p2s_tag", "php2shell-probe" in hit["tags"])

    # --- unit: body cap never allocates declared size ---
    head = (
        b"POST /upload.php HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: 140000000\r\n"
        b"Content-Type: multipart/form-data; boundary=x\r\n\r\n"
    )
    prefix = b"--x\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nlure\r\n"
    sock = OneShot([prefix + b"X" * 5000])
    h, body, declared, _drained, _dcapped, _meta = _http_head_and_body(sock, head)
    failures += check("body_cap", len(body) <= phpapp.BODY_PREFIX_CAP,
                      "len=%d" % len(body))
    failures += check("declared_kept", declared == 140000000, str(declared))

    sensor, port, events_path = make_http_sensor()
    try:
        # clinic home on bare IP
        r = http_exchange(
            port,
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        failures += check("home_200", status_line(r).startswith("HTTP/1.1 200"),
                          status_line(r))
        failures += check("home_apache", b"Server: Apache/2.4.58 (Ubuntu)" in r)
        failures += check("home_xpb", b"X-Powered-By: PHP/8.4.26" in r)
        failures += check("home_clinic", b"outpatient" in r or b"Staff" in r)

        # unknown path on bare IP -> 404 (clinic/php fallthrough)
        r = http_exchange(
            port,
            b"GET /nmaplowercheck99 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n")
        # clinic role may soft-404 via vhosts or apache
        failures += check(
            "bare_unknown_not_200_welcome",
            not (status_line(r).startswith("HTTP/1.1 200") and b"It works" in r),
            status_line(r))

        # default-server: / -> 200 welcome; random -> 404
        r = http_exchange(
            port,
            b"GET / HTTP/1.1\r\nHost: ec2-1-2-3-4.compute-1.amazonaws.com\r\n"
            b"Connection: close\r\n\r\n")
        failures += check("ds_root_200", status_line(r).startswith("HTTP/1.1 200"),
                          status_line(r))
        failures += check("ds_root_works", b"It works" in r)

        r = http_exchange(
            port,
            b"GET /nmaplowercheck1 HTTP/1.1\r\n"
            b"Host: ec2-1-2-3-4.compute-1.amazonaws.com\r\n"
            b"Connection: close\r\n\r\n")
        failures += check("ds_path_404", status_line(r).startswith("HTTP/1.1 404"),
                          status_line(r))

        r = http_exchange(
            port,
            b"GET /login.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n")
        failures += check("login_php", b"Staff" in r and b"PHPSESSID" in r)

        r = http_exchange(
            port,
            b"GET /phpinfo.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n")
        failures += check("phpinfo", b"8.4.26" in r and
                          b"session.upload_progress" in r)

        r = http_exchange(
            port,
            b"GET /.env HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n")
        failures += check("env_bait", b"DB_PASSWORD" in r and b"AKIA" in r)

        r = http_exchange(
            port,
            b"GET /wp-config.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n")
        failures += check("wpconfig_bait", b"wordpress_clinic" in r)

        # page asset should be tagged php-page-asset (not high-login)
        r = http_exchange(
            port,
            b"GET /assets/app.js HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n")
        failures += check("asset_js", status_line(r).startswith("HTTP/1.1 200"))

        # PHP2Shell multipart POST
        boundary = "----bound"
        body = (
            "--%s\r\n"
            "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n"
            "\r\nlure\r\n"
            "--%s--\r\n" % (boundary, boundary)
        ).encode()
        req = (
            "POST /upload.php HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "Cookie: PHPSESSID=%s\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n" % (boundary, "B" * 200, len(body))
        ).encode() + body
        r = http_exchange(port, req)
        failures += check("p2s_upload_resp", status_line(r).startswith("HTTP/1.1 200"),
                          status_line(r))

        # Synology should NOT appear on bare IP after retirement
        r = http_exchange(
            port,
            b"GET /webman/login.cgi HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n")
        failures += check("no_synology_brand",
                          b"Synology" not in r and b"DiskStation" not in r,
                          status_line(r))

        # huge declared Content-Length must return quickly
        t0 = time.time()
        r = http_exchange(
            port,
            b"POST /upload.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Type: multipart/form-data; boundary=x\r\n"
            b"Cookie: PHPSESSID=" + b"Z" * 180 + b"\r\n"
            b"Content-Length: 140000000\r\nConnection: close\r\n\r\n"
            b"--x\r\nContent-Disposition: form-data; "
            b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nlure\r\n",
            timeout=2.5,
        )
        elapsed = time.time() - t0
        failures += check("huge_no_hang", elapsed < 2.5 and r,
                          "%.2fs %s" % (elapsed, status_line(r)))
    finally:
        sensor.stop()
        time.sleep(0.1)

    evs = load_events(events_path)
    failures += check("events_written", len(evs) > 0, "n=%d" % len(evs))
    p2s = [e for e in evs if e.get("php2shell") or
           any(str(t).startswith("php2shell") for t in (e.get("tags") or []))]
    failures += check("p2s_events", len(p2s) >= 1, "n=%d" % len(p2s))
    ds404 = [e for e in evs if "default-server" in (e.get("tags") or [])
             and e.get("http_status") == 404]
    failures += check("ds_404_events", len(ds404) >= 1, "n=%d" % len(ds404))
    assets = [e for e in evs if "php-page-asset" in (e.get("tags") or [])]
    failures += check("asset_tagged", len(assets) >= 1, "n=%d" % len(assets))

    # Safety: ensure inspect never implies a fetch (no network helpers imported)
    import anglerfish.phpapp as m
    src = open(m.__file__, encoding="utf-8").read()
    failures += check("no_urlopen_in_phpapp",
                      "urlopen" not in src and "requests." not in src)

    print()
    if failures:
        print("%d FAILURES" % failures)
        return 1
    print("all sunday overhaul checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
