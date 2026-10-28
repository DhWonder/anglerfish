"""Domain Host over plain HTTP -> 301 to HTTPS; bare IP and the HTTPS port are untouched.

Uses the public example persona (domain example.net) and a throwaway
self-signed cert in a temp state_dir, so the redirect is active.
"""

import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

_TMP = tempfile.mkdtemp(prefix="anglerfish-redirect-")
_EVENTS = os.path.join(_TMP, "events.jsonl")
os.environ["ANGLERFISH_EVENTS_PATH"] = _EVENTS
os.environ.pop("ANGLERFISH_HTTPS_REDIRECT", None)

from anglerfish.sensor import Sensor
import anglerfish.sensor as sensor_module

sensor_module.AUTH_FAIL_DELAY_MIN = 0.05
sensor_module.AUTH_FAIL_DELAY_MAX = 0.05
sensor_module.STATUS_WRITE_MIN_GAP = 0.0

DOMAIN = "example.net"
FQDN = "files01.example.net"


def check(name, ok):
    print("  %-62s %s" % (name, "ok" if ok else "FAILED"))
    return ok


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


def _read_all(sock):
    sock.settimeout(3)
    data = b""
    while True:
        try:
            chunk = sock.recv(8192)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        data += chunk
    return data


def http_get(port, host, path="/", method="GET"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                      % (method, path, host)).encode())
        return _read_all(conn)


def https_get(port, host, path="/"):
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with cctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                         % (path, host)).encode())
            return _read_all(tls)


def header(resp, name):
    for line in resp.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == name.lower().encode():
            return v.strip().decode("latin-1")
    return None


def make_sensor(name, ports, **kw):
    return Sensor(name=name, ports=ports, persona=False, classroom=True,
                  state_dir=_TMP, bind="127.0.0.1",
                  log_path=os.path.join(_TMP, name + ".log"),
                  status_path=os.path.join(_TMP, name + ".json"), **kw)


def main():
    failures = 0
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", os.path.join(_TMP, "tls-key.pem"),
         "-out", os.path.join(_TMP, "tls-cert.pem"), "-days", "1",
         "-subj", "/O=Example Clinic/CN=%s" % FQDN],
        check=True, capture_output=True, timeout=60)

    http_port, https_port = free_port(), free_port()
    sensor_module.SERVICE_BY_PORT[http_port] = "http"
    sensor_module.SERVICE_BY_PORT[https_port] = "http"
    sensor_module.HTTPS_PORTS = set(sensor_module.HTTPS_PORTS) | {https_port}
    sensor_module.TLS_PORTS = set(sensor_module.TLS_PORTS) | {https_port}

    sensor = make_sensor("redirect", [http_port, https_port])
    assert sensor._ssl_ctx is not None, "TLS context missing (cert not loaded)"
    failures += not check("redirect defaults to on", sensor.https_redirect is True)
    sensor.start()
    time.sleep(0.3)

    r = http_get(http_port, DOMAIN, "/webman/login.cgi?x=1")
    failures += not check("apex domain on HTTP -> 301",
                          r.startswith(b"HTTP/1.1 301"))
    failures += not check("Location keeps host + path + query",
                          header(r, "Location") == "https://%s/webman/login.cgi?x=1" % DOMAIN)

    r = http_get(http_port, "WWW.%s:80" % DOMAIN.upper())
    failures += not check("www subdomain (mixed case, :80) -> 301 https://www.<domain>/",
                          r.startswith(b"HTTP/1.1 301")
                          and header(r, "Location") == "https://www.%s/" % DOMAIN)

    r = http_get(http_port, FQDN, method="HEAD")
    failures += not check("HEAD on persona fqdn -> 301 with no body",
                          r.startswith(b"HTTP/1.1 301") and r.endswith(b"\r\n\r\n"))

    r = http_get(http_port, "127.0.0.1")
    failures += not check("bare IP Host on HTTP stays 200 (clinic cover)",
                          r.startswith(b"HTTP/1.1 200") and b"Apache/2.4.58" in r
                          and header(r, "Location") is None)

    r = http_get(http_port, "evil.example")
    failures += not check("unknown Host is not redirected to HTTPS",
                          header(r, "Location") is None
                          and not r.startswith(b"HTTP/1.1 301"))

    r = http_get(http_port, "not%s" % DOMAIN)
    failures += not check("look-alike Host (not<domain>) is not redirected",
                          header(r, "Location") is None)

    try:
        r = https_get(https_port, DOMAIN)
    except Exception as exc:
        print("  https client error:", exc)
        r = b""
    failures += not check("domain Host on the HTTPS port -> 200, not redirected",
                          r.startswith(b"HTTP/1.1 200") and header(r, "Location") is None)

    time.sleep(0.3)
    sensor.stop()

    evs = []
    if os.path.exists(_EVENTS):
        with open(_EVENTS, encoding="utf-8") as fh:
            evs = [json.loads(l) for l in fh if l.strip()]
    tagged = [e for e in evs if "https-redirect" in (e.get("tags") or [])]
    failures += not check("redirects emit http events tagged https-redirect",
                          len(tagged) >= 3
                          and all(e.get("http_status") == 301 for e in tagged))

    # Flag off: same request is served normally.
    port2 = free_port()
    sensor_module.SERVICE_BY_PORT[port2] = "http"
    off = make_sensor("noredirect", [port2], https_redirect=False)
    off.start()
    time.sleep(0.2)
    r = http_get(port2, DOMAIN)
    failures += not check("https_redirect=False -> domain Host served 200",
                          r.startswith(b"HTTP/1.1 200") and header(r, "Location") is None)
    off.stop()

    os.environ["ANGLERFISH_HTTPS_REDIRECT"] = "0"
    failures += not check("ANGLERFISH_HTTPS_REDIRECT=0 disables it",
                          make_sensor("envoff", [free_port()]).https_redirect is False)
    os.environ.pop("ANGLERFISH_HTTPS_REDIRECT", None)

    # No cert loaded -> never redirect to an HTTPS port that is not served.
    nocert_dir = tempfile.mkdtemp(prefix="anglerfish-nocert-")
    port3 = free_port()
    sensor_module.SERVICE_BY_PORT[port3] = "http"
    nc = Sensor(name="nocert", ports=[port3], persona=False, classroom=True,
                state_dir=nocert_dir, bind="127.0.0.1",
                log_path=os.path.join(nocert_dir, "s.log"),
                status_path=os.path.join(nocert_dir, "s.json"))
    nc.start()
    time.sleep(0.2)
    r = http_get(port3, DOMAIN)
    failures += not check("no TLS cert loaded -> no redirect",
                          r.startswith(b"HTTP/1.1 200") and header(r, "Location") is None)
    nc.stop()

    print()
    if failures:
        print("%d redirect check(s) failed." % failures)
        return 1
    print("All HTTPS redirect checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
