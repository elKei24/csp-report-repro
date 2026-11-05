#!/usr/bin/env python3
"""Minimal repro: Chrome drops CSP `report-to` reports from opaque-origin (sandboxed) iframes.

    python3 server.py            # serves https://localhost:8443
    python3 server.py --chrome   # also launches headless Chrome against it and prints what arrived
    python3 server.py --firefox  # same with Firefox
    python3 server.py --http     # plain HTTP on 0.0.0.0:$PORT, for a TLS-terminating proxy in front

Each frame has `script-src 'none'` and one inline <script>, so one CSP violation per frame.
"""
import argparse
import hashlib
import http.server
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

PORT = 8443
ORIGIN = f"https://localhost:{PORT}"
CERT = Path("cert.pem")
KEY = Path("key.pem")


FRAME_CSP = {
    "/sandbox-report-to": "script-src 'none'; report-to csp",
    "/sandbox-report-uri": "script-src 'none'; report-uri /report",
    "/plain-report-to": "script-src 'none'; report-to csp",
}

INDEX_HTML = """<!doctype html>
<h1>CSP report-to repro</h1>
<p>sandbox-report-to<br><iframe sandbox="allow-scripts" src="/sandbox-report-to"></iframe></p>
<p>sandbox-report-uri<br><iframe sandbox="allow-scripts" src="/sandbox-report-uri"></iframe></p>
<p>plain-report-to<br><iframe src="/plain-report-to"></iframe></p>
<pre id="out"></pre>
<script>
setInterval(async () => {
  const response = await fetch("/reports");
  out.textContent = JSON.stringify(await response.json(), null, 1);
}, 1000);
</script>
"""

FRAME_HTML = """<!doctype html>
<script>document.body.append("script ran, CSP missing")</script>
"""

reports = []
REPORT_TTL = timedelta(minutes=5)


def drop_old_reports():
    cutoff = (datetime.now(timezone.utc) - REPORT_TTL).isoformat(timespec="seconds")
    reports[:] = [report for report in reports if report["received"] > cutoff]


class ReproHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.respond(INDEX_HTML)
        elif self.path in FRAME_CSP:
            self.respond(FRAME_HTML, headers={
                "Reporting-Endpoints": 'csp="/report"',
                "Content-Security-Policy": FRAME_CSP[self.path],
            })
        elif self.path == "/reports":
            drop_old_reports()
            self.respond(json.dumps(reports), content_type="application/json")
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        self.respond("", status=204, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST",
            "Access-Control-Allow-Headers": "content-type",
        })

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        report = {
            "received": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "path": self.path,
            "type": self.headers.get("Content-Type"),
            "origin": self.headers.get("Origin"),
            "user_agent": self.headers.get("User-Agent"),
            "body": json.loads(self.rfile.read(length)),
        }
        drop_old_reports()
        reports.append(report)
        print("REPORT", json.dumps(report), flush=True)
        self.respond("", content_type="text/plain", headers={"Access-Control-Allow-Origin": "*"})

    def respond(self, body, status=200, content_type="text/html", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


def reported_frames(report):
    body = report["body"]
    if isinstance(body, list):  # report-to: application/reports+json
        urls = [entry["body"]["documentURL"] for entry in body]
    else:  # report-uri: application/csp-report
        urls = [body["csp-report"]["document-uri"]]
    return [urlparse(url).path for url in urls]


def ensure_certificate():
    if CERT.exists():
        return
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
        "-keyout", KEY, "-out", CERT, "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, capture_output=True)


def start_https_server():
    ensure_certificate()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), ReproHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("serving", ORIGIN, flush=True)
    return server


def start_http_server():
    port = int(os.environ.get("PORT", 8080))
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), ReproHandler)
    print("serving http on port", port, flush=True)
    return server


def chrome_command(profile):
    return [
        "google-chrome", f"--user-data-dir={profile}", "--headless=new", "--no-first-run",
        "--ignore-certificate-errors", "--short-reporting-delay",
        "--disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessChecks",
        ORIGIN + "/",
    ]


def firefox_command(profile):
    # Firefox has no --ignore-certificate-errors; a cert_override.txt entry trusts the cert for this host.
    der = ssl.PEM_cert_to_DER_cert(CERT.read_text())
    fingerprint = ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())
    (profile / "cert_override.txt").write_text(
        f"localhost:{PORT}:\tOID.2.16.840.1.101.3.4.2.1\t{fingerprint}\tMUT\t\n"
    )
    return ["firefox", "--headless", "--no-remote", "--profile", str(profile), ORIGIN + "/"]


def run_browser(command_for, wait):
    # snap Firefox cannot read /tmp, so the profile lives under $HOME
    with tempfile.TemporaryDirectory(dir=Path.home(), ignore_cleanup_errors=True) as profile:
        command = command_for(Path(profile))
        browser = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(wait)
        browser.terminate()
        browser.wait()


def print_summary(wait):
    seen = {name for report in reports for name in reported_frames(report)}
    print(f"\nafter {wait}s:")
    for name in FRAME_CSP:
        print(f"  {name:20} {'reported' if name in seen else 'NOTHING'}")
    return seen == set(FRAME_CSP)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--chrome", dest="browser", action="store_const", const=chrome_command)
    mode.add_argument("--firefox", dest="browser", action="store_const", const=firefox_command)
    mode.add_argument("--http", action="store_true", help="plain HTTP on 0.0.0.0:$PORT (default 8080) behind a TLS proxy")
    parser.add_argument("--wait", type=int, default=20, help="seconds to give the browser (default: 20)")
    return parser.parse_args()


def main():
    args = parse_args()
    server = start_http_server() if args.http else start_https_server()
    if args.browser is None:
        server.serve_forever()
        return
    threading.Thread(target=server.serve_forever, daemon=True).start()
    run_browser(args.browser, args.wait)
    sys.exit(0 if print_summary(args.wait) else 1)


if __name__ == "__main__":
    main()
