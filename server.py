#!/usr/bin/env python3
"""Minimal repro: Chrome drops CSP `report-to` reports from opaque-origin (sandboxed) iframes.

    python3 server.py            # serves https://localhost:8443
    python3 server.py --chrome   # also launches headless Chrome against it and prints what arrived
    python3 server.py --firefox  # same with Firefox

Each frame has `script-src 'none'` and one inline <script>, so one CSP violation per frame.
"""
import hashlib, http.server, json, os, ssl, subprocess, sys, tempfile, threading, time
from urllib.parse import urlparse, parse_qs

PORT = 8443
ORIGIN = f"https://localhost:{PORT}"
CERT, KEY = "cert.pem", "key.pem"
reports = []

FRAMES = {
    "sandbox-report-to": dict(sandbox=True, csp="script-src 'none'; report-to csp"),
    "sandbox-report-uri": dict(sandbox=True, csp="script-src 'none'; report-uri /report"),
    "plain-report-to": dict(sandbox=False, csp="script-src 'none'; report-to csp"),
}


class H(http.server.BaseHTTPRequestHandler):
    def _send(self, body, ctype="text/html", headers=()):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            frames = "".join(
                f'<p>{name}<br><iframe name="{name}" {"sandbox=allow-scripts" if f["sandbox"] else ""} src="/frame?name={name}"></iframe></p>'
                for name, f in FRAMES.items())
            return self._send(f"<h1>CSP report-to repro</h1>{frames}<pre id=out></pre>"
                              "<script>setInterval(async()=>{out.textContent=JSON.stringify(await (await fetch('/reports')).json(),null,1)},1000)</script>")
        if u.path == "/frame":
            name = parse_qs(u.query)["name"][0]
            return self._send(f"<p>{name}</p><script>document.body.append('script ran, CSP missing')</script>",
                              headers=[("Reporting-Endpoints", f'csp="{ORIGIN}/report"'),
                                       ("Content-Security-Policy", FRAMES[name]["csp"])])
        if u.path == "/reports":
            return self._send(json.dumps(reports), "application/json")
        self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        entry = dict(path=self.path, type=self.headers.get("Content-Type"), origin=self.headers.get("Origin"), body=json.loads(body))
        reports.append(entry)
        print("REPORT", json.dumps(entry), flush=True)
        self._send("", "text/plain", [("Access-Control-Allow-Origin", "*")])

    def log_message(self, *a):
        pass


def frame_of(r):
    b = r["body"]
    docs = [x["body"].get("document-uri", x["body"].get("documentURL", "")) for x in b] if isinstance(b, list) else [b["csp-report"]["document-uri"]]
    return [parse_qs(urlparse(d).query).get("name", ["?"])[0] for d in docs]


def main():
    if not os.path.exists(CERT):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", KEY, "-out", CERT,
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "365"], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("serving", ORIGIN, flush=True)
    if not {"--chrome", "--firefox"} & set(sys.argv):
        return srv.serve_forever()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    wait = int(os.environ.get("WAIT", "20"))
    # snap Firefox cannot read /tmp, so profiles live under $HOME
    with tempfile.TemporaryDirectory(dir=os.path.expanduser("~"), ignore_cleanup_errors=True) as prof:
        if "--firefox" in sys.argv:
            der = ssl.PEM_cert_to_DER_cert(open(CERT).read())
            fp = ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())
            with open(os.path.join(prof, "cert_override.txt"), "w") as f:
                f.write(f"localhost:{PORT}:\tOID.2.16.840.1.101.3.4.2.1\t{fp}\tMUT\t\n")
            cmd = ["firefox", "--headless", "--no-remote", "--profile", prof, ORIGIN + "/"]
        else:
            cmd = ["google-chrome", f"--user-data-dir={prof}", "--headless=new", "--no-first-run",
                   "--ignore-certificate-errors", "--short-reporting-delay",
                   "--disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessChecks", ORIGIN + "/"]
        browser = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(wait)
        browser.terminate()
        browser.wait()
    seen = {f for r in reports for f in frame_of(r)}
    print(f"\nafter {wait}s:")
    for name in FRAMES:
        print(f"  {name:20} {'reported' if name in seen else 'NOTHING'}")
    sys.exit(0 if seen == set(FRAMES) else 1)


if __name__ == "__main__":
    main()
