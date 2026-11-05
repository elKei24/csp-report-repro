# Chrome drops CSP `report-to` reports from sandboxed iframes

A document inside `<iframe sandbox="allow-scripts">` has an opaque origin. When
such a document sends a `Content-Security-Policy` with `report-to` and a
`Reporting-Endpoints` header, Chrome never delivers its violation reports. The
reports are queued and stay in the queue. The same frame with `report-uri`
delivers its report. Firefox delivers both.

This repository contains a minimal server that shows the problem.

## What the reproduction shows

The server at `https://localhost:8443/` serves a page with three iframes. Each
frame has the policy `script-src 'none'` and one inline `<script>`, so each
frame causes exactly one CSP violation. Each frame response also carries
`Reporting-Endpoints: csp="/report"`.

| Frame                | `sandbox="allow-scripts"` | Policy suffix        | Chrome 156  | Firefox 157 |
|----------------------|---------------------------|----------------------|-------------|-------------|
| `sandbox-report-to`  | yes                       | `report-to csp`      | no report   | report      |
| `sandbox-report-uri` | yes                       | `report-uri /report` | report      | report      |
| `plain-report-to`    | no                        | `report-to csp`      | report      | report      |

The only difference between `sandbox-report-to` and `plain-report-to` is the
`sandbox` attribute. The only difference between `sandbox-report-to` and
`sandbox-report-uri` is the report directive. So the lost report is caused by
the combination of an opaque origin and `report-to`.

Firefox sends the report from the sandboxed frame as `application/reports+json`
with `Origin: null`, which is the expected result.

## Run

    python3 server.py --chrome
    python3 server.py --firefox

The script creates a self-signed certificate, serves `https://localhost:8443`,
opens the headless browser with a throwaway profile, waits 20 s (`--wait 60` to
change) and prints which frame delivered a report. The exit code is 1 when a
frame stays silent.

Chrome 156.0.8078.79:

    /sandbox-report-to   NOTHING
    /sandbox-report-uri  reported
    /plain-report-to     reported

Firefox 157.0:

    /sandbox-report-to   reported
    /sandbox-report-uri  reported
    /plain-report-to     reported

Without a browser flag the server only serves. Open `https://localhost:8443/`
in a Chrome started with:

    google-chrome --user-data-dir=/tmp/csp-profile \
      --ignore-certificate-errors --short-reporting-delay \
      --disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessChecks \
      https://localhost:8443/

The page polls `/reports` and shows what arrived. The separate profile is
necessary: the flags have no effect when the URL opens in a Chrome that is
already running, and a certificate warning that you click through makes Chrome
ignore `Reporting-Endpoints` completely.

### Why the flags

- `Reporting-Endpoints` is only honored over https, hence the self-signed
  certificate and `--ignore-certificate-errors`.
- `--short-reporting-delay` sends queued reports at once instead of after a
  minute. Without the flag the result is the same, only slower.
- Local Network Access blocks requests from an opaque origin to loopback, which
  would hide the bug behind a different error.
- Firefox has no flag to ignore certificate errors, so the script writes a
  `cert_override.txt` with the certificate fingerprint into the profile.

## Host it with a real certificate

The browser flags above are only necessary for the self-signed certificate on
`localhost`. Behind a reverse proxy that terminates TLS, the page works in a
normal Chrome without flags. The `Container image` workflow publishes an image
on each push to `main`:

    docker run -p 8080:8080 ghcr.io/elkei24/csp-report-repro

or `docker build -t csp-report-repro .`, or `python3 server.py --http` (port
from `PORT`, default 8080). Put a TLS proxy such as Caddy in front:

    repro.example.org {
        reverse_proxy localhost:8080
    }

Reports are kept in memory for 5 minutes and `/reports` shows them with the
time of receipt. Chrome sends `report-to` reports about one minute after the
violation, so wait a minute (or start Chrome with `--short-reporting-delay`).

## Why this is wrong

### The standards do not exclude opaque origins

[CSP Level 3, § 5.5 "Report a violation"][csp-report] says what to do when the
policy contains `report-to`: build a `CSPViolationReportBody` and run the
Reporting API algorithm "generate and queue a report". The algorithm has no
condition on the origin of the document. Opaque origins are not mentioned.

[Reporting API, § 3.3 "Process reporting endpoints for response"][rep-process]
says when a `Reporting-Endpoints` header is accepted:

> Abort these steps if response's HTTPS state is not "modern", and the origin
> of response's url is not potentially trustworthy.

The condition looks at the **response's URL**, not at the document's origin.
The URL of the sandboxed frame is `https://localhost:8443/sandbox-report-to`.
Its origin is `https://localhost:8443`, which is potentially trustworthy. The
document's opaque origin plays no role in this algorithm.

The per-endpoint check in the same algorithm is also about the endpoint URL,
not about the document:

> If endpoint url's origin is not potentially trustworthy, then continue.

[HTML, "secure context"][html-secure] confirms that the sandboxed document is
a secure context: the decision uses the **top-level creation URL**, which is
`https://localhost:8443/`, not the document's origin. Chrome agrees: a script
in such a frame sees `isSecureContext === true` and `origin === "null"`.

So, by the specifications, the `Reporting-Endpoints` header of the sandboxed
frame must be accepted, and the CSP violation must be sent to it.

### `report-uri` is not a fallback

[CSP Level 3, § 6.5.1 "report-uri"][csp-report-uri] tells authors to specify
both directives, and says that `report-to` wins:

> If the latter directive is present, this directive will be ignored. To ensure
> backwards compatibility, we suggest specifying both, like this:
> `Content-Security-Policy: ...; report-uri https://endpoint.com; report-to groupname`

Chrome follows this part. So a policy written the recommended way loses all
reports from sandboxed frames in Chrome. There is no way to get them: with
`report-to` the report is never sent, and `report-uri` is ignored because
`report-to` is present.

### Firefox delivers the reports

Firefox 157 runs the same page and delivers all three reports. The report from
the sandboxed frame has `Origin: null` and the normal `application/reports+json`
body. Chrome and Firefox disagree, and the specification sides with Firefox.

### No warning, no error

Chrome does not log anything in the console. The report is queued and stays
queued. If Chrome intended to exclude opaque origins, the specification would
need a step for it, and the browser should at least say in the console that it
dropped the report.

## Cause

[`RenderFrameHostImpl::DidCommitNewDocument`][chromium-src] in
`content/browser/renderer_host/render_frame_host_impl.cc` registers the
`Reporting-Endpoints` header of a committed document only under this condition:

```c++
// Reporting API: If a Reporting-Endpoints header was received with this
// document over secure connection, send it to the network service to
// configure the endpoints in the reporting cache.
if (GURL::SchemeIsCryptographic(origin.scheme()) &&
    navigation_request->response() &&
    navigation_request->response()->parsed_headers->reporting_endpoints) {
  ...
  GetStoragePartition()->GetNetworkContext()->SetDocumentReportingEndpoints(
      GetReportingSource(), origin, isolation_info_, endpoints);
}
```

`origin` is the committed origin of the document. For a sandboxed document it
is opaque, and an opaque origin has an empty scheme. `SchemeIsCryptographic("")`
is false, so the endpoints are never sent to the network service. The CSP
violation is still queued for the reporting source of the document, but the
reporting cache knows no endpoint for that source, so the report is never
uploaded.

The comment says "over secure connection", which matches the specification's
intent: check the response URL. The code checks the document origin instead.
The fix is to test the scheme of the committed URL (or the response URL)
instead of the origin's scheme.

## Related

- [Chromium issue 581045139][crbug-581045139] tracks this bug.
- [Chromium issue 41490651][crbug-41490651]: `report-to` reports for
  `frame-ancestors` violations in iframes are not sent. Different trigger,
  but also a case where a `Reporting-Endpoints` registration for a frame is
  missing.
- The [WPT suite for CSP reporting][wpt] has no test with a sandboxed iframe,
  which is why the case is not covered by interop testing.

[csp-report]: https://w3c.github.io/webappsec-csp/#report-violation
[csp-report-uri]: https://w3c.github.io/webappsec-csp/#directive-report-uri
[rep-process]: https://w3c.github.io/reporting/#process-header
[html-secure]: https://html.spec.whatwg.org/multipage/webappapis.html#secure-context
[chromium-src]: https://source.chromium.org/chromium/chromium/src/+/main:content/browser/renderer_host/render_frame_host_impl.cc;l=17620
[crbug-581045139]: https://issues.chromium.org/issues/581045139
[crbug-41490651]: https://issues.chromium.org/issues/41490651
[wpt]: https://github.com/web-platform-tests/wpt/tree/master/content-security-policy/reporting-api
