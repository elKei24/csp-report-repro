# Chrome drops CSP `report-to` reports from sandboxed iframes

A document in `<iframe sandbox="allow-scripts">` has an opaque origin. Chrome
does not register its `Reporting-Endpoints` header, so CSP violations that use
`report-to` are queued and never sent. `report-uri` from the same frame works.

## Run

    python3 server.py --chrome
    python3 server.py --firefox

This creates a self-signed certificate, serves `https://localhost:8443`, opens
the headless browser with a throwaway profile, waits 20 s (`--wait 60` to change)
and prints which frame delivered a report. Exit code 1 if a frame stays silent.

Chrome 156.0.8078.79:

    sandbox-report-to    NOTHING
    sandbox-report-uri   reported
    plain-report-to      reported

Firefox 157.0 delivers all three. Its report from the sandboxed frame arrives
as `application/reports+json` with `Origin: null`.

Without `--chrome` the server only serves. Open `https://localhost:8443/` in a
Chrome started with:

    google-chrome --ignore-certificate-errors --short-reporting-delay \
      --disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessChecks \
      https://localhost:8443/

The page polls `/reports` and shows what arrived.

## Why the flags

- `Reporting-Endpoints` is only honored over https, hence the self-signed
  certificate and `--ignore-certificate-errors`.
- `--short-reporting-delay` sends queued reports at once instead of after a
  minute.
- Local Network Access blocks requests from an opaque origin to loopback, which
  would hide the bug behind a different error.
- Firefox has no flag to ignore certificate errors, so the script writes a
  `cert_override.txt` with the certificate fingerprint into the profile.

## Cause

`RenderFrameHostImpl::DidCommitNewDocument` (content/browser/renderer_host/render_frame_host_impl.cc)
registers `Reporting-Endpoints` only when
`GURL::SchemeIsCryptographic(origin.scheme())` holds for the committed origin.
An opaque origin has an empty scheme, so the endpoints are never stored.
