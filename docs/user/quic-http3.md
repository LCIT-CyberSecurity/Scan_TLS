# QUIC / HTTP/3 observations

QUIC is an optional UDP check inside the existing TLS scan profile and scan workflow. It uses aioquic to initiate a
QUIC handshake and offers HTTP/3 ALPN `h3`; it does not send an HTTP request, enumerate UDP ports, or run a second
compliance engine. The dependency is BSD-3-Clause and supports Python 3.12 / Debian 13.

## Configuration

In **Policies → TLS → Scan profiles**, opt in to QUIC / HTTP/3. Profiles without the setting remain disabled, including
existing published versions. Configure 1–16 explicit UDP ports (default 443), handshake timeout (1–10 seconds),
retries (0–1), maximum targets (1–64), concurrency (1–8), and global duration (1–120 seconds).

In **Scans**, the optional control inherits the selected published profile. You can override it for an individual scan;
the override is stored on the scan definition and does not edit a published profile. Historical scan snapshots remain
unchanged.

## Reading results

`observed` means aioquic completed the QUIC TLS 1.3 handshake. Results display UDP port, QUIC version, negotiated
ALPN, cipher suite, and certificate subject / issuer / serial / SHA-256 fingerprint when those fields are available.
ALPN `h3` indicates HTTP/3 protocol negotiation only; no application data is requested.

`inconclusive` means the handshake could not be confirmed (including timeout, filtering, or a transport/protocol
error). A silent UDP port is never labeled absent. Targets beyond the configured cap are `not_tested`.

The existing TLS policy is applied only to the observed TLS 1.3 version and a recognized cipher family. Its aggregate
status remains `not_evaluated`; certificate-chain trust, hostname matching, expiration, revocation, and TCP-specific
or STARTTLS controls are not inferred from this probe. QUIC observations are stored separately from TCP TLS endpoints,
shown in scan history, included in HTML/Markdown addenda, and available in a dedicated CSV export when CSV is enabled.
