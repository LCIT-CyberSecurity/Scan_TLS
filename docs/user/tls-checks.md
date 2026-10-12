# Complementary TLS checks

Eight additional, non-destructive checks that enrich a scan. They are **opt-in**: a configuration or a WebUI profile that does
not mention them behaves exactly as before. Their results are shown **next to** the findings and never change the grade, the
compliance status, the findings, the CSV or the CBOM.

| Id | Family | Recommended | What it establishes |
|---|---|---|---|
| `hostname_san` | identity | yes | The certificate presented for the **requested name** covers it (SAN DNS or IP). |
| `ocsp_stapling` | identity | yes | The server itself delivers a valid, current OCSP response for its certificate. |
| `tls_compression` | handshake | yes | TLS-level compression is not negotiated (CRIME). |
| `renegotiation` | handshake | yes | Secure renegotiation (RFC 5746) and the behaviour towards a client-initiated renegotiation. |
| `fallback_scsv` | handshake | yes | A downgraded connection carrying `TLS_FALLBACK_SCSV` is refused. |
| `extended_master_secret` | handshake | yes | Support of RFC 7627 (TLS 1.2 and earlier). |
| `ecdhe_groups` | groups | no | ECDHE groups **proven** to be accepted. |
| `ffdhe_groups` | groups | no | Size of the Diffie-Hellman parameters and named FFDHE groups. |

"Recommended" only means *pre-selected when a new profile is created in the WebUI*. Existing profiles and YAML files are never modified.

## Result statuses

| Status | Meaning |
|---|---|
| `PASS` | The control was performed and the observation is satisfactory. |
| `FAIL` | The control was performed and the observation is not satisfactory. |
| `NOT_APPLICABLE` | The control does not concern this endpoint (e.g. compression on a TLS 1.3-only server, stapling without an OCSP URL in the certificate). |
| `NOT_TESTED` | The control was not run: cancelled scan, time budget exhausted, STARTTLS protocol not supported, preconditions unknown. |
| `INCONCLUSIVE` | The control ran but cannot support a conclusion (timeout, unexpected answer, reference negotiation failed). |
| `ERROR` | Unexpected internal error; it never stops the scan or the other checks. |

`NOT_TESTED`, `INCONCLUSIVE` and `ERROR` mean *unknown*, never *passed*. Each result also carries structured **observations**
(what was actually proven), a short message and a few non-sensitive evidence lines.

## The checks, their method and their limits

**`hostname_san`** — The reference identity is the name you asked to scan (FQDN targets), or the IP address when the target is an
address or a network. A reverse-DNS (PTR) name is never used. For each requested name the certificate is fetched with that name as
SNI and matched according to RFC 9525: SAN DNS entries (case-insensitive, internationalised names compared as A-labels, a wildcard
only as the whole left-most label and never `*.tld`), SAN IP entries for addresses; the Common Name is **never** used. It says
nothing about chain trust (see the PKI controls). *Limit*: an IP target whose certificate has no IP SAN is a `FAIL` — a client
connecting by address would reject it too.

**`ocsp_stapling`** — Not the online OCSP query of the revocation control. For TLS ≤ 1.2 a raw handshake requests the status
and the stapled response is parsed and verified (status, certificate serial, freshness with a 5-minute tolerance, signature by the
issuer or by a delegated OCSP-signing responder). Absence is confirmed by a second attempt after about 1.5 s because some servers
(nginx, Apache) only staple once their cache is filled. Distinguished outcomes: absent, invalid/expired, revoked, unknown status,
valid, not applicable (no OCSP URL), inconclusive. *Limit*: a TLS 1.3-only server staples inside the encrypted handshake; it is then
read through `openssl s_client -status` and **the signature is not verified** (stated in the result).

**`tls_compression`** — A TLS ≤ 1.2 ClientHello offers DEFLATE and null; the compression method chosen in the ServerHello is read.
`PASS` only if the server chose null. Nothing is ever compressed (no `openssl -comp`). Not applicable when TLS 1.3 is the only version.

**`renegotiation`** — The ServerHello of a TLS ≤ 1.2 handshake must carry `renegotiation_info` (RFC 5746); otherwise the mode is
`insecure` (`FAIL`). When it does, one TLS 1.2 session is opened with `openssl s_client` and a single renegotiation request is sent:
`accepted`, `refused` or `undetermined` is recorded (mode `secure` / `refused`). `PASS` in both cases; an accepted client-initiated
renegotiation is flagged in the message because it can be abused for resource exhaustion. *Limit*: legacy (insecure) renegotiation is
never enabled on the client, so the classic CVE-2009-3555 behaviour is detected by the absence of RFC 5746, not by exploiting it.

**`fallback_scsv`** — Precondition: the main scan proved at least two supported versions. The probe offers the highest supported
version below the maximum (TLS 1.0–1.2); a **reference** handshake at that version must first succeed, then the same hello with
`TLS_FALLBACK_SCSV` must be answered with alert `inappropriate_fallback` (`PASS`); a normal ServerHello means no protection (`FAIL`).
Single-version servers are `NOT_APPLICABLE`; if the reference handshake fails the result is `INCONCLUSIVE`.

**`extended_master_secret`** — The extension is offered; the server must echo it. `NOT_APPLICABLE` for TLS 1.3-only endpoints.

**`ecdhe_groups`** — x25519, x448, secp256r1, secp384r1, secp521r1 and brainpoolP256r1/384r1/512r1 are offered **one at a time**
(per TLS version actually supported). A completed handshake with that group *proves* it is accepted; a refusal only means "not
accepted in that probe". The result lists the proven groups, the group negotiated by default and the refused/undetermined ones, and
states that it is **not a complete inventory** (older curves such as secp224r1 or sect* and hybrid ML-KEM groups — see the PQC
profile — are outside this check). Up to 18 connections per endpoint.

**`ffdhe_groups`** — A TLS 1.2 handshake restricted to DHE suites reads the Diffie-Hellman parameter size (`< 2048` bits is a `FAIL`;
the client uses OpenSSL security level 0 for this probe only, so that small parameters can be *observed*). The five RFC 7919 groups
are offered one at a time in TLS 1.3. A refusal in these probes is reported as "not accepted in this probe", not as proof of absence;
no DHE at all is `NOT_APPLICABLE`.

## Execution and safety

* One endpoint = its checks run one after the other, inside the host worker that scanned it: the existing parallelism limit
  (`scan.workers`) is the only concurrency, and there is no extra process pool.
* Limits (YAML `checks.tls.timeout_seconds`, 1–30, default 10 per connection; `time_budget_seconds`, 10–600, default 120 per
  endpoint). A check that finds the budget exhausted is `NOT_TESTED`. Cancelling a scan stops the remaining checks.
* Only fixed command lines are used (`openssl s_client` argument lists, no shell), with addresses coming from Nmap or validated targets.
* No Heartbleed, ROBOT, CCS injection, session resumption or 0-RTT test and no STARTTLS adapter beyond SMTP (the engine's existing one).
  On STARTTLS ports other than SMTP the raw-handshake checks return `NOT_TESTED`.
* Needs `openssl` (≥ 3.0; 3.5 recommended) in the scan environment — already required by the PKI controls.

## YAML

```yaml
checks:
  certificate: { ... }        # unchanged
  tls:
    timeout_seconds: 10       # per connection (default 10)
    time_budget_seconds: 120  # per endpoint (default 120)
    hostname_san: true        # or { enabled: true }
    ocsp_stapling: true
    tls_compression: true
    renegotiation: true
    fallback_scsv: true
    extended_master_secret: true
    ecdhe_groups: false
    ffdhe_groups: false
```

A configuration without `checks.tls` runs none of them. An unknown check id or an invalid value is a configuration error (so a typo
cannot silently skip a control). The same parser validates the Standalone YAML and the WebUI profiles.

## Standalone and WebUI

Same engine, same keys, same results. The WebUI selects them in *Policies → Profiles → Complementary TLS checks*, stores them
per endpoint (`run_endpoints.tls_checks`), shows them in the scan detail, the HTML/Markdown reports, the REST results API
(`tls_checks` on each endpoint), the external API/MCP and in comparisons (status changes). The Standalone CLI writes them to the
HTML and Markdown reports only; its terminal table, CSV, findings CSV and CBOM are unchanged.
