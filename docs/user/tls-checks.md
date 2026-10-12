# Complementary TLS checks

Eighteen additional, non-destructive checks that enrich a scan: eight about identity and negotiation (lot 1) and ten about sessions, client authentication and STARTTLS protocols (lot 2). They are **opt-in**: a configuration or a WebUI profile that does
not mention them behaves exactly as before. Their results are shown **next to** the findings and never change the grade, the
compliance status, the findings, the CSV or the CBOM.

One historical field is aware of them: the list of *checks not performed* of an endpoint always contains "Hostname validation" and "SAN validation" (the historical engine never checks the name). When `hostname_san` ends with `PASS` or `FAIL`, those two entries are removed for that endpoint, since the verdict now exists; with any other status (`INCONCLUSIVE`, `NOT_TESTED`, `ERROR`, `NOT_APPLICABLE`) they stay.

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
| `session_resumption` | sessions | yes | Whether a session offered back is resumed (identifier, ticket or TLS 1.3 PSK). |
| `session_tickets` | sessions | yes | Whether session tickets are issued and usable, and their lifetime hint. |
| `early_data` | sessions | yes | Whether TLS 1.3 early data (0-RTT) is announced; acceptance only with the optional deep probe. |
| `client_auth` | authentication | yes | Whether a client certificate is requested or required at the TLS level (no client certificate is used). |
| `starttls_imap` | protocols | yes | IMAP is confirmed and the service switches to TLS with `STARTTLS`. |
| `starttls_pop3` | protocols | yes | POP3 is confirmed and the service switches to TLS with `STLS`. |
| `starttls_ldap` | protocols | yes | LDAP is confirmed and accepts the StartTLS extended operation. |
| `starttls_ftp` | protocols | yes | FTP is confirmed and accepts `AUTH TLS`. |
| `starttls_postgres` | protocols | yes | PostgreSQL answers the native `SSLRequest` and switches to TLS. |
| `starttls_xmpp` | protocols | yes | XMPP (client-to-server) announces and accepts `STARTTLS`. |
| `starttls_xmpp_server` | protocols | yes | XMPP server-to-server (port 5269) announces and accepts `STARTTLS`. |

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
valid, not applicable (no OCSP URL), inconclusive. A TLS 1.3-only server staples inside the encrypted handshake: the decrypted
Certificate message printed by `openssl s_client -msg` is parsed like the TLS 1.2 one and verified the same way, **signature included**.
*Fallback*: if that transcript cannot be parsed, `openssl s_client -status` text is read instead and **the signature is then not verified** (stated in the result).

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

## Lot 2: sessions, client authentication and STARTTLS protocols

### How to read the statuses of these observation checks

Session resumption, tickets, 0-RTT and client authentication are **properties to know about, not defects**. A server that resumes
sessions, issues tickets, announces 0-RTT or requests a client certificate is not non-compliant, and neither is one that does not.
They therefore return `PASS` when the observation is **conclusive** (the actual finding is in `observations.outcome` and in the
message), `INCONCLUSIVE` when it is not, `NOT_APPLICABLE` when the protocol version does not allow it, and never `FAIL`. Nothing here
changes the grade. The STARTTLS protocol checks do use `FAIL`: a service confirmed as IMAP (etc.) that does not switch to TLS stays in clear text.

### `session_resumption` and `session_tickets`

Both read **one shared set of probes** per endpoint (the connections are not repeated). For TLS 1.3 and TLS 1.2 a first connection obtains
a session; in TLS 1.3 the connection is only read, for at most `ticket_wait_seconds` (default 2), until the post-handshake ticket arrives.
Then up to `attempts` (default 2, max 3) connections offer the session back with the same server name, each one using the session of the
previous connection. The handshake itself says whether the session was reused. TLS 1.2 is probed twice: with tickets, and with tickets
disabled to exercise **identifier-based** resumption. Outcomes of `session_resumption`: `resumed` (with the mechanisms), `refused`
(offered N times, full handshake each time — other back-ends behind a load balancer may behave differently), `not_offered` (no ticket
and no identifier issued), or `INCONCLUSIVE`. `session_tickets` distinguishes **announced** (TLS 1.2: the empty `session_ticket`
extension in the ServerHello), **issued** (with the lifetime hint in seconds) and **resumption demonstrated**; a TLS 1.3 ticket not seen
within the wait is `INCONCLUSIVE`, since a later ticket cannot be excluded.

*Limits*: ticket content is never stored or logged (only presence and lifetime hint, sessions live in memory); ticket-key **rotation**
and key strength, stateless versus stateful TLS 1.3 tickets and the behaviour of other back-ends are not observable from outside;
a refusal never proves that the server cannot resume.

### `early_data` (TLS 1.3 0-RTT)

After a bounded wait for the ticket, `openssl s_client` shows whether the ticket announces early data (`max_early_data_size`).
Without the deep probe the result is "announced" or "not announced" and `acceptance: not_tested` — acceptance cannot be shown without
sending early data. With `probe: true` (**off by default**) the session is resumed once and the only thing sent as early data is an
**empty line (CRLF)**: HTTP servers ignore it, it contains no method, command or body, and it cannot change any state. The probe is skipped on
STARTTLS channels. The result then says `accepted` or `rejected`. Accepted 0-RTT means the application must tolerate **replayed**
data (idempotent requests, or replay protection); it is information, not a vulnerability, and is never graded. The temporary
session file `openssl` needs is created in a private (0700) directory and removed immediately.

### `client_auth` (mTLS)

For TLS 1.3 then TLS 1.2 two observations are made without any client certificate: `openssl s_client -msg` shows whether a
`CertificateRequest` is sent (and the accepted CA names, at most 10), and a handshake without certificate shows whether the server
tolerates it; in TLS 1.3 the connection is read for about a second to catch a post-handshake alert. Outcomes: `none_observed`, `requested_optional_or_probable`
(requested and accepted at the TLS layer without a certificate), `required_demonstrated` (requested and rejected without one),
or `INCONCLUSIVE`. A completed handshake does not prove that the application behind it does not authenticate users (a proxy may
answer HTTP 400 for a missing certificate after a successful handshake), and a failed one does not by itself prove mTLS.
*Not in scope*: client certificates are not supported — no key or certificate is read, stored or logged; this keeps the check usable
everywhere without a secrets mechanism. A future extension would add an explicitly configured certificate reference.

### STARTTLS protocols (`starttls_imap`, `starttls_pop3`, `starttls_ldap`, `starttls_ftp`, `starttls_postgres`, `starttls_xmpp`)

| Protocol | Standard port | Dialogue (nothing else is ever sent) |
|---|---|---|
| IMAP | 143 | greeting, `CAPABILITY`, `STARTTLS` (only if announced) |
| POP3 | 110 | greeting, `CAPA`, `STLS` (tried anyway when `CAPA` is not implemented) |
| LDAP | 389 | one `ExtendedRequest` StartTLS (OID 1.3.6.1.4.1.1466.20037), result code read from the BER answer |
| FTP | 21 | banner, `AUTH TLS` (reply 234); no login, no data connection, no transfer |
| PostgreSQL | 5432 | the native 8-byte `SSLRequest`; the single-byte answer `S` / `N` / `E` is read (not a text STARTTLS) |
| XMPP | 5222 | stream header (client-to-server `jabber:client`), `<starttls/>` feature, `<proceed/>` |
| XMPP server-to-server | 5269 | same dialogue on a `jabber:server` stream; no dialback, no stanza |
| SMTP | 25, 587 | historical, always active, unchanged: `EHLO`, `STARTTLS` |

Each adapter first **confirms the protocol from the server's own answers**, so a port number alone never proves a service: the result
records `assumed_by` (standard or configured ports) and `confirmed`. No authentication, no business command, bounded reads (4 KB per
line, 64 KB per exchange), a deadline and cooperative cancellation. Statuses: `PASS` (confirmed, upgraded and a TLS handshake
completed on the negotiated channel; version and cipher recorded), `FAIL` (confirmed but STARTTLS not offered or refused: the
connection stays in clear text), `NOT_APPLICABLE` (the service does not answer like this protocol), `INCONCLUSIVE` (timeout, closed
connection, malformed answer).

**Selecting a protocol also changes how the endpoint's other checks reach TLS.** On a port that belongs to a selected protocol (the
standard one, or the ones in `ports`), every selected check — the lot 1 raw handshakes, the group probes, the sessions, 0-RTT, mTLS, the
identity check and the certificate chain used by the trust/revocation controls — goes through the adapter, so they really run on the
negotiated TLS channel. Without the protocol selected, those checks would be talking TLS to a plain-text service and end `INCONCLUSIVE`.
Protocol checks **only exist on their own ports**: on any other endpoint they are skipped (no result row, no connection).
Which endpoints are scanned at all still comes from Nmap, which negotiates STARTTLS on the standard client ports by itself; it does not discover
XMPP server-to-server (5269) or non-standard ports, where the `ports` option only decides how a *discovered* endpoint is reached. A non-SMTP service with STARTTLS-only is not scanned over implicit TLS (993, 995, 636 ... are direct TLS and need no protocol check).

### Options (YAML and *Advanced options* of the profile form)

| Check | Option | Default | Range |
|---|---|---|---|
| `session_resumption` | `attempts` | 2 | 1–3 |
| `session_resumption` | `ticket_wait_seconds` (also used by `session_tickets`) | 2 | 0–10 |
| `early_data` | `ticket_wait_seconds` | 3 | 0–10 |
| `early_data` | `probe` (deep probe, sends an empty line) | `false` | boolean |
| `starttls_*` | `ports` | the standard port | 1 to 16 distinct ports, 1–65535 |

Options are only accepted for the checks that declare them; anything else (a command, a path, an unknown key) is a configuration error.

```yaml
checks:
  tls:
    session_resumption: { enabled: true, attempts: 3 }
    session_tickets: true
    early_data: { enabled: true, probe: false }   # probe: true sends an empty line as early data
    client_auth: true
    starttls_imap: { enabled: true, ports: [143, 1143] }
    starttls_pop3: true
    starttls_ldap: true
    starttls_ftp: true
    starttls_postgres: true
    starttls_xmpp: true
    starttls_xmpp_server: true
```

### Testing and known gaps

Validated on real TLS negotiations against nginx (OpenSSL 3.5), `openssl s_server`, the lab STARTTLS services
(`tests/lab/starttls_server.py`: scripted application dialogues, then a real TLS handshake, including the misbehaving variants) **and genuine
daemons**: `tests/regression/real-servers.sh` starts Postfix (SMTP), Dovecot (IMAP, POP3), vsftpd (FTP), OpenLDAP (LDAP), PostgreSQL
and Prosody (XMPP client-to-server and server-to-server) on their standard ports and requires every protocol check to end `PASS` on a TLS
channel negotiated by the adapter, with the other checks run through it. Observed with them, as expected from an external probe:
Dovecot issues tickets but a new connection often lands on another login process, so resumption is reported `refused` (hence the caveat about
other back-ends), and PostgreSQL issues no TLS 1.3 ticket (`session_tickets` stays `INCONCLUSIVE` after the wait). Implicit TLS variants and the
mTLS client-certificate flow are not covered (see `client_auth`).

## Execution and safety

* One endpoint = its checks run one after the other, inside the host worker that scanned it: the existing parallelism limit
  (`scan.workers`) is the only concurrency, and there is no extra process pool.
* Limits (YAML `checks.tls.timeout_seconds`, 1–30, default 10 per connection; `time_budget_seconds`, 10–600, default 120 per
  endpoint). A check that finds the budget exhausted is `NOT_TESTED`. Cancelling a scan stops the remaining checks.
* Only fixed command lines are used (`openssl s_client` argument lists, no shell), with addresses coming from Nmap or validated targets.
* No Heartbleed, ROBOT or CCS injection test (lot 3). The raw-handshake checks work on direct TLS and on every STARTTLS protocol
  whose `starttls_*` check is selected for the port; on a STARTTLS port of an unselected protocol they stay `INCONCLUSIVE` (the service is not speaking TLS yet).
* Connections per endpoint: about 1–3 for most checks, up to 18 for `ecdhe_groups`, 7 for `ffdhe_groups`, up to 9 (+1 raw handshake for `session_tickets`) for the
  shared session probes, 2–3 for 0-RTT, 4 for `client_auth`, 1 for a protocol check. Disabled checks open no connection.
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
    # lot 2 (options and protocols: see above)
    session_resumption: true
    session_tickets: true
    early_data: true
    client_auth: true
    starttls_imap: true
```

A configuration without `checks.tls` runs none of them. An unknown check id or an invalid value is a configuration error (so a typo
cannot silently skip a control). The same parser validates the Standalone YAML and the WebUI profiles.

## Standalone and WebUI

Same engine, same keys, same results. The WebUI selects them in *Policies → Profiles → Complementary TLS checks*, stores them
per endpoint (`run_endpoints.tls_checks`), shows them in the scan detail, the HTML/Markdown reports, the REST results API
(`tls_checks` on each endpoint), the external API/MCP and in comparisons (status changes). The Standalone CLI writes them to the
HTML and Markdown reports only; its terminal table, CSV, findings CSV and CBOM are unchanged.
