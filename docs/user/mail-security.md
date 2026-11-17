# Mail security checks

Mail security checks are an optional, read-only addition to a TLS scan. They are disabled by default and do not alter the published scan profile or the TLS grade. When enabled, select one or more checks in the scan definition under **Additional checks**.

The checks run only for explicitly selected FQDN targets. IP addresses and CIDR ranges are never converted into mail domains. At most 25 domains and 20 DKIM selectors are processed per run. No SMTP connection is opened and no message is sent. DNS lookups are bounded and cached during a domain check; MTA-STS uses one verified HTTPS request with redirects blocked, public-address-only resolution, a three-second timeout and a 16 KiB policy body limit.

| Check | Observation |
| --- | --- |
| SPF | Looks for one `v=spf1` TXT record, validates supported mechanisms and follows `include` / `redirect` within the RFC limit of ten DNS lookups. It does not prove that a specific sender is authorised. |
| DMARC | Checks the `_dmarc` TXT policy, including `p`, `sp`, `pct`, `adkim` and `aspf`. `p=none` or partial enforcement is shown as a warning. `rua`/`ruf` destinations do not prove that reports arrive. |
| DKIM | Checks only selectors entered by the operator. DNS cannot enumerate selectors exhaustively. Without a selector, the result is **not evaluated**. Public key presence is not a signature check; a signed message is required to validate a signature. |
| MTA-STS | Checks the `_mta-sts` TXT record and fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt`. The HTTPS certificate is verified; redirects, non-public addresses and oversized responses are rejected. The published MX patterns are compared with observed MX records. |
| TLS-RPT | Checks `_smtp._tls` syntax and report destinations. It does not verify receipt of reports. |
| DANE / TLSA | Queries TLSA only for observed MX hosts. Results are evaluated only when the recursive resolver sets the DNSSEC authenticated-data bit; certificate-to-record matching is not actively tested. Missing or unvalidated data is not treated as non-compliant. |

Each result records the domain, observation time, DNS evidence, provenance and one of **compliant**, **non-compliant**, **warning**, **not evaluated** or **error**. Results are kept in scan history, shown separately from TLS results and included in HTML/Markdown reports. A separate mail-security CSV is generated when CSV export is enabled.

Existing scan definitions and runs remain unchanged unless an operator edits a definition and explicitly enables the module. The first four controls (SPF, DMARC, MTA-STS and TLS-RPT) are preselected inside the collapsed, disabled module; DKIM and DANE are opt-in.
