# User guide (WebUI)

## Roles (global, not per SI)
| Role | Can |
|---|---|
| AUDITOR | see dashboard, runs, reports; download reports; filter by SI / sub-SI / tag. Nothing else. |
| USER | + create/manage **own** targets, groups, definitions, schedules; launch and cancel own scans; compare runs; consult policies/profiles |
| OPERATOR | + see/cancel/delete every scan, edit any definition/target/schedule, manage policies, profiles, report templates, SI and tags, see failed runs |
| ADMIN | + users and roles, settings (retention, SMTP), audit log, diagnostics |

Everyone signed in can read shared results; only an object's owner (or an operator) can modify it.

## Typical flow
1. **Targets** → *New target*: FQDN, IP or CIDR, optional ports (`443,8443,9000-9010`), description,
   tags, SI/sub-SI. Importing: one `value;ports;description` per line. A target exists once and can be used by any
   number of definitions and groups. SI, sub-SI and tags only help you organise and filter.
2. **Scans → Definitions → New scan**: pick targets/groups, a *technical profile* (how to scan), one or more
   *policies* (what is acceptable; the latest published version is used), a report template, tags and SI.
3. **Run**. The run page shows the current phase (*port discovery*, *TLS analysis*, *evaluating compliance*,
   *generating reports*), elapsed time and — only when reliable — hosts processed. No fake percentage.
4. **Cancel** your own scan any time: unstarted hosts are skipped and listed, results gathered so far are kept
   (*cancelled*, never counted as compliant).
5. **Results**: endpoints with grade/compliance/TLS versions/certificate, findings with evidence and
   remediation, errors, and *checks not performed* (never shown as compliant). Download HTML / Markdown / CSV / CBOM.
6. **Compare with previous**: new / fixed / persistent findings, TLS version, cipher suite and certificate changes.
   A target that was not re-tested is listed as *not re-tested*, **never as fixed**. Warnings tell you when the
   scope, profile or policy versions differ.
7. **Schedules**: once, daily, weekly, monthly, or cron (≥ 5 min). Scheduled scans use the latest published policy
   versions. See next run, last result, and the history (including skipped occurrences and why).

## Equivalent scans are shared
If someone already runs an identical scan (same effective targets/ports, profile, policy versions), your request
attaches to it — you will find the result in *My scans* and get the notification — without extra network load. You
gain no right to modify the other user's definitions or schedules. After it finishes, run again for fresh data.

## Complementary TLS checks
If the profile enables them, the scan detail page has a **Complementary TLS checks** table (identity of the certificate, OCSP
stapling, compression, renegotiation, TLS_FALLBACK_SCSV, Extended Master Secret, ECDHE/FFDHE groups). It is separate from the
findings: these results do not change the grade or the compliance status. `NOT_TESTED` / `INCONCLUSIVE` mean *unknown*, not
*passed*. See [Complementary TLS checks](tls-checks.md).

## Preferences
Language (FR/EN/DE; browser language by default, your choice wins and is stored on your profile), light/dark/system,
palette, e-mail notification events, local password change.

## What "no TLS service" means
A target with no TLS on the scanned ports yields a *completed* run with zero endpoints and an explicit notice. It
is neither an execution error nor a compliance result.

## API and MCP access

Two optional, **read-only** accesses let your own tools consult scan results with the rights of your account: the **external REST API** (`/api/v1`, for scripts and dashboards) and the **MCP server** (`/mcp`, for AI assistants that speak the Model Context Protocol). They never launch or change anything.

* **Is my account allowed?** Open *Preferences → API and MCP access*. For each service you see whether the administrator enabled it, whether **your account** is authorised, and the state of your key. If something is missing the page says so and the *Generate* button stays disabled: ask an administrator (*Administration → Users*). Being an administrator does not grant it automatically.
* **Create a key**: click *Generate a key*. The key is shown **once** in a dialog: click *Copy* and store it in your secret manager. It is valid 90 days; there is one key per service. *Regenerate* replaces it (the old one stops working at once); *Revoke* removes it.
* **Use it**: REST keys start with `tls_scan_pat_`, MCP keys with `tls_scan_mcp_`; they are not interchangeable.
  ```bash
  curl -H "Authorization: Bearer tls_scan_pat_…" https://<server>:<port>/api/v1/scans?limit=5
  ```
  The interactive documentation is at `/api/v1/docs` (while the API is enabled). For MCP, add the server URL `https://<server>:<port>/mcp` and the header `Authorization: Bearer tls_scan_mcp_…` in your MCP client; ask for example *"list the latest scans"* or *"which endpoints of scan <id> are non-compliant?"*.
* **What you can read**: scans, their TLS endpoints, findings, compliance statistics and (USER role or higher) comparisons, exactly as in the WebUI. Role changes apply immediately.
* **Usual messages**: `401 Authentication required` = missing, expired or revoked key, service disabled or account not authorised (generate a new key or ask an administrator); `403` = your role cannot do this (comparison needs USER); `404` = unknown scan; `429` = too many requests, wait a minute.

Details: [external API](../integrations/external-api.md) · [MCP server](../integrations/mcp.md). Targets can also be created from a DNS discovery (see below).

## DNS discovery (OPERATOR and ADMIN)

*Targets → DNS discovery*: enter a domain you are authorised to query and confirm it. TLS Scan looks up the domain's name servers and asks each one, once, for a **zone transfer (AXFR)** of that domain. If a server accepts, the host names (A, AAAA, CNAME) are listed so you can tick the ones to add as targets (grouped under the domain name); an accepted transfer is also reported as a DNS weakness. Refusal is the normal, safe answer: then add names yourself or import a list. Nothing is guessed or brute-forced; loopback, link-local and multicast servers are never queried; each request is audited.

## Several targets at once

In *New target*, the *Targets* field accepts several values (FQDN, IP address or network in CIDR notation, one per line or separated by commas). Each becomes a target; with several values they are gathered in a group named after the label you typed.


See also: [Exclusions](exclusions.md) (what a scan must never touch), [Trust authorities](trust-authorities.md), [DNS discovery](dns-discovery.md).
