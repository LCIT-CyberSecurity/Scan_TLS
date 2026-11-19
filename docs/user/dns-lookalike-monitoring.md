# DNS lookalike monitoring

Lookalike monitoring is an optional, administrator-managed feature inside **Targets → DNS discoveries**. It proposes typo-style variants of an authorised public reference domain and records passive DNS and optional Certificate Transparency observations. It never establishes malicious intent and never adds proposed names to Targets, scan definitions, groups, or network maps.

## Enable a domain

1. Sign in as an administrator and open **Targets → DNS discoveries**.
2. Enter one public reference domain, for example `example.org`. Internal names and private suffixes are rejected.
3. Review the TLD suffixes, exclusion list, candidate limit, similarity threshold and concurrency. The engine caps candidates at 200, concurrency at 10 and DNS timeouts at 10 seconds.
4. Check the authorisation confirmation. Leave **Enable and schedule immediately** unchecked to save a paused monitor. When checked, the monitor uses the existing DNS scheduler (daily, weekly or monthly at 03:00 UTC).
5. CT queries and notifications each have a separate opt-in. CT queries are limited to five candidates per run and can also be disabled by the administrator. To receive alerts, enable lookalike alerts here and select **New lookalike domain observed** in Preferences.

Monitoring is off for all existing installations, users, domains and schedules. Creating a paused monitor does not generate candidates or external queries. Enabling or manually running it queues work for the existing DNS worker; pausing disables future runs, and queued work rechecks the monitor before doing any lookup. Deletion is soft: it stops future work while retaining its history.

## Read results

Each run stores a timestamped snapshot and compares it with the previous run. The DNS observations distinguish resolved, not observed, inconclusive, error and wildcard responses. CT observations are reported separately. `new`, `changed`, `known` and `not_observed` describe differences between snapshots; a missing answer is never treated as domain deletion. Wildcard DNS answers are marked for manual review.

An observation means only that a public source returned data. It does not prove registration, control, compromise or malicious intent. A candidate marked for review is not a confirmed threat. Review the source, timestamp, record evidence and similarity before taking action. Domains are not imported into the scan inventory: third-party lookalikes are not authorised scan endpoints.

## Sources and limits

- Candidate generation uses bounded one-edit variants (missing, repeated, transposed and adjacent keyboard characters), selected digit substitutions, hyphen insertion, IDNA/punycode homoglyphs and explicitly configured alternate TLDs. The small, established `idna` Python package is used in strict mode instead of a broad fuzzy-domain library; candidates remain capped and deterministic.
- DNS is queried through the worker resolver. A random sibling name is used as a wildcard probe. DNS answers are bounded to eight values per record type.
- CT is queried only when explicitly enabled and permitted by the administrator. External lookups send only the public candidate domain, do not follow redirects and are subject to provider availability and rate limits.
- RDAP lookup is currently not connected. The UI and results report RDAP as `not_checked`; registration is never inferred from DNS or CT.
- There is no HTTP/SMTP connection, port scan, fingerprinting, brute force, registration or modification of third-party domains.

## Troubleshooting and disable

A failed scheduled run appears in monitor history. Check the application and worker logs for the discovery ID, DNS resolver reachability and current administrator CT setting. Provider errors are recorded by type without exposing remote response content. If the worker was offline, use **Run** after it returns. To stop monitoring immediately, choose **Pause**; the worker checks enabled state before starting queued work. Remove the monitor only when its retained history is no longer needed.
