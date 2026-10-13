# Reports

The existing generators produce the reports unchanged; the WebUI stores them on the `data` volume
(`reports/<definition>_<timestamp>/{html,markdown,csv,cbom,metadata}`) and serves them through the API (role check,
SHA-256 verified, CSP `sandbox`, audit event `report.download`).

When the profile enables the complementary TLS checks, the HTML and Markdown reports gain a **Complementary TLS Checks**
section and the endpoint drawer lists them; CSV, findings CSV and CBOM keep exactly their historical content
([details](tls-checks.md)). Without those checks nothing is added.

**Extra sections of the WebUI reports** (HTML and Markdown), computed from the stored results and appended after the engine generated the
report (the Standalone reports are unchanged; a section with nothing to say is omitted):

- *Evolution since the previous scan*: new / fixed / persistent / not-retested findings against the previous comparable scan of the same
  scan definition, endpoints added and removed, compliance improved or degraded, new and fixed findings, certificate changes, and a caution
  when the targets, profile or policies differ.
- *Certificates to renew*: certificates expired or expiring within 90 days, once per certificate, with the endpoints that serve them.
- *Trend over the last scans*: occurrences per severity for the last six scans of the definition.
- *Scan scope*: exclusions applied (and where they were defined), targets removed before the scan, hosts skipped.

Every report states the targets actually checked, date, profile, policy versions, conformity conclusions, errors,
checks not performed and limitations — a control that did not run is never presented as compliant.

**Report templates** (OPERATOR) choose the **export formats** (HTML, Markdown, CSV, CBOM) and brand the **HTML** report:
organisation name on the cover, accent colour, logo (PNG/JPEG/SVG ≤ 150 KB). Branding is applied after the engine
generated the report, before the integrity hash is stored. The report **language** and **sections / detail level** are those
of the engine and cannot be changed yet (see [limitations](../limitations.md)).
