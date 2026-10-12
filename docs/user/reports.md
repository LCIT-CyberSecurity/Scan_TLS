# Reports

The existing generators produce the reports unchanged; the WebUI stores them on the `data` volume
(`reports/<definition>_<timestamp>/{html,markdown,csv,cbom,metadata}`) and serves them through the API (role check,
SHA-256 verified, CSP `sandbox`, audit event `report.download`).

When the profile enables the complementary TLS checks, the HTML and Markdown reports gain a **Complementary TLS Checks**
section and the endpoint drawer lists them; CSV, findings CSV and CBOM keep exactly their historical content
([details](tls-checks.md)). Without those checks nothing is added.

Every report states the targets actually checked, date, profile, policy versions, conformity conclusions, errors,
checks not performed and limitations — a control that did not run is never presented as compliant.

**Report templates** (OPERATOR) choose the **export formats** (HTML, Markdown, CSV, CBOM) and brand the **HTML** report:
organisation name on the cover, accent colour, logo (PNG/JPEG/SVG ≤ 150 KB). Branding is applied after the engine
generated the report, before the integrity hash is stored. The report **language** and **sections / detail level** are those
of the engine and cannot be changed yet (see [limitations](../limitations.md)).
