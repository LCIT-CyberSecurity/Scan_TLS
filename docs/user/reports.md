# Reports

The existing generators produce the reports unchanged; the WebUI stores them on the `data` volume
(`reports/<definition>_<timestamp>/{html,markdown,csv,cbom,metadata}`) and serves them through the API (role check,
SHA-256 verified, CSP `sandbox`, audit event `report.download`).

Every report states the targets actually checked, date, profile, policy versions, conformity conclusions, errors,
checks not performed and limitations — a control that did not run is never presented as compliant.

**Report templates** (OPERATOR) currently choose the **export formats** (HTML, Markdown, CSV, CBOM). Logo, colours,
language, section selection and detail level are *not* implemented because the existing generators do not support them
(see [limitations](../limitations.md)); no setting is offered that would have no effect.
