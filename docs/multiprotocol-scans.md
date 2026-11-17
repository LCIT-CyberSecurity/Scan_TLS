# Generic multi-technology scan profiles

Published generic profiles store independent `tls`, `ipsec`, and `ssh` sections. The TLS section retains the existing `scan` and `checks` format; the IPsec section retains the existing `ike` format; SSH settings bound TCP ports, per-port timeout, at most one timeout retry, quick/deep preset, and maximum target count. Existing TLS and IPsec profiles and definitions keep their original format and behavior.

New WebUI scan definitions use a generic profile and independently select TLS, IPsec/IKE, and SSH. TLS and IPsec/IKE are on by default for a new definition; SSH is off. Each enabled technology must have a published policy of that same technology. Policy version IDs, generic profile version ID, effective controls, targets and settings are captured in the run snapshot. The worker runs enabled engines sequentially under the existing global worker and duration limits. IKE and SSH evidence are stored separately from TLS endpoints and each has its own HTML, Markdown, and CSV report formats (`ipsec_*`, `ssh_*`).

SSH uses Debian's `ssh-audit` package with unauthenticated protocol inspection only. The quick preset checks the first configured port; deep checks all configured ports. Each probe has a 1–5 second timeout, and the number of expanded targets is capped. No passwords, keys, authentication attempts, DHEat, or rate tests are used. SSH policy results compare observed protocol and algorithm offers; missing observations and missing RSA key-size evidence remain indeterminate.

The nullable `scan_definitions.enabled_controls` column is intentionally left `NULL` on legacy definitions. This lets the planner retain their pre-multiprotocol `control_type` behavior without retroactively enabling a new check. The API rejects profiles or policies whose technologies do not match the selected controls.

Service identification and SNMP/LLDP remain separate optional controls for their corresponding engine tickets; a saved setting is never treated as an observation until its engine has executed it.
