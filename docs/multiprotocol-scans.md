# Generic multi-technology scan profiles

Published generic profiles store independent `tls` and `ipsec` sections. The TLS section retains the existing `scan` and `checks` format; the IPsec section retains the existing `ike` format. Existing TLS and IPsec profiles and definitions keep their original format and behavior.

New WebUI scan definitions use a generic profile and independently select TLS and/or IPsec/IKE. Each enabled technology must have a published policy of that same technology. Policy version IDs, generic profile version ID, effective controls, targets and settings are captured in the run snapshot. The worker runs TLS and IKE sequentially under the existing global worker and duration limits. IKE evidence is stored separately from TLS endpoints and is downloadable as `ipsec_html`, `ipsec_md`, and `ipsec_csv` in combined runs.

The nullable `scan_definitions.enabled_controls` column is intentionally left `NULL` on legacy definitions. This lets the planner retain their pre-multiprotocol `control_type` behavior without retroactively enabling a new check. The API rejects profiles or policies whose technologies do not match the selected controls.

At this stage, the generic profile schema accepts the existing TLS and IPsec engines. SSH, service identification, and SNMP/LLDP controls are added with their corresponding engine tickets; a saved setting is never treated as an observation until its engine has executed it.
