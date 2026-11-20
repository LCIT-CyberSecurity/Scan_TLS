# Generic multi-technology scan profiles

Published generic profiles store independent `tls`, `ipsec`, and `ssh` sections and may include bounded `service_identification` settings. The TLS section retains the existing `scan` and `checks` format; the IPsec section retains the existing `ike` format; SSH settings bound TCP ports, per-port timeout, at most one timeout retry, quick/deep preset, and maximum target count. Existing TLS and IPsec profiles and definitions keep their original format and behavior.

New WebUI scan definitions use a generic profile and independently select TLS, IPsec/IKE, and SSH. TLS and IPsec/IKE are on by default for a new definition; SSH is off. Each enabled technology must have a published policy of that same technology. Policy version IDs, generic profile version ID, effective controls, targets and settings are captured in the run snapshot. The worker runs enabled engines sequentially under the existing global worker and duration limits. IKE and SSH evidence are stored separately from TLS endpoints and each has its own HTML, Markdown, and CSV report formats (`ipsec_*`, `ssh_*`).

Two built-in references are seeded at start, published, like *ANSSI* and *Standard*: created once, never overwritten,
editable and versioned afterwards.

- **Standard (TLS, IPsec, SSH)**, a generic profile. Its TLS section is the *Standard* profile; IPsec uses IKEv2 on UDP
  500/4500; SSH runs a quick audit of TCP 22, 2 s timeout, 256 targets at most. Tick the technologies in each definition.
- **SSH Baseline**, an SSH policy (`config/encryption_policy/ssh_baseline_policy.yaml`). It follows the ANSSI-BP-007
  principles (SSHv2 only, no SHA-1, CBC or 3DES, strong key exchange, RSA ≥ 2048 bits), updated with the current
  OpenSSH algorithms: hybrid post-quantum ML-KEM / sntrup761 and X25519 key exchange, Ed25519 and ECDSA / RSA-SHA2 host
  keys, ChaCha20-Poly1305, AES-GCM and AES-CTR, and SHA-2 / UMAC-128 MACs. The `ext-info-s` and
  `kex-strict-s-v00@openssh.com` entries are protocol markers, not algorithms. A default OpenSSH 10 still offers
  `hmac-sha1` and `umac-64` MACs, so it is reported **non-compliant** until its `MACs` setting is hardened.

To combine TLS and SSH in a definition: tick both technologies, choose *Standard (TLS, IPsec, SSH)* and select *ANSSI*
(TLS) and *SSH Baseline* (SSH). IPsec additionally needs a published IPsec policy.

SSH uses Debian's `ssh-audit` package with unauthenticated protocol inspection only. The quick preset checks the first configured port; deep checks all configured ports. Each probe has a 1–5 second timeout, and the number of expanded targets is capped. No passwords, keys, authentication attempts, DHEat, or rate tests are used. SSH policy results compare observed protocol and algorithm offers; missing observations and missing RSA key-size evidence remain indeterminate.

The nullable `scan_definitions.enabled_controls` column is intentionally left `NULL` on legacy definitions. This lets the planner retain their pre-multiprotocol `control_type` behavior without retroactively enabling a new check. The API rejects profiles or policies whose technologies do not match the selected controls.

Service identification is an independent scan option, off by default, and can be enabled without publishing a profile change. It uses Nmap `-sV` with light probes by default and an optional detailed intensity. With TLS enabled, it consumes only the open TCP ports discovered during that scan; on non-TLS scans, it stays within the scan profile's port scope. Targets, services, parallelism and total duration are bounded, and no NSE scripts or CVE inference are used.

Service observations (including source, confidence, state and scan time) are stored with the run and shown separately from TLS grades. They can be included as a CSV report when CSV export is enabled. The network-map host panel shows the most recent service observations independently of the latest TLS run, so disabling this option on a later run does not erase older evidence. The map does not infer topology from service banners. SNMP/LLDP remains a separate optional discovery workflow.
