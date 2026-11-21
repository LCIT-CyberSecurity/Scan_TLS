# Generic multi-technology scan profiles

Published generic profiles store independent `tls`, `ipsec`, and `ssh` sections and may include bounded `service_identification` settings. The TLS section retains the existing `scan` and `checks` format; the IPsec section retains the existing `ike` format; SSH settings bound TCP ports, per-port timeout, at most one timeout retry, quick/deep preset, and maximum target count. Existing TLS and IPsec profiles and definitions keep their original format and behavior.

New WebUI scan definitions use a generic profile and independently select TLS, IPsec/IKE, and SSH. TLS and IPsec/IKE are on by default for a new definition; SSH is off. Each enabled technology must have a published policy of that same technology. Policy version IDs, generic profile version ID, effective controls, targets and settings are captured in the run snapshot. The worker runs enabled engines sequentially under the existing global worker and duration limits. IKE and SSH evidence are stored separately from TLS endpoints and each has its own HTML, Markdown, and CSV report formats (`ipsec_*`, `ssh_*`).

Two built-in references are seeded at start, published, like *ANSSI* and *Standard*: created once, never overwritten,
editable and versioned afterwards.

- **Standard (TLS, IPsec, SSH)**, a generic profile. Its TLS section is the *Standard* profile; IPsec uses IKEv2 on UDP
  500/4500; SSH runs a quick audit of TCP 22, 2 s timeout, 256 targets at most. Tick the technologies in each definition.
- **ANSSI SSH**, an SSH policy (`config/encryption_policy/anssi_ssh_encryption_policy.yaml`). It is the SSH counterpart
  of the *ANSSI* TLS policy, built from the ANSSI recommendations (ANSSI-BP-007 for OpenSSH and the cryptographic algorithm
  selection guide): SSHv2 only; SHA-2 only (no SHA-1, MD5 or UMAC); AES-GCM, ChaCha20-Poly1305 or AES-CTR (no CBC, 3DES,
  RC4); ECDH on NIST P-256/384/521 or Diffie-Hellman of at least 2048 bits; ECDSA or RSA-SHA2 host keys, RSA of at least
  2048 bits as in the TLS policy (no DSA). The `ext-info-s` and `kex-strict-s-v00@openssh.com` entries are protocol
  markers, not algorithms. Algorithms outside these recommendations (X25519, Ed25519, the post-quantum hybrids ML-KEM /
  sntrup761) are not allowed: an organisation that accepts them edits the policy and publishes a new version.

A default OpenSSH 10 offers X25519 and ML-KEM key exchange, an Ed25519 host key and SHA-1 / UMAC MACs, so it is reported
**non-compliant**. An `sshd_config` that complies (then remove the Ed25519 `HostKey`):

```
KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
```

To combine TLS and SSH in a definition: tick both technologies, choose *Standard (TLS, IPsec, SSH)* and select *ANSSI*
(TLS) and *ANSSI SSH* (SSH). IPsec additionally needs a published IPsec policy.

SSH uses Debian's `ssh-audit` package with unauthenticated protocol inspection only. The quick preset checks the first configured port; deep checks all configured ports. Each probe has a 1–5 second timeout, and the number of expanded targets is capped. No passwords, keys, authentication attempts, DHEat, or rate tests are used. SSH policy results compare observed protocol and algorithm offers; missing observations and missing RSA key-size evidence remain indeterminate. A port where no SSH server answers (closed, filtered, unreachable, or another protocol that sends no SSH banner) is not reported at all; a DNS failure or an unexpected ssh-audit output is reported as `error`.

The nullable `scan_definitions.enabled_controls` column is intentionally left `NULL` on legacy definitions. This lets the planner retain their pre-multiprotocol `control_type` behavior without retroactively enabling a new check. The API rejects profiles or policies whose technologies do not match the selected controls.

Service identification is an independent scan option, off by default, and can be enabled without publishing a profile change. It uses Nmap `-sV` with light probes by default and an optional detailed intensity. With TLS enabled, it consumes only the open TCP ports discovered during that scan; on non-TLS scans, it stays within the scan profile's port scope. Targets, services, parallelism and total duration are bounded, and no NSE scripts or CVE inference are used.

Service observations (including source, confidence, state and scan time) are stored with the run and shown separately from TLS grades. They can be included as a CSV report when CSV export is enabled. The network-map host panel shows the most recent service observations independently of the latest TLS run, so disabling this option on a later run does not erase older evidence. The map does not infer topology from service banners. SNMP/LLDP remains a separate optional discovery workflow.

## SSH findings

SSH policy violations are also stored as run **findings** (category `SSH`), so they appear in the run's findings, the
dashboard, evolution, comparisons and *new non-compliance* notifications. Each affected server is listed as
`<target>:<port>/tcp`, and the evidence names the offending offers. TLS grades and endpoint counts are unchanged.

| Finding | Severity | Raised when the server offers… |
|---|---|---|
| `SSH_WEAK_KEX`, `SSH_WEAK_CIPHER`, `SSH_WEAK_MAC`, `SSH_WEAK_HOST_KEY`, `SSH_WEAK_PROTOCOL` | high | an offer outside the policy that is weak in itself: SHA-1, MD5, CBC, 3DES, RC4, Blowfish, CAST, DSA, `ssh-rsa` (SHA-1 signature), 64-bit or truncated MACs, `none`, SSHv1 |
| `SSH_KEX_NOT_ALLOWED`, `SSH_CIPHER_NOT_ALLOWED`, `SSH_MAC_NOT_ALLOWED`, `SSH_HOST_KEY_NOT_ALLOWED`, `SSH_PROTOCOL_NOT_ALLOWED` | medium | a strong offer the policy does not list (for example X25519 or Ed25519 under *ANSSI SSH*) |
| `SSH_RSA_KEY_TOO_SHORT` | high | an RSA host key shorter than the policy's `minimum_rsa_bits` |

An indeterminate observation raises no finding. A comparison reports an SSH finding as fixed only when that server
answered again in the newer run. Scans run before this change are not recalculated.
