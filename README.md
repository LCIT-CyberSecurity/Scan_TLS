# TLS Scanner

`TLS Scanner` is a Python tool that uses Nmap to scan hosts or IP address
ranges for TLS versions, certificate validity, and cipher suites. It checks
the detected configuration against current security standards and flags weak
or outdated protocols.

## Features

- Scans common TCP ports by default for TLS versions, certificate validity,
  and cipher suites.
- Resolves host FQDNs by default.
- Accepts multiple FQDNs, IP addresses, and subnets in one scan.
- Checks protocol versions, cipher suites, certificate signatures, RSA key
  sizes, and certificate expiration.
- Reports every cipher suite detected by Nmap.
- Supports one or more TCP ports, or automatic discovery of all open TCP
  ports.
- Assigns a grade from `A+` to `F` to each host and port, based on the weakest
  finding for that endpoint.
- Displays an activity bar with elapsed time while Nmap is running.
- Displays separate `IP` and `FQDN` columns in the terminal table.
- Optionally exports results with separate `IP` and `FQDN` columns to CSV.
- Provides an optional PQC profile that actively tests TLS 1.3 hybrid ML-KEM
  key exchange groups.

## Requirements

- Python 3
- Nmap
- The Python packages listed below
- OpenSSL 3.5 or later with TLS ML-KEM support, only when using the `pqc`
  profile

Verify that Python 3 is installed:

```bash
python3 --version
```

Install Nmap by following the instructions on the
[official Nmap website](https://nmap.org/download.html).

Install the required Python packages:

```bash
python3 -m pip install python-nmap prettytable tqdm
```

## Usage

Run the scanner with one or more comma-separated targets:

```bash
python3 Scan_nmap_TLS3.py [-i] [-c {standard,pqc}] [-p PORTS] [-e FILENAME] <targets> [csv_filename]
```

| Parameter | Description |
| --- | --- |
| `<targets>` | Comma-separated FQDNs, IP addresses, or subnets. |
| `[csv_filename]` | Optional CSV output filename. |
| `-e`, `--export` | Export to `.csv` or CycloneDX 1.6 `.cbom.json`. |
| `-p`, `--ports` | Ports to test: one port, a list, ranges, `fast`, or `all`. Default: `fast`. |
| `-c`, `--crypto` | Compliance profile: `standard` or `pqc`. Default: `standard`. |
| `-i`, `--ip` | Disable DNS resolution and leave the `FQDN` column empty. |
| `-h`, `--help` | Display command-line help. |

The terminal table and CSV export always contain separate `IP` and `FQDN`
columns. The `FQDN` field is empty when reverse DNS resolution is disabled or
not available.

The CSV export adds a `Reason` column after `Compliance`. It contains a short
English cause for `KO` results and remains empty for `OK` results. This column
is not displayed in the terminal table.

Use `-e` to select an export format from the filename:

```bash
python3 Scan_nmap_TLS3.py example.com -e results.csv
python3 Scan_nmap_TLS3.py example.com -e results.cbom.json
```

The CBOM export conforms to the CycloneDX 1.6 JSON schema and inventories the
TLS protocols, cipher suites, public keys, and observed PQC key-exchange groups.
The legacy positional CSV filename remains supported.

With `-p fast`, the scanner uses Nmap `-F` to discover approximately the 100
most common TCP ports. With `-p all`, it discovers open TCP ports from `1` to
`65535`. Both modes use Nmap timing option `-T4`, then run the TLS scripts only
on open ports. If `-p` is omitted, `fast` is used for every specified subnet,
IP address, and FQDN. The `all` mode can still take time on large subnets.

The activity bar is indeterminate because `python-nmap` does not expose a
reliable completion percentage while Nmap is running.

## Standard Compliance Policy

A result is marked `KO` when at least one of these conditions is detected:

- TLS 1.0, TLS 1.1, or an unknown TLS version.
- MD5 or SHA-1 in the cipher suite or certificate signature.
- Weak or obsolete cipher components: `NULL`, `EXPORT`, `RC4`, `DES`,
  `3DES`, or `IDEA`.
- An RSA certificate key smaller than 2048 bits, or an RSA key whose size
  cannot be determined.
- An expired certificate or an unreadable expiration date.

Accepted cipher suites use AES-GCM, AES-CCM, ChaCha20-Poly1305, or CBC with
SHA-256/SHA-384. CBC suites using SHA-1 remain `KO`. Static RSA key exchange is
accepted but lowers the endpoint grade to `B` because it does not provide
forward secrecy.

RSA 2048 is accepted by the scanner. See the
[ANSSI cryptographic mechanisms guide, version 3.00](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf)
for the broader recommendations around key sizes.

## Post-Quantum Compliance Policy

Select the post-quantum profile with `-c pqc`. The standard profile remains
the default and its behavior and output are unchanged.

The PQC profile requires OpenSSL 3.5 or later. Before loading Nmap or starting
any network scan, the scanner checks both the OpenSSL version and the actual
availability of a supported TLS ML-KEM group. If either prerequisite is not
met, it prints an English error message and exits with status code `2`.

The following TLS 1.3 hybrid key exchange groups are accepted:

- `X25519MLKEM768` (preferred)
- `SecP256r1MLKEM768`
- `SecP384r1MLKEM1024`

Each group is tested actively with OpenSSL. A PQC row is marked:

- `OK` when TLS 1.3 is used and one of the accepted hybrid groups is
  negotiated;
- `KO` when TLS 1.3 is not used or no accepted hybrid group can be
  negotiated.

The PQC terminal table retains the standard endpoint information, renames
`Grade` to `TLS Grade`, and adds a `Key Exchange` column. `TLS Grade` remains
the standard TLS grade for context; only `Compliance` represents the PQC
verdict. RSA certificate keys remain informational for the PQC verdict because
no RSA key size provides post-quantum security.

Example:

```bash
python3 Scan_nmap_TLS3.py -c pqc -p 443 server.example.com
```

## Endpoint Grade

The `Grade` column is placed between `Port` and `TLS Version`. The weakest
finding detected for a specific host and port determines its grade, which is
repeated on every cipher-suite row for that endpoint. A weak service on one
port does not lower the grade of another port on the same host:

- `A+`: TLS 1.3 is available and no weaker finding is detected.
- `A`: All findings are acceptable, but TLS 1.3 is absent or CBC is enabled.
- `B`: RSA 2048 certificate or static RSA key exchange.
- `C`: SHA-1 or TLS 1.1.
- `D`: MD5, TLS 1.0, DES, 3DES, or IDEA.
- `F`: RC4, `NULL`, `EXPORT`, an expired or unreadable certificate, or an RSA
  key smaller than 2048 bits. Unknown TLS versions are also graded `F`.

This grade is inspired by SSL assessment tools but does not reproduce the
Qualys SSL Labs algorithm.

## Examples

Scan multiple subnets using the default fast port discovery:

```bash
python3 Scan_nmap_TLS3.py 192.168.1.0/24,10.0.0.0/24
```

Scan several TCP ports:

```bash
python3 Scan_nmap_TLS3.py -p 443,8443,9443 192.168.1.0/24
```

Scan a port range and individual ports:

```bash
python3 Scan_nmap_TLS3.py -p 443,8000-8010,8443 server.example.com
```

Quickly discover common TCP ports before testing TLS:

```bash
python3 Scan_nmap_TLS3.py -p fast 192.168.1.0/24
```

Scan standard SMTP and submission ports:

```bash
python3 Scan_nmap_TLS3.py -p 25,465,587 smtp.example.com
```

Discover all open TCP ports before testing TLS:

```bash
python3 Scan_nmap_TLS3.py -p all 192.168.1.10
```

Scan multiple individual IP addresses without subnet notation:

```bash
python3 Scan_nmap_TLS3.py 192.168.1.10,192.168.1.20,10.0.0.5
```

Scan multiple FQDNs:

```bash
python3 Scan_nmap_TLS3.py web.example.com,mail.example.com
```

Scan a mix of subnets, individual IP addresses, and FQDNs, then export the
results:

```bash
python3 Scan_nmap_TLS3.py 192.168.1.0/24,10.0.0.5,web.example.com results.csv
```

Disable DNS resolution and leave the `FQDN` column empty:

```bash
python3 Scan_nmap_TLS3.py -i 192.168.1.0/24,10.0.0.5,web.example.com results.csv
```

Combine fast port discovery, multiple targets, disabled DNS, and CSV export:

```bash
python3 Scan_nmap_TLS3.py -i -p fast 192.168.1.0/24,10.0.0.5 results.csv
```

Display all command-line options:

```bash
python3 Scan_nmap_TLS3.py --help
```
