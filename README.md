# TLS Scanner

`TLS Scanner` is a Python tool that uses Nmap to scan hosts or IP address
ranges for TLS versions, certificate validity, and cipher suites. It checks
the detected configuration against current security standards and flags weak
or outdated protocols.

## Features

- Scans port 443 for TLS versions, certificate validity, and cipher suites.
- Resolves host FQDNs by default.
- Accepts multiple FQDNs, IP addresses, and subnets in one scan.
- Checks protocol versions, cipher suites, certificate signatures, RSA key
  sizes, and certificate expiration.
- Reports every cipher suite detected by Nmap.
- Displays separate `IP` and `FQDN` columns in the terminal table.
- Optionally exports results with separate `IP` and `FQDN` columns to CSV.

## Requirements

- Python 3
- Nmap
- The Python packages listed below

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
python3 Scan_nmap_TLS3.py [-i] <targets> [csv_filename]
```

- `<targets>`: Comma-separated FQDNs, IP addresses, or subnets.
- `[csv_filename]`: Optional output filename for exporting the results to CSV.
- `-i`, `--ip`: Disable DNS resolution. The terminal and CSV `FQDN` columns
  remain empty. DNS resolution is enabled by default.

The terminal table and CSV export always contain separate `IP` and `FQDN`
columns. The `FQDN` field is empty when reverse DNS resolution is disabled or
not available.

## Compliance Policy

A result is marked `KO` when at least one of these conditions is detected:

- TLS 1.0, TLS 1.1, or an unknown TLS version.
- MD5 or SHA-1 in the cipher suite or certificate signature.
- Weak or obsolete cipher components: `NULL`, `EXPORT`, `RC4`, `DES`,
  `3DES`, or `IDEA`.
- A non-authenticated encryption mode such as CBC.
- TLS 1.2 without ephemeral `ECDHE` or `DHE` key exchange.
- An RSA certificate key smaller than 3072 bits, or an RSA key whose size
  cannot be determined.
- An expired certificate or an unreadable expiration date.

Accepted cipher suites use authenticated encryption such as AES-GCM, AES-CCM,
or ChaCha20-Poly1305. TLS 1.2 also requires an ephemeral key exchange. TLS 1.3
provides ephemeral key exchange independently of the cipher suite name.

The RSA threshold follows the ANSSI recommendation of at least 3072 bits.
ANSSI still defines 2048 bits as the minimum for uses ending no later than
December 31, 2030, but recommends 3072 bits even before that date. See the
[ANSSI cryptographic mechanisms guide, version 3.00](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf).

## Examples

Scan multiple subnets:

```bash
python3 Scan_nmap_TLS3.py 192.168.1.0/24,10.0.0.0/24
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
