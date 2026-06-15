# TLS Scanner

`TLS Scanner` is a Python tool that uses Nmap to scan hosts or IP address
ranges for TLS versions, certificate validity, and cipher suites. It checks
the detected configuration against current security standards and flags weak
or outdated protocols.

## Features

- Scans port 443 for TLS versions, certificate validity, and cipher suites.
- Checks TLS protocol and certificate compliance.
- Displays results in a readable table.
- Optionally exports results to a CSV file.

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

Run the scanner with a host or IP address range:

```bash
python3 Scan_nmap_TLS3.py <target> [csv_filename]
```

- `<target>`: IP address or IP address range to scan, such as
  `192.168.1.1` or `192.168.1.0/24`.
- `[csv_filename]`: Optional output filename for exporting the results to CSV.

## Examples

Display the scan results in the terminal:

```bash
python3 Scan_nmap_TLS3.py 192.168.1.1
```

Scan a subnet and export the results:

```bash
python3 Scan_nmap_TLS3.py 192.168.1.0/24 results.csv
```
