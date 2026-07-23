"""CSV export builder."""


def build_csv_export(results, args, scan_timestamp):
    headers = [
        "IP",
        "FQDN",
        "Port",
        "TLS Grade" if args.crypto == "pqc" else "Grade",
        "TLS Version",
        "Cipher Suite",
        "Public Key",
        "Certificate Validity",
    ]
    if args.crypto == "pqc":
        headers.append("Key Exchange")
    headers.extend(
        [
            "Compliance",
            "Reason",
            "Scan Timestamp",
            "Scan Targets",
            "Port Selection",
            "Crypto Profile",
            "DNS Resolution",
        ]
    )

    scan_metadata = [
        scan_timestamp,
        args.targets,
        str(args.ports),
        args.crypto,
        "disabled" if args.ip else "enabled",
    ]
    rows = [list(row) + scan_metadata for row in results]
    return headers, rows
