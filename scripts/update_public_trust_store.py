#!/usr/bin/env python3
"""Update TLS Scan's embedded public Web PKI snapshot from local certifi."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import certifi
except ImportError as error:
    raise SystemExit("certifi is required to update the public trust store snapshot") from error

from cryptography import x509

PEM_CERTIFICATE_RE = re.compile(
    b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
ROOT = Path(__file__).resolve().parents[1]
PUBLIC_STORE = ROOT / "tls_scanner" / "truststores" / "public_roots.pem"
PUBLIC_METADATA = ROOT / "tls_scanner" / "truststores" / "public_roots_metadata.json"


def load_certificates(data: bytes) -> list[x509.Certificate]:
    certificates = []
    for block in PEM_CERTIFICATE_RE.findall(data):
        certificates.append(x509.load_pem_x509_certificate(block))
    if not certificates:
        raise ValueError("certifi bundle contains no usable PEM certificates")
    return certificates


def main() -> int:
    source = Path(certifi.where())
    data = source.read_bytes()
    certificates = load_certificates(data)
    PUBLIC_STORE.parent.mkdir(parents=True, exist_ok=True)
    PUBLIC_STORE.write_bytes(data if data.endswith(b"\n") else data + b"\n")
    stored = PUBLIC_STORE.read_bytes()
    metadata = {
        "name": "TLS Scan Public Web PKI",
        "source": "Mozilla-derived public trust store",
        "source_package": "certifi",
        "source_version": certifi.__version__,
        "updated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "sha256": hashlib.sha256(stored).hexdigest(),
        "certificate_count": len(certificates),
    }
    PUBLIC_METADATA.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Updated {PUBLIC_STORE}")
    print(f"certifi {certifi.__version__} from {source}")
    print(f"certificates: {len(certificates)}")
    print(f"sha256: {metadata['sha256']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"Unable to update public trust store: {error}", file=sys.stderr)
        raise SystemExit(1)
