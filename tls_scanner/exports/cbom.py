"""CycloneDX CBOM export builder."""

import re
import uuid
from datetime import datetime, timezone

from ..constants import PQC_TLS_GROUPS


def build_cbom(results, pqc=False):
    components = []
    algorithm_refs = {}
    public_key_refs = {}

    def make_ref(value):
        return "crypto:" + str(uuid.uuid5(uuid.NAMESPACE_URL, value))

    def add_algorithm(name, primitive):
        key = (name, primitive)
        if key not in algorithm_refs:
            algorithm_ref = make_ref(f"algorithm:{name}:{primitive}")
            algorithm_refs[key] = algorithm_ref
            components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": algorithm_ref,
                    "name": name,
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {"primitive": primitive},
                    },
                }
            )
        return algorithm_refs[key]

    primitive_by_key_type = {
        "RSA": "pke",
        "ECDSA": "signature",
        "ED25519": "signature",
        "DSA": "signature",
        "ECDH": "key-agree",
    }

    for row in results:
        host, fqdn, port, grade, tls_version, cipher_suite = row[:6]
        public_key, cert_validity = row[6:8]
        key_exchange = row[8] if pqc else None
        compliance_index = 9 if pqc else 8
        compliance = row[compliance_index]
        reason = row[compliance_index + 1]

        crypto_refs = []
        key_match = re.fullmatch(r"(.+?)(?: (\d+) bits)?", public_key)
        if key_match and key_match.group(1) != "Unknown":
            key_type = key_match.group(1)
            key_size = (
                int(key_match.group(2)) if key_match.group(2) is not None else None
            )
            algorithm_ref = add_algorithm(
                key_type,
                primitive_by_key_type.get(key_type, "unknown"),
            )
            public_key_id = (host, port, key_type, key_size)
            if public_key_id not in public_key_refs:
                public_key_ref = make_ref(
                    f"public-key:{host}:{port}:{key_type}:{key_size}"
                )
                public_key_refs[public_key_id] = public_key_ref
                material_properties = {
                    "type": "public-key",
                    "algorithmRef": algorithm_ref,
                }
                if key_size is not None:
                    material_properties["size"] = key_size
                components.append(
                    {
                        "type": "cryptographic-asset",
                        "bom-ref": public_key_ref,
                        "name": f"{key_type} public key on {host}:{port}",
                        "cryptoProperties": {
                            "assetType": "related-crypto-material",
                            "relatedCryptoMaterialProperties": material_properties,
                        },
                    }
                )
            crypto_refs.append(public_key_refs[public_key_id])

        if key_exchange in PQC_TLS_GROUPS:
            upper_exchange = key_exchange.upper()
            primitive = (
                "combiner"
                if "MLKEM" in upper_exchange and "X25519" in upper_exchange
                else "kem"
                if "MLKEM" in upper_exchange
                else "key-agree"
            )
            crypto_refs.append(add_algorithm(key_exchange, primitive))

        properties = [
            {"name": "scan-tls:ip", "value": str(host)},
            {"name": "scan-tls:port", "value": str(port)},
            {"name": "scan-tls:grade", "value": str(grade)},
            {"name": "scan-tls:compliance", "value": str(compliance)},
            {
                "name": "scan-tls:certificate-valid-until",
                "value": str(cert_validity),
            },
        ]
        if fqdn:
            properties.append({"name": "scan-tls:fqdn", "value": str(fqdn)})
        if reason:
            properties.append({"name": "scan-tls:reason", "value": str(reason)})
        if key_exchange:
            properties.append(
                {"name": "scan-tls:key-exchange", "value": str(key_exchange)}
            )

        protocol_properties = {
            "type": "tls",
            "version": tls_version.removeprefix("TLSv"),
            "cipherSuites": [{"name": cipher_suite}],
        }
        if crypto_refs:
            protocol_properties["cryptoRefArray"] = crypto_refs

        protocol_ref = make_ref(
            f"tls:{host}:{port}:{tls_version}:{cipher_suite}"
        )
        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": protocol_ref,
                "name": f"{tls_version} {cipher_suite} on {host}:{port}",
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": protocol_properties,
                },
                "properties": properties,
            }
        )

    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "lifecycles": [{"phase": "discovery"}],
        },
        "components": components,
    }
