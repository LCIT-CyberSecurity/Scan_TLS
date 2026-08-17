"""
PKI trust-store loading, peer chain collection, and local X.509 validation.

The scan path never downloads CA material and validates only against trust-store
snapshots already available on disk.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa

from .models import (
    CertificateRevocationResult,
    CertificateTrustResult,
    ConfigError,
    LoadedTrustStore,
    TrustStoreConfig,
    TrustStoreValidation,
)

PUBLIC_TRUST_STORE_NAME = "TLS Scan Public Web PKI"
PUBLIC_TRUST_STORE_DESCRIPTION = "Mozilla-derived public trust store"
PUBLIC_TRUST_STORE_ID = "public-web-pki"
PUBLIC_TRUST_STORE_PATH = Path(__file__).resolve().parent / "truststores" / "public_roots.pem"
PUBLIC_TRUST_STORE_METADATA_PATH = Path(__file__).resolve().parent / "truststores" / "public_roots_metadata.json"

TRUST_PUBLIC = "PUBLIC_TRUSTED"
TRUST_PRIVATE = "PRIVATE_TRUSTED"
TRUST_UNTRUSTED = "UNTRUSTED"
TRUST_NOT_TESTED = "NOT_TESTED"
TRUST_ERROR = "ERROR"

STATUS_TRUSTED = "trusted"
STATUS_UNTRUSTED = "untrusted"
STATUS_ERROR = "error"
STATUS_NOT_TESTED = "not_tested"

PEM_CERTIFICATE_RE = re.compile(
    b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)

SMTP_STARTTLS_PORTS = {25, 587}


@dataclass(frozen=True)
class PeerCertificateChain:
    certificates: tuple[x509.Certificate, ...]
    status: str = "ok"
    error: str = ""


def trust_result_not_tested(reason: str = "") -> CertificateTrustResult:
    return CertificateTrustResult(
        trust_classification=TRUST_NOT_TESTED,
        chain_validation_status="Not Tested",
        trust_store_results=(
            TrustStoreValidation(
                store_id="none",
                store_name="Trust validation",
                store_type="none",
                status=STATUS_NOT_TESTED,
                validation_error=reason,
            ),
        ) if reason else (),
    )


def trust_result_error(reason: str) -> CertificateTrustResult:
    return CertificateTrustResult(
        trust_classification=TRUST_ERROR,
        chain_validation_status="Error",
        trust_store_results=(
            TrustStoreValidation(
                store_id="chain-collection",
                store_name="Certificate chain collection",
                store_type="network",
                status=STATUS_ERROR,
                validation_error=reason,
            ),
        ),
    )


def certificate_subject(certificate: x509.Certificate) -> str:
    return certificate.subject.rfc4514_string()


def certificate_fingerprint(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


def load_pem_certificates(data: bytes, source: str) -> tuple[x509.Certificate, ...]:
    certificates = []
    seen = set()
    for block in PEM_CERTIFICATE_RE.findall(data):
        try:
            certificate = x509.load_pem_x509_certificate(block)
        except ValueError as error:
            raise ConfigError(f"invalid certificate in trust store {source}: {error}") from error
        fingerprint = certificate_fingerprint(certificate)
        if fingerprint not in seen:
            seen.add(fingerprint)
            certificates.append(certificate)
    if not certificates:
        raise ConfigError(f"trust store {source} does not contain any usable PEM certificate")
    return tuple(certificates)


def read_file_bytes(path: Path, field_name: str) -> bytes:
    if not path.exists():
        raise ConfigError(f"{field_name} does not exist: {path}")
    if not path.is_file():
        raise ConfigError(f"{field_name} must be a file: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ConfigError(f"unable to read {field_name} {path}: {error}") from error


def load_public_store() -> LoadedTrustStore:
    data = read_file_bytes(PUBLIC_TRUST_STORE_PATH, "public trust store")
    certificates = load_pem_certificates(data, str(PUBLIC_TRUST_STORE_PATH))
    metadata = {
        "name": PUBLIC_TRUST_STORE_NAME,
        "source": PUBLIC_TRUST_STORE_DESCRIPTION,
    }
    if PUBLIC_TRUST_STORE_METADATA_PATH.exists():
        try:
            loaded = json.loads(PUBLIC_TRUST_STORE_METADATA_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                metadata.update(loaded)
        except (OSError, json.JSONDecodeError) as error:
            raise ConfigError(f"unable to read public trust store metadata: {error}") from error
    return LoadedTrustStore(
        store_id=PUBLIC_TRUST_STORE_ID,
        store_name=PUBLIC_TRUST_STORE_NAME,
        store_type="public",
        source=PUBLIC_TRUST_STORE_DESCRIPTION,
        certificates=certificates,
        metadata=metadata,
    )


def store_id_from_name(name: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")
    return normalized or "custom-store"


def load_custom_store(config: TrustStoreConfig) -> LoadedTrustStore:
    path = Path(config.path)
    if config.store_type == "file":
        data = read_file_bytes(path, f"custom trust store {config.name}")
        certificates = load_pem_certificates(data, str(path))
    elif config.store_type == "directory":
        if not path.exists():
            raise ConfigError(f"custom trust store {config.name} directory does not exist: {path}")
        if not path.is_dir():
            raise ConfigError(f"custom trust store {config.name} must be a directory: {path}")
        blocks = []
        try:
            files = sorted(item for item in path.iterdir() if item.is_file())
        except OSError as error:
            raise ConfigError(f"unable to read custom trust store directory {path}: {error}") from error
        for item in files:
            try:
                data = item.read_bytes()
            except OSError as error:
                raise ConfigError(f"unable to read custom trust store file {item}: {error}") from error
            blocks.extend(PEM_CERTIFICATE_RE.findall(data))
        if not blocks:
            raise ConfigError(f"custom trust store {config.name} directory contains no usable PEM certificate")
        certificates = load_pem_certificates(b"\n".join(blocks), str(path))
    else:
        raise ConfigError(f"unknown custom trust store type for {config.name}: {config.store_type}")

    return LoadedTrustStore(
        store_id=f"custom-{store_id_from_name(config.name)}",
        store_name=config.name,
        store_type=config.store_type,
        source="custom",
        certificates=certificates,
        metadata={
            "name": config.name,
            "type": config.store_type,
            "certificate_count": len(certificates),
        },
    )


def load_trust_stores(public_enabled: bool, custom_stores: Iterable[TrustStoreConfig]) -> tuple[LoadedTrustStore, ...]:
    stores = []
    seen_names = set()
    if public_enabled:
        stores.append(load_public_store())
        seen_names.add(PUBLIC_TRUST_STORE_NAME.casefold())
    for config in custom_stores:
        key = config.name.casefold()
        if key in seen_names:
            raise ConfigError(f"duplicate trust store name: {config.name}")
        seen_names.add(key)
        stores.append(load_custom_store(config))
    return tuple(stores)


def safe_sni_name(hostname: str) -> str:
    try:
        socket.inet_pton(socket.AF_INET, hostname)
        return ""
    except OSError:
        return hostname if hostname else ""


def starttls_protocol_for_port(port: int | str) -> str:
    try:
        normalized_port = int(port)
    except (TypeError, ValueError):
        return ""
    if normalized_port in SMTP_STARTTLS_PORTS:
        return "smtp"
    return ""


def collect_peer_certificate_chain(host: str, port: int | str, fqdn: str = "", timeout: int = 10) -> PeerCertificateChain:
    if shutil.which("openssl") is None:
        return PeerCertificateChain((), "error", "openssl is required to collect the peer certificate chain")
    endpoint = f"{host}:{port}"
    command = ["openssl", "s_client", "-showcerts", "-connect", endpoint]
    starttls_protocol = starttls_protocol_for_port(port)
    if starttls_protocol:
        command.extend(["-starttls", starttls_protocol])
    server_name = safe_sni_name(fqdn or host)
    if server_name:
        command.extend(["-servername", server_name])
    try:
        result = subprocess.run(
            command,
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return PeerCertificateChain((), "error", str(error))
    output = result.stdout + result.stderr
    blocks = PEM_CERTIFICATE_RE.findall(output)
    if not blocks:
        message = output.decode("utf-8", errors="replace").splitlines()[:1]
        return PeerCertificateChain((), "not_tested", message[0] if message else "no certificate chain presented")
    certificates = []
    for block in blocks:
        try:
            certificates.append(x509.load_pem_x509_certificate(block))
        except ValueError as error:
            return PeerCertificateChain((), "error", f"invalid peer certificate in chain: {error}")
    return PeerCertificateChain(tuple(certificates))


def certificate_to_pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def write_certificates(path: Path, certificates: Iterable[x509.Certificate]) -> None:
    path.write_bytes(b"".join(certificate_to_pem(certificate) for certificate in certificates))


def openssl_verify_chain(chain: tuple[x509.Certificate, ...], store: LoadedTrustStore) -> tuple[bool, str]:
    if shutil.which("openssl") is None:
        return False, "openssl is required to validate certificate chains"
    if not chain:
        return False, "no peer certificate chain available"
    with tempfile.TemporaryDirectory(prefix="tls-scan-pki-") as temp_dir:
        root = Path(temp_dir)
        leaf_path = root / "leaf.pem"
        untrusted_path = root / "untrusted.pem"
        ca_path = root / "ca.pem"
        write_certificates(leaf_path, [chain[0]])
        write_certificates(untrusted_path, chain[1:])
        write_certificates(ca_path, store.certificates)
        command = ["openssl", "verify", "-CAfile", str(ca_path)]
        if len(chain) > 1:
            command.extend(["-untrusted", str(untrusted_path)])
        command.append(str(leaf_path))
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            return False, str(error)
    if result.returncode == 0:
        return True, ""
    error = (result.stderr or result.stdout or "certificate chain validation failed").strip()
    return False, error.splitlines()[-1] if error else "certificate chain validation failed"


def verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    public_key = issuer.public_key()
    signature_hash = child.signature_hash_algorithm
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), signature_hash)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(signature_hash))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(child.signature, child.tbs_certificate_bytes)
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def find_trust_anchor(chain: tuple[x509.Certificate, ...], store: LoadedTrustStore) -> x509.Certificate | None:
    if not chain:
        return None
    last_presented = chain[-1]
    for candidate in store.certificates:
        if certificate_fingerprint(candidate) == certificate_fingerprint(last_presented):
            return candidate
    for candidate in store.certificates:
        if last_presented.issuer == candidate.subject and verify_signature(last_presented, candidate):
            return candidate
    leaf = chain[0]
    for candidate in store.certificates:
        if certificate_fingerprint(candidate) == certificate_fingerprint(leaf):
            return candidate
    return None


def validate_chain_with_store(chain: tuple[x509.Certificate, ...], store: LoadedTrustStore) -> TrustStoreValidation:
    ok, error = openssl_verify_chain(chain, store)
    if not ok:
        return TrustStoreValidation(
            store_id=store.store_id,
            store_name=store.store_name,
            store_type=store.store_type,
            status=STATUS_UNTRUSTED if "openssl is required" not in error else STATUS_ERROR,
            validation_error=error,
        )
    anchor = find_trust_anchor(chain, store)
    verified_length = len(chain) + (0 if anchor and any(certificate_fingerprint(anchor) == certificate_fingerprint(cert) for cert in chain) else 1)
    return TrustStoreValidation(
        store_id=store.store_id,
        store_name=store.store_name,
        store_type=store.store_type,
        status=STATUS_TRUSTED,
        trust_anchor_subject=certificate_subject(anchor) if anchor else "",
        verified_chain_length=verified_length,
    )


def classify_trust(results: tuple[TrustStoreValidation, ...]) -> CertificateTrustResult:
    if not results:
        return trust_result_not_tested()
    trusted = tuple(result for result in results if result.status == STATUS_TRUSTED)
    if trusted:
        public_trusted = any(result.store_type == "public" for result in trusted)
        classification = TRUST_PUBLIC if public_trusted else TRUST_PRIVATE
        chain_status = "Passed"
        trust_anchor = next((result.trust_anchor_subject for result in trusted if result.trust_anchor_subject), "")
        return CertificateTrustResult(
            trust_classification=classification,
            trusted_by=tuple(result.store_name for result in trusted),
            trust_anchor=trust_anchor,
            chain_validation_status=chain_status,
            trust_store_results=results,
        )
    if all(result.status == STATUS_UNTRUSTED for result in results):
        return CertificateTrustResult(
            trust_classification=TRUST_UNTRUSTED,
            chain_validation_status="Failed",
            trust_store_results=results,
        )
    if any(result.status == STATUS_ERROR for result in results):
        return CertificateTrustResult(
            trust_classification=TRUST_ERROR,
            chain_validation_status="Error",
            trust_store_results=results,
        )
    return trust_result_not_tested()


def validate_peer_chain(chain: PeerCertificateChain, stores: tuple[LoadedTrustStore, ...], enabled: bool = True) -> CertificateTrustResult:
    if not enabled:
        return trust_result_not_tested("trust validation disabled")
    if not stores:
        return trust_result_not_tested("no trust store enabled")
    if chain.status == "not_tested":
        return trust_result_not_tested(chain.error)
    if chain.status != "ok" or not chain.certificates:
        return trust_result_error(chain.error or "certificate chain could not be collected")
    return classify_trust(tuple(validate_chain_with_store(chain.certificates, store) for store in stores))


REVOCATION_GOOD = "Good"
REVOCATION_REVOKED = "Revoked"
REVOCATION_UNKNOWN = "Unknown"
REVOCATION_NOT_TESTED = "Not Tested"
REVOCATION_ERROR = "Error"


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def revocation_result_not_tested(reason: str = "") -> CertificateRevocationResult:
    return CertificateRevocationResult(
        revocation_status=REVOCATION_NOT_TESTED,
        ocsp_status=REVOCATION_NOT_TESTED,
        crl_status=REVOCATION_NOT_TESTED,
        details=(reason,) if reason else (),
    )


def extension_value(certificate: x509.Certificate, extension_type):
    try:
        return certificate.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None


def ocsp_urls(certificate: x509.Certificate) -> tuple[str, ...]:
    aia = extension_value(certificate, x509.AuthorityInformationAccess)
    if aia is None:
        return ()
    return tuple(
        str(item.access_location.value)
        for item in aia
        if item.access_method == x509.AuthorityInformationAccessOID.OCSP
    )


def crl_urls(certificate: x509.Certificate) -> tuple[str, ...]:
    distribution_points = extension_value(certificate, x509.CRLDistributionPoints)
    if distribution_points is None:
        return ()
    urls = []
    for point in distribution_points:
        if point.full_name is None:
            continue
        urls.extend(str(name.value) for name in point.full_name if isinstance(name, x509.UniformResourceIdentifier))
    return tuple(urls)


def validate_revocation_url(url: str, allow_private_urls: bool = False) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("revocation URL must use http or https and include a hostname")
    if allow_private_urls:
        return url
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise ValueError(f"unable to resolve revocation URL host: {error}") from error
    for item in addresses:
        address = ipaddress.ip_address(item[4][0])
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved:
            raise ValueError("revocation URL resolves to a private or local address")
    return url


def fetch_url(url: str, timeout: int, max_response_bytes: int, allow_private_urls: bool = False, data: bytes | None = None, headers: dict[str, str] | None = None) -> bytes:
    validate_revocation_url(url, allow_private_urls)
    request = Request(url, data=data, headers=headers or {})
    opener = build_opener(NoRedirectHandler)
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(max_response_bytes + 1)
    except HTTPError as error:
        raise ValueError(f"HTTP {error.code} from revocation URL") from error
    except URLError as error:
        raise ValueError(f"revocation URL fetch failed: {error.reason}") from error
    except OSError as error:
        raise ValueError(f"revocation URL fetch failed: {error}") from error
    if len(payload) > max_response_bytes:
        raise ValueError("revocation response exceeds configured size limit")
    return payload


def verify_tbs_signature(signature: bytes, tbs_bytes: bytes, public_key, signature_hash) -> bool:
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, tbs_bytes, padding.PKCS1v15(), signature_hash)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, tbs_bytes, ec.ECDSA(signature_hash))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, tbs_bytes)
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def public_key_identifier(public_key) -> bytes:
    return x509.SubjectKeyIdentifier.from_public_key(public_key).digest


def verify_ocsp_response_signature(response: ocsp.OCSPResponse, issuer: x509.Certificate) -> bool:
    if response.responder_name == issuer.subject or response.responder_key_hash == public_key_identifier(issuer.public_key()):
        return verify_tbs_signature(response.signature, response.tbs_response_bytes, issuer.public_key(), response.signature_hash_algorithm)
    for responder_cert in response.certificates:
        eku = extension_value(responder_cert, x509.ExtendedKeyUsage)
        if eku is None or x509.ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
            continue
        if responder_cert.issuer == issuer.subject and verify_signature(responder_cert, issuer):
            return verify_tbs_signature(response.signature, response.tbs_response_bytes, responder_cert.public_key(), response.signature_hash_algorithm)
    return False


def time_is_stale(next_update: datetime | None) -> bool:
    if next_update is None:
        return False
    if next_update.tzinfo is None:
        next_update = next_update.replace(tzinfo=timezone.utc)
    return next_update < datetime.now(timezone.utc)


def check_ocsp_revocation(leaf: x509.Certificate, issuer: x509.Certificate, timeout: int, max_response_bytes: int, allow_private_urls: bool = False) -> tuple[str, str]:
    urls = ocsp_urls(leaf)
    if not urls:
        return REVOCATION_NOT_TESTED, "no OCSP responder URL in certificate"
    request = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1()).build()
    request_data = request.public_bytes(serialization.Encoding.DER)
    errors = []
    for url in urls:
        try:
            data = fetch_url(
                url,
                timeout,
                max_response_bytes,
                allow_private_urls,
                data=request_data,
                headers={"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"},
            )
            response = ocsp.load_der_ocsp_response(data)
            if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                errors.append(f"{url}: OCSP responder returned {response.response_status.name}")
                continue
            if response.serial_number != leaf.serial_number:
                errors.append(f"{url}: OCSP response serial does not match certificate")
                continue
            if time_is_stale(response.next_update):
                errors.append(f"{url}: OCSP response is stale")
                continue
            if not verify_ocsp_response_signature(response, issuer):
                errors.append(f"{url}: OCSP response signature could not be verified")
                continue
            if response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                return REVOCATION_REVOKED, f"OCSP responder reports certificate revoked via {url}"
            if response.certificate_status == ocsp.OCSPCertStatus.GOOD:
                return REVOCATION_GOOD, f"OCSP responder reports certificate good via {url}"
            return REVOCATION_UNKNOWN, f"OCSP responder returned unknown status via {url}"
        except ValueError as error:
            errors.append(f"{url}: {error}")
    return REVOCATION_ERROR, "; ".join(errors) if errors else "OCSP check failed"


def load_crl(data: bytes) -> x509.CertificateRevocationList:
    try:
        return x509.load_der_x509_crl(data)
    except ValueError:
        return x509.load_pem_x509_crl(data)


def check_crl_revocation(leaf: x509.Certificate, issuer: x509.Certificate, timeout: int, max_response_bytes: int, allow_private_urls: bool = False) -> tuple[str, str]:
    urls = crl_urls(leaf)
    if not urls:
        return REVOCATION_NOT_TESTED, "no CRL distribution point URL in certificate"
    errors = []
    for url in urls:
        try:
            crl = load_crl(fetch_url(url, timeout, max_response_bytes, allow_private_urls))
            if crl.issuer != issuer.subject:
                errors.append(f"{url}: CRL issuer does not match certificate issuer")
                continue
            if not verify_tbs_signature(crl.signature, crl.tbs_certlist_bytes, issuer.public_key(), crl.signature_hash_algorithm):
                errors.append(f"{url}: CRL signature could not be verified")
                continue
            if time_is_stale(crl.next_update):
                errors.append(f"{url}: CRL is stale")
                continue
            revoked = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
            if revoked is not None:
                return REVOCATION_REVOKED, f"CRL lists certificate serial as revoked via {url}"
            return REVOCATION_GOOD, f"CRL does not list certificate serial via {url}"
        except ValueError as error:
            errors.append(f"{url}: {error}")
    return REVOCATION_ERROR, "; ".join(errors) if errors else "CRL check failed"


def combine_revocation_status(ocsp_status: str, crl_status: str) -> str:
    statuses = {ocsp_status, crl_status}
    if REVOCATION_REVOKED in statuses:
        return REVOCATION_REVOKED
    tested = statuses - {REVOCATION_NOT_TESTED}
    if not tested:
        return REVOCATION_NOT_TESTED
    if REVOCATION_GOOD in tested:
        return REVOCATION_GOOD
    if REVOCATION_UNKNOWN in tested:
        return REVOCATION_UNKNOWN
    return REVOCATION_ERROR


def validate_certificate_revocation(
    chain: PeerCertificateChain,
    enabled: bool = False,
    ocsp_enabled: bool = True,
    crl_enabled: bool = True,
    timeout_seconds: int = 5,
    max_response_bytes: int = 1048576,
    allow_private_urls: bool = False,
) -> CertificateRevocationResult:
    if not enabled:
        return revocation_result_not_tested("revocation validation disabled")
    if chain.status == "not_tested":
        return revocation_result_not_tested(chain.error)
    if chain.status != "ok" or not chain.certificates:
        return CertificateRevocationResult(revocation_status=REVOCATION_ERROR, details=(chain.error or "certificate chain could not be collected",))
    if len(chain.certificates) < 2:
        return revocation_result_not_tested("issuer certificate not presented by server")
    leaf, issuer = chain.certificates[0], chain.certificates[1]
    ocsp_status, ocsp_detail = (REVOCATION_NOT_TESTED, "OCSP check disabled")
    crl_status, crl_detail = (REVOCATION_NOT_TESTED, "CRL check disabled")
    if ocsp_enabled:
        ocsp_status, ocsp_detail = check_ocsp_revocation(leaf, issuer, timeout_seconds, max_response_bytes, allow_private_urls)
    if crl_enabled:
        crl_status, crl_detail = check_crl_revocation(leaf, issuer, timeout_seconds, max_response_bytes, allow_private_urls)
    return CertificateRevocationResult(
        revocation_status=combine_revocation_status(ocsp_status, crl_status),
        ocsp_status=ocsp_status,
        crl_status=crl_status,
        details=tuple(detail for detail in (ocsp_detail, crl_detail) if detail),
    )


def trust_result_to_report_dict(result: CertificateTrustResult) -> dict[str, object]:
    return {
        "trust_classification": result.trust_classification,
        "trusted_by": list(result.trusted_by),
        "trust_anchor": result.trust_anchor,
        "chain_validation_status": result.chain_validation_status,
        "trust_store_results": [asdict(item) for item in result.trust_store_results],
    }
