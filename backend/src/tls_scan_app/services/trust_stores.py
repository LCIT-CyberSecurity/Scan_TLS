"""Administered trust stores: strict import of public CA certificates, immutable versions, snapshot resolution.

Reuses the engine for everything cryptographic (`tls_scanner.pki`): this module only validates what an
administrator uploads and records it. It never runs a shell command and never uses an uploaded file name
as a path.
"""
from __future__ import annotations

import base64
import copy
import binascii
import hashlib
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from sqlalchemy import Text, cast, func, select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import ScanProfileVersion, ScanRun, TrustStore, TrustStoreCertificate, TrustStoreVersion, User
from tls_scan_app.models.trust import ROLE_ANCHOR, ROLE_INTERMEDIATE
from tls_scanner.pki import (
    PUBLIC_TRUST_STORE_DESCRIPTION, PUBLIC_TRUST_STORE_ID, PUBLIC_TRUST_STORE_NAME, certificate_fingerprint,
    load_public_store, verify_signature,
)

MAX_FILE_BYTES = 512 * 1024
MAX_FILES_PER_IMPORT = 20
MAX_CERTS_PER_FILE = 100
MAX_CERTS_PER_VERSION = 300
EXPIRING_DAYS = 30
NAME_RE = re.compile(r"^[^,\x00-\x1f]{1,120}$")  # no comma: store names are joined with ", " in the reports

_BLOCK_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)
_ANY_BEGIN_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")
_FORBIDDEN_MARKERS = (b"PRIVATE KEY", b"ENCRYPTED", b"PKCS12", b"PFX")


class TrustStoreError(ValueError):
    """An explicit, user-presentable import/validation error."""


def validate_name(name: str) -> str:
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise TrustStoreError("The name must be 1 to 120 characters and must not contain a comma")
    if name.casefold() == PUBLIC_TRUST_STORE_NAME.casefold():
        raise TrustStoreError("This name is reserved for the built-in public store")
    return name


def _key_info(key) -> tuple[str, int | None]:
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC ({key.curve.name})", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    return type(key).__name__, None


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def describe(cert: x509.Certificate) -> dict[str, Any]:
    """Readable facts about a CA certificate (also the stored `details`)."""
    key_type, key_size = _key_info(cert.public_key())
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        basic = {"ca": bc.ca, "path_length": bc.path_length}
    except x509.ExtensionNotFound:
        basic = None
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        usages = [n for n, v in (("digital_signature", ku.digital_signature), ("key_cert_sign", ku.key_cert_sign), ("crl_sign", ku.crl_sign),
                                 ("content_commitment", ku.content_commitment), ("key_encipherment", ku.key_encipherment),
                                 ("data_encipherment", ku.data_encipherment), ("key_agreement", ku.key_agreement)) if v]
    except x509.ExtensionNotFound:
        usages = None
    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else cert.signature_algorithm_oid._name
    except Exception:  # noqa: BLE001 - exotic signature algorithms: display the OID
        sig = cert.signature_algorithm_oid.dotted_string
    return {
        "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": _iso(cert.not_valid_before_utc), "not_after": _iso(cert.not_valid_after_utc),
        "key_type": key_type, "key_size": key_size, "signature_algorithm": sig,
        "basic_constraints": basic, "key_usage": usages,
        "self_issued": cert.subject == cert.issuer,
    }


def classify(cert: x509.Certificate) -> str:
    """Root CA (self-signed, signature verified with its own key) = trust anchor; any other CA only completes chains."""
    if cert.subject == cert.issuer:
        if not verify_signature(cert, cert):
            raise TrustStoreError("Inconsistent certificate: issuer equals subject but the self-signature is invalid")
        return ROLE_ANCHOR
    return ROLE_INTERMEDIATE


def check_ca_certificate(cert: x509.Certificate, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise TrustStoreError("Not a CA certificate: the Basic Constraints extension is missing") from None
    if not bc.ca:
        raise TrustStoreError("Not a CA certificate: Basic Constraints says CA:FALSE")
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.key_cert_sign:
            raise TrustStoreError("This CA certificate cannot sign certificates (Key Usage lacks keyCertSign)")
    except x509.ExtensionNotFound:
        pass
    if cert.not_valid_before_utc >= cert.not_valid_after_utc:
        raise TrustStoreError("Inconsistent validity period (notBefore is not before notAfter)")
    if cert.not_valid_after_utc < now:
        raise TrustStoreError(f"Expired certificate (notAfter {cert.not_valid_after_utc:%Y-%m-%d})")
    if cert.not_valid_before_utc > now:
        raise TrustStoreError(f"Certificate not yet valid (notBefore {cert.not_valid_before_utc:%Y-%m-%d})")


def parse_upload(data: bytes, filename: str = "") -> list[x509.Certificate]:
    """Strict PEM parsing of one uploaded file. The content is inspected, never the extension or the name."""
    label = _safe_label(filename)
    if len(data) > MAX_FILE_BYTES:
        raise TrustStoreError(f"{label}: file too large (maximum {MAX_FILE_BYTES // 1024} KiB)")
    if not data.strip():
        raise TrustStoreError(f"{label}: empty file")
    if any(m in data.upper() for m in _FORBIDDEN_MARKERS):
        raise TrustStoreError(f"{label}: private keys and encrypted/PKCS#12 content are refused; import the public CA certificate only")
    if b"\x00" in data:
        raise TrustStoreError(f"{label}: binary content is not supported (PEM text expected; PKCS#12/PFX and DER are refused)")
    begins = _ANY_BEGIN_RE.findall(data)
    if any(kind != b"CERTIFICATE" for kind in begins):
        raise TrustStoreError(f"{label}: only PEM CERTIFICATE blocks are accepted")
    blocks = _BLOCK_RE.findall(data)
    if not blocks or len(blocks) != len(begins):
        raise TrustStoreError(f"{label}: no valid PEM certificate found (malformed or truncated block)")
    if len(blocks) > MAX_CERTS_PER_FILE:
        raise TrustStoreError(f"{label}: too many certificates in one file (maximum {MAX_CERTS_PER_FILE})")
    certs = []
    for index, (_, body) in enumerate(blocks, 1):
        pem = b"-----BEGIN CERTIFICATE-----" + body + b"-----END CERTIFICATE-----\n"
        try:
            certs.append(x509.load_pem_x509_certificate(pem))
        except ValueError as error:
            raise TrustStoreError(f"{label}: certificate #{index} is not a valid X.509 certificate") from error
    return certs


def _safe_label(filename: str) -> str:
    return re.sub(r"[^\w.\- ]", "_", (filename or "file"))[:60] or "file"


def decode_files(files: list[dict[str, str]]) -> list[tuple[str, bytes]]:
    if not files:
        raise TrustStoreError("No file provided")
    if len(files) > MAX_FILES_PER_IMPORT:
        raise TrustStoreError(f"Too many files (maximum {MAX_FILES_PER_IMPORT})")
    out = []
    for item in files:
        try:
            data = base64.b64decode(item.get("content_b64", ""), validate=True)
        except (binascii.Error, ValueError):
            raise TrustStoreError(f"{_safe_label(item.get('filename', ''))}: invalid encoding") from None
        out.append((item.get("filename", ""), data))
    return out


def inspect_files(files: list[dict[str, str]]) -> dict[str, Any]:
    """Dry run for the import dialog: per file, the readable certificates or the explicit error. Nothing is stored."""
    result, seen = [], set()
    try:
        decoded = decode_files(files)
    except TrustStoreError as error:
        return {"files": [{"filename": "", "error": str(error), "certificates": []}], "valid": False}
    valid = True
    for filename, data in decoded:
        entry: dict[str, Any] = {"filename": _safe_label(filename), "error": None, "certificates": []}
        try:
            for cert in parse_upload(data, filename):
                fp = certificate_fingerprint(cert)
                item = {"fingerprint_sha256": fp, "role": None, "error": None, "duplicate": fp in seen} | describe(cert)
                seen.add(fp)
                try:
                    check_ca_certificate(cert)
                    item["role"] = classify(cert)
                except TrustStoreError as error:
                    item["error"] = str(error)
                    valid = False
                entry["certificates"].append(item)
        except TrustStoreError as error:
            entry["error"] = str(error)
            valid = False
        result.append(entry)
    return {"files": result, "valid": valid}


def certificates_from_files(files: list[dict[str, str]]) -> list[x509.Certificate]:
    """All the certificates of the upload, each validated; an invalid one refuses the whole import. Duplicates are merged."""
    unique: dict[str, x509.Certificate] = {}
    for filename, data in decode_files(files):
        for cert in parse_upload(data, filename):
            try:
                check_ca_certificate(cert)
                classify(cert)
            except TrustStoreError as error:
                raise TrustStoreError(f"{_safe_label(filename)} - {cert.subject.rfc4514_string()[:80]}: {error}") from None
            unique.setdefault(certificate_fingerprint(cert), cert)
    return list(unique.values())


def content_hash(entries: list[tuple[str, str]]) -> str:
    return hashlib.sha256("\n".join(f"{role}:{fp}" for role, fp in sorted(entries)).encode()).hexdigest()


def current_version(db: DbSession, store_id: uuid.UUID) -> TrustStoreVersion | None:
    return db.execute(select(TrustStoreVersion).where(TrustStoreVersion.store_id == store_id)
                      .order_by(TrustStoreVersion.version.desc()).limit(1)).scalar_one_or_none()


def version_certificates(db: DbSession, version_id: uuid.UUID) -> list[TrustStoreCertificate]:
    return list(db.execute(select(TrustStoreCertificate).where(TrustStoreCertificate.version_id == version_id)
                           .order_by(TrustStoreCertificate.role, TrustStoreCertificate.fingerprint_sha256)).scalars())


def create_version(db: DbSession, store: TrustStore, certificates: list[x509.Certificate], user: User, comment: str = "") -> TrustStoreVersion:
    """Publish a new immutable version holding exactly `certificates`. Serialised per store (row lock)."""
    db.execute(select(TrustStore.id).where(TrustStore.id == store.id).with_for_update())
    if len(certificates) > MAX_CERTS_PER_VERSION:
        raise TrustStoreError(f"Too many certificates in a store (maximum {MAX_CERTS_PER_VERSION})")
    roles = [(classify(c), certificate_fingerprint(c)) for c in certificates]
    if not any(role == ROLE_ANCHOR for role, _ in roles):
        raise TrustStoreError("A store needs at least one Root CA (self-signed trust anchor); intermediates alone trust nothing")
    previous = current_version(db, store.id)
    number = (previous.version if previous else 0) + 1
    version = TrustStoreVersion(store_id=store.id, version=number, content_sha256=content_hash(roles), comment=comment[:500], created_by=user.id)
    db.add(version)
    db.flush()
    for cert, (role, fp) in zip(certificates, roles, strict=True):
        db.add(TrustStoreCertificate(version_id=version.id, fingerprint_sha256=fp, role=role,
                                     pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"), details=describe(cert)))
    db.flush()
    return version


def load_certificates(rows: list[TrustStoreCertificate]) -> list[x509.Certificate]:
    return [x509.load_pem_x509_certificate(r.pem.encode("ascii")) for r in rows]


# ---- usage and references ----
def profile_usage(db: DbSession, store_id: uuid.UUID) -> list[dict[str, str]]:
    """Profiles whose latest version (draft or published) selects this store."""
    from tls_scan_app.models import ScanProfile

    out = {}
    for version, profile in db.execute(select(ScanProfileVersion, ScanProfile).join(ScanProfile, ScanProfile.id == ScanProfileVersion.profile_id)).all():
        if str(store_id) in selected_store_ids(version.content):
            out.setdefault(profile.id, {"id": str(profile.id), "name": profile.name, "versions": []})["versions"].append(version.version)
    return list(out.values())


def run_usage_count(db: DbSession, store_id: uuid.UUID) -> int:
    return db.scalar(select(func.count()).select_from(ScanRun).where(cast(ScanRun.config_snapshot, Text).like(f"%{store_id}%"))) or 0


def selected_store_ids(content: dict[str, Any]) -> list[str]:
    trust = ((content.get("checks") or {}).get("certificate") or {}).get("trust") or {}
    ids = trust.get("private_stores") or []
    return [str(i) for i in ids] if isinstance(ids, list) else []


def validate_profile_selection(db: DbSession, content: dict[str, Any]) -> None:
    """A profile may only reference existing, active stores, by technical id."""
    trust = ((content.get("checks") or {}).get("certificate") or {}).get("trust") or {}
    ids = trust.get("private_stores")
    if ids is None:
        return
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids) or len(set(ids)) != len(ids):
        raise TrustStoreError("checks.certificate.trust.private_stores must be a list of distinct store ids")
    if ids and trust.get("enabled", True) is False:
        raise TrustStoreError("Private trust stores need the chain verification to be enabled")
    for raw in ids:
        try:
            store = db.get(TrustStore, uuid.UUID(raw))
        except ValueError:
            raise TrustStoreError(f"Invalid trust store identifier: {raw}") from None
        if store is None:
            raise TrustStoreError(f"Unknown trust store: {raw}")
        if not store.active:
            raise TrustStoreError(f"The trust store '{store.name}' is disabled")


def resolve_for_snapshot(db: DbSession, content_checks: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return (engine checks with the stores inlined, provenance list) pinning the exact versions at launch time."""
    checks = copy.deepcopy(content_checks)
    certificate = checks.get("certificate")
    trust = certificate.get("trust") if isinstance(certificate, dict) else None
    provenance: list[dict[str, Any]] = []
    if not isinstance(trust, dict):
        return checks, provenance
    trust.pop("inline_stores", None)  # only the planner may inline stores
    ids = trust.pop("private_stores", None) or []
    if trust.get("enabled", True) is False:
        return checks, provenance
    inline = []
    for raw in ids:
        store = db.get(TrustStore, uuid.UUID(raw))
        if store is None:
            raise TrustStoreError(f"The trust store {raw} no longer exists")
        if not store.active:
            raise TrustStoreError(f"The trust store '{store.name}' is disabled")
        version = current_version(db, store.id)
        if version is None:
            raise TrustStoreError(f"The trust store '{store.name}' has no version")
        rows = version_certificates(db, version.id)
        anchors = [r for r in rows if r.role == ROLE_ANCHOR]
        if not anchors:
            raise TrustStoreError(f"The trust store '{store.name}' has no Root CA")
        meta = {"store_uuid": str(store.id), "version": version.version, "content_sha256": version.content_sha256,
                "anchors": [r.details["subject"] for r in anchors], "anchor_sha256": [r.fingerprint_sha256 for r in anchors],
                "intermediate_count": len(rows) - len(anchors)}
        inline.append({"store_id": f"managed-{store.id}-v{version.version}", "name": f"{store.name} (v{version.version})",
                       "anchors": [r.pem for r in anchors], "intermediates": [r.pem for r in rows if r.role == ROLE_INTERMEDIATE], "metadata": meta})
        provenance.append({"id": str(store.id), "name": store.name, "version": version.version, "version_id": str(version.id),
                           "content_sha256": version.content_sha256, "anchors": meta["anchors"], "anchor_sha256": meta["anchor_sha256"],
                           "intermediate_count": meta["intermediate_count"]})
    if inline:
        trust["inline_stores"] = inline
    return checks, provenance


def builtin_public() -> dict[str, Any]:
    store = load_public_store()
    return {"id": PUBLIC_TRUST_STORE_ID, "name": PUBLIC_TRUST_STORE_NAME, "description": PUBLIC_TRUST_STORE_DESCRIPTION, "builtin": True,
            "type": "public", "active": True, "certificate_count": len(store.certificates), "version": None,
            "updated_at": store.metadata.get("generated_at") or store.metadata.get("updated_at")}


def public_snapshot(snapshot: dict[str, Any] | None) -> dict[str, Any] | None:
    """The run snapshot as exposed by the API: the inlined CA certificates are replaced by their provenance (no raw certificate)."""
    if not snapshot:
        return snapshot
    out = copy.deepcopy(snapshot)
    trust = ((out.get("checks") or {}).get("certificate") or {}).get("trust")
    if isinstance(trust, dict) and trust.get("inline_stores"):
        trust["inline_stores"] = [{"store_id": i["store_id"], "name": i["name"], "metadata": i.get("metadata", {})} for i in trust["inline_stores"]]
    return out
