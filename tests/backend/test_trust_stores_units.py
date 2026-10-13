"""Trust stores: import validation and chain verification through the engine, without any running service.

Certificates are generated on the fly (throw-away keys); the engine does the cryptography, as in production.
"""
from __future__ import annotations

import base64
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tls_scan_app.services import trust_stores as svc
from tls_scanner.config import parse_inline_stores
from tls_scanner.models import ConfigError
from tls_scanner.pki import (
    TRUST_PRIVATE, TRUST_UNTRUSTED, PeerCertificateChain, load_inline_store, load_trust_stores, validate_peer_chain,
)

NOW = dt.datetime.now(dt.UTC)


def name(cn: str, org: str = "ACME") -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def issue(subject_cn, subject_key, issuer_cert=None, issuer_key=None, *, ca=True, path_length=None, key_cert_sign=True, san=None,
          days=365, not_before=None, org="ACME", with_basic=True, signing_hash=hashes.SHA256()):
    subject = name(subject_cn, org)
    issuer = issuer_cert.subject if issuer_cert is not None else subject
    signer = issuer_key or subject_key
    start = not_before or NOW - dt.timedelta(days=1)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(subject_key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(start + dt.timedelta(days=days)))
    if with_basic:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), critical=True)
    if ca:
        builder = builder.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                                      key_agreement=False, key_cert_sign=key_cert_sign, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in san]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(signer, signing_hash)


@pytest.fixture(scope="module")
def pki():
    root_key, inter_key, leaf_key = key(), key(), key()
    root = issue("ACME-Root-CA", root_key)
    inter = issue("ACME-Issuing-CA", inter_key, root, root_key, path_length=0)
    leaf = issue("intranet.acme.local", leaf_key, inter, inter_key, ca=False, san=["intranet.acme.local"])
    g_root_key, g_inter_key, g_leaf_key = key(), key(), key()
    g_root = issue("Globex-Root-CA", g_root_key, org="Globex")
    g_inter = issue("Globex-Issuing-CA", g_inter_key, g_root, g_root_key, path_length=0, org="Globex")
    g_leaf = issue("intranet.globex.local", g_leaf_key, g_inter, g_inter_key, ca=False, san=["intranet.globex.local"], org="Globex")
    return {"root": root, "inter": inter, "leaf": leaf, "g_root": g_root, "g_inter": g_inter, "g_leaf": g_leaf,
            "root_key": root_key, "inter_key": inter_key}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def upload(*items: tuple[str, bytes]) -> list[dict]:
    return [{"filename": n, "content_b64": b64(d)} for n, d in items]


# ---------------------------------------------------------------------------------------------
# import validation
# ---------------------------------------------------------------------------------------------
def test_valid_root_and_roles(pki):
    certs = svc.parse_upload(pem(pki["root"]) + pem(pki["inter"]), "bundle.pem")
    assert len(certs) == 2
    assert [svc.classify(c) for c in certs] == ["anchor", "intermediate"]
    info = svc.describe(certs[0])
    assert info["subject"].startswith("CN=ACME-Root-CA") and info["key_type"] == "RSA" and info["key_size"] == 2048
    assert info["basic_constraints"] == {"ca": True, "path_length": None} and "key_cert_sign" in info["key_usage"]
    assert len(svc.certificate_fingerprint(certs[0])) == 64


@pytest.mark.parametrize("data, message", [
    (b"", "empty"),
    (b"not a certificate", "no valid PEM"),
    (b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "not a valid X.509"),
    (b"-----BEGIN CERTIFICATE-----\nAAAA\n", "no valid PEM"),
    (b"\x30\x82\x01\x0a\x00\x01", "binary"),
    (b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n", "only PEM CERTIFICATE"),
    (b"x" * (svc.MAX_FILE_BYTES + 1), "too large"),
])
def test_malformed_input_is_rejected(data, message):
    with pytest.raises(svc.TrustStoreError, match=message):
        svc.parse_upload(data, "x.pem")


def test_private_keys_and_pkcs12_are_refused(pki):
    private = pki["root_key"].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    for blob in (private, pem(pki["root"]) + private,
                 pki["root_key"].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()),
                 pki["root_key"].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw"))):
        with pytest.raises(svc.TrustStoreError, match="private keys"):
            svc.parse_upload(blob, "key.pem")
    from cryptography.hazmat.primitives.serialization import pkcs12

    p12 = pkcs12.serialize_key_and_certificates(b"ca", pki["root_key"], pki["root"], None, serialization.BestAvailableEncryption(b"pw"))
    with pytest.raises(svc.TrustStoreError):
        svc.parse_upload(p12, "bundle.p12")
    with pytest.raises(svc.TrustStoreError):
        svc.parse_upload(pki["root"].public_bytes(serialization.Encoding.DER), "root.cer")  # DER is not accepted, whatever the extension


def test_extension_is_irrelevant(pki):
    assert svc.parse_upload(pem(pki["root"]), "weird.exe.txt")


def test_ca_constraints_are_enforced(pki):
    leaf = pki["leaf"]
    with pytest.raises(svc.TrustStoreError, match="CA:FALSE"):
        svc.check_ca_certificate(leaf)
    no_basic = issue("NoBasic", key(), with_basic=False)
    with pytest.raises(svc.TrustStoreError, match="Basic Constraints"):
        svc.check_ca_certificate(no_basic)
    no_sign = issue("NoSign", key(), key_cert_sign=False)
    with pytest.raises(svc.TrustStoreError, match="keyCertSign"):
        svc.check_ca_certificate(no_sign)
    expired = issue("Old-CA", key(), not_before=NOW - dt.timedelta(days=800), days=30)
    with pytest.raises(svc.TrustStoreError, match="Expired"):
        svc.check_ca_certificate(expired)
    future = issue("Future-CA", key(), not_before=NOW + dt.timedelta(days=30))
    with pytest.raises(svc.TrustStoreError, match="not yet valid"):
        svc.check_ca_certificate(future)
    svc.check_ca_certificate(pki["root"])


def test_inconsistent_self_issued_certificate_is_refused():
    real, other = key(), key()
    forged = x509.CertificateBuilder().subject_name(name("Forged-Root")).issuer_name(name("Forged-Root")).public_key(real.public_key()) \
        .serial_number(1).not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=10)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(other, hashes.SHA256())  # subject == issuer, signed by another key
    with pytest.raises(svc.TrustStoreError, match="self-signature is invalid"):
        svc.classify(forged)


def test_inspect_reports_per_file_and_flags_duplicates(pki):
    result = svc.inspect_files(upload(("a.pem", pem(pki["root"])), ("b.crt", pem(pki["root"]) + pem(pki["inter"])), ("k.pem", b"junk"), ("leaf.pem", pem(pki["leaf"]))))
    assert result["valid"] is False
    files = {f["filename"]: f for f in result["files"]}
    assert files["k.pem"]["error"] and files["leaf.pem"]["certificates"][0]["error"]
    assert files["b.crt"]["certificates"][0]["duplicate"] is True and files["b.crt"]["certificates"][1]["role"] == "intermediate"
    assert svc.inspect_files(upload(("ok.pem", pem(pki["root"]))))["valid"] is True
    assert svc.inspect_files([{"filename": "x", "content_b64": "***"}])["valid"] is False


def test_import_deduplicates_and_refuses_the_whole_upload_on_one_bad_certificate(pki):
    certs = svc.certificates_from_files(upload(("a.pem", pem(pki["root"]) + pem(pki["root"])), ("b.pem", pem(pki["inter"]) + pem(pki["root"]))))
    assert len(certs) == 2
    with pytest.raises(svc.TrustStoreError, match="CA:FALSE"):
        svc.certificates_from_files(upload(("a.pem", pem(pki["root"])), ("leaf.pem", pem(pki["leaf"]))))
    with pytest.raises(svc.TrustStoreError, match="Too many files"):
        svc.decode_files(upload(*[(f"{i}.pem", b"x") for i in range(svc.MAX_FILES_PER_IMPORT + 1)]))


def test_file_name_never_reaches_a_path_or_a_message_unsanitised(pki):
    with pytest.raises(svc.TrustStoreError) as error:
        svc.parse_upload(b"junk", "../../etc/passwd;rm -rf /.pem")
    assert "/" not in str(error.value) and ";" not in str(error.value)


@pytest.mark.parametrize("value", ["", "  ", "a,b", "x" * 121, "TLS Scan Public Web PKI", "bad\nname"])
def test_store_names(value):
    with pytest.raises(svc.TrustStoreError):
        svc.validate_name(value)
    assert svc.validate_name(" Client A - PKI interne ") == "Client A - PKI interne"


def test_content_hash_is_order_independent():
    assert svc.content_hash([("anchor", "b"), ("intermediate", "a")]) == svc.content_hash([("intermediate", "a"), ("anchor", "b")])
    assert svc.content_hash([("anchor", "a")]) != svc.content_hash([("intermediate", "a")])


# ---------------------------------------------------------------------------------------------
# chain verification through the engine (scenarios A to G)
# ---------------------------------------------------------------------------------------------
def store(label, anchors, intermediates=()):
    return load_inline_store(label, f"managed-{label}", [pem(c).decode() for c in anchors], [pem(c).decode() for c in intermediates])


def verdict(chain, *stores):
    return validate_peer_chain(PeerCertificateChain(tuple(chain)), tuple(stores))


def test_A_root_absent_is_untrusted(pki):
    result = verdict([pki["leaf"], pki["inter"]], store("Globex PKI (v1)", [pki["g_root"]]))
    assert result.trust_classification == TRUST_UNTRUSTED


def test_B_root_selected_is_private_trusted_and_names_the_authority(pki):
    s = store("ACME PKI (v1)", [pki["root"]])
    result = verdict([pki["leaf"], pki["inter"]], s)
    assert result.trust_classification == TRUST_PRIVATE and result.chain_validation_status == "Passed"
    assert result.trusted_by == ("ACME PKI (v1)",) and "ACME-Root-CA" in result.trust_anchor


def test_B_with_an_intermediate_in_the_store(pki):
    s = store("ACME PKI (v2)", [pki["root"]], [pki["inter"]])
    full = verdict([pki["leaf"], pki["inter"]], s)
    assert full.trust_classification == TRUST_PRIVATE and "ACME-Root-CA" in full.trust_anchor


def test_F_incomplete_chain_is_not_invented(pki):
    # the server sent the leaf only and the store holds the root only: nothing proves the issuer
    assert verdict([pki["leaf"]], store("ACME PKI (v1)", [pki["root"]])).trust_classification == TRUST_UNTRUSTED
    # an intermediate administered in the store (explicitly provided by the administrator) legitimately completes it, and the anchor is still the Root CA
    completed = verdict([pki["leaf"]], store("ACME PKI (v2)", [pki["root"]], [pki["inter"]]))
    assert completed.trust_classification == TRUST_PRIVATE and "ACME-Root-CA" in completed.trust_anchor


def test_an_intermediate_alone_does_not_become_a_root(pki):
    # store content = the intermediate only, as an anchor-less store: the engine store refuses it, and as an "anchor" it would not validate (no partial chain)
    with pytest.raises(ConfigError):
        parse_inline_stores([{"name": "X (v1)", "store_id": "m-x", "anchors": [], "intermediates": [pem(pki["inter"]).decode()]}])
    as_anchor = store("Inter only (v1)", [pki["inter"]])
    assert verdict([pki["leaf"], pki["inter"]], as_anchor).trust_classification == TRUST_UNTRUSTED


def test_G_customers_are_not_mixed(pki):
    acme = store("ACME PKI (v1)", [pki["root"]])
    globex = store("Globex PKI (v1)", [pki["g_root"]])
    chain = [pki["g_leaf"], pki["g_inter"]]
    assert verdict(chain, acme).trust_classification == TRUST_UNTRUSTED
    both = verdict(chain, acme, globex)
    assert both.trust_classification == TRUST_PRIVATE and both.trusted_by == ("Globex PKI (v1)",)
    by_store = {r.store_name: r.status for r in both.trust_store_results}
    assert by_store == {"ACME PKI (v1)": "untrusted", "Globex PKI (v1)": "trusted"}


def test_C_expired_leaf_is_not_trusted(pki):
    expired = issue("old.acme.local", key(), pki["inter"], pki["inter_key"], ca=False, san=["old.acme.local"], not_before=NOW - dt.timedelta(days=800), days=30)
    result = verdict([expired, pki["inter"]], store("ACME PKI (v1)", [pki["root"]]))
    assert result.trust_classification == TRUST_UNTRUSTED  # the engine's verification includes validity; expiry is also reported by the certificate checks


def test_weak_signature_and_unknown_authority(pki):
    unknown_key = key()
    rogue_root = issue("ACME-Root-CA", unknown_key)  # same name as the real root, other key
    rogue_leaf = issue("evil.acme.local", key(), rogue_root, unknown_key, ca=False, san=["evil.acme.local"])
    assert verdict([rogue_leaf, rogue_root], store("ACME PKI (v1)", [pki["root"]])).trust_classification == TRUST_UNTRUSTED
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_root = issue("EC-Root", ec_key)
    ec_leaf = issue("ec.acme.local", ec.generate_private_key(ec.SECP256R1()), ec_root, ec_key, ca=False, san=["ec.acme.local"])
    assert verdict([ec_leaf], store("EC PKI (v1)", [ec_root])).trust_classification == TRUST_PRIVATE


def test_public_store_still_loads_alongside_inline_stores(pki):
    stores = load_trust_stores(True, (), (store("ACME PKI (v1)", [pki["root"]]),))
    assert [s.store_type for s in stores] == ["public", "inline"]
    assert verdict([pki["leaf"], pki["inter"]], *stores).trust_classification == TRUST_PRIVATE
    assert load_trust_stores(True, ())[0].store_type == "public"  # Standalone behaviour unchanged
    with pytest.raises(ConfigError, match="duplicate"):
        load_trust_stores(True, (), (store("ACME", [pki["root"]]), store("acme", [pki["root"]])))


def test_inline_store_config_validation():
    for bad in ({"name": "x", "store_id": "m", "anchors": "nope"}, {"name": "", "store_id": "m", "anchors": ["x"]}, {"name": "x", "anchors": ["x"]}, "str"):
        with pytest.raises(ConfigError):
            parse_inline_stores([bad])
    with pytest.raises(ConfigError, match="invalid certificate"):
        parse_inline_stores([{"name": "x", "store_id": "m", "anchors": ["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"]}])
