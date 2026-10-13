# Trust authorities (private PKI)

TLS Scan verifies certificate chains against **trust stores**. The public Mozilla-derived store is built in. To verify
certificates issued by a customer's internal PKI, an administrator imports its CA certificates in
**Administration → Trust authorities**, and a profile selects which stores to use.

## Administration → Trust authorities (ADMIN only)

| What | How |
|---|---|
| See the stores | The built-in public store is listed first, read-only. Private stores show their version, number of CA certificates, state and last change. |
| Create a store | *New trust store*: a name (no comma) and one or several `.pem`, `.crt`, `.cer` files **in PEM format**. The dialog previews what would be stored (role, subject, validity, key, fingerprint) or the exact reason a file is refused. |
| Change a store | *Details* → *Publish a new version*: add certificates to the current content, or replace it entirely. Removing a certificate also publishes a new version. |
| Consult history | Every version stays readable (certificates, SHA-256 content hash, comment). A published version is never modified. |
| Deactivate | A deactivated store cannot be selected, and a profile that still selects it cannot launch a scan until it is reactivated (no silent downgrade of the verification). |
| Delete | Only a store never referenced by a profile nor a scan. Otherwise deactivate it. |

### What is accepted

Public CA certificates only: PEM text, several certificates per file. The backend inspects the real content, never the
extension or the file name (which is never used as a path). Refused: private keys (plain or encrypted), PKCS#12/PFX, DER
and any binary content, other PEM block types, malformed or truncated blocks, certificates that are not CAs
(`CA:FALSE`, missing Basic Constraints), a Key Usage without `keyCertSign`, expired or not-yet-valid certificates,
inconsistent validity, a self-issued certificate whose self-signature is invalid, files above 512 KiB, more than 20 files
per import, 100 certificates per file or 300 per store. Duplicates are merged. One refused certificate refuses the whole
import.

### Root CAs and intermediate CAs

- A **Root CA** (self-signed) is a **trust anchor**: the only kind of certificate that can make a chain trusted.
- An **intermediate CA** is **never** a trust anchor. It only completes the chain up to a Root CA of the *same store*, for
  servers that do not send their whole chain. If the Root CA is not in the store, nothing is trusted.
- A store needs at least one Root CA.
- Each store is verified on its own: a customer B certificate is never trusted through customer A's store.

## Profiles → Scan profiles

When *Validate certificate chains* is on, the profile form offers **Built-in public authorities** (on by default) and the
list of **private trust stores** (none selected by default; inactive ones cannot be newly selected). A profile
references stores by their technical identifier (`checks.certificate.trust.private_stores`). Existing profiles are not
modified; new versions of a profile follow the usual versioning.

## Scans and traceability

When a scan is launched, the snapshot pins the **exact version** of every selected store (identifier, version, SHA-256 of
the content, anchors) and carries the certificates the worker needs. Changing a store later never changes a scan that is
queued, running or historical; a new scan uses the then-current version. The API returns the provenance without any raw
certificate (`trust_stores` on a run; `config_snapshot` is scrubbed).

## Reading the results

The scan page has a **PKI trust** card: per endpoint, the chain verdict, the store (with version) that validated it, the
Root CA that anchored the chain, the failure reason when not trusted, and — in separate columns — the name check
(FQDN/SAN), the certificate state and the revocation status.

| Verdict | Meaning |
|---|---|
| `PUBLIC_TRUSTED` | The chain is validated by a built-in public authority. |
| `PRIVATE_TRUSTED` | The chain is validated by a selected private store (and by no public one). |
| `UNTRUSTED` | No selected authority validates the chain (unknown authority, expired certificate, incomplete chain…). |
| `NOT_TESTED` | The verification was not performed. |
| `ERROR` | The verification failed technically. |

**A trusted chain is not a complete compliance verdict.** It does not say that the name matches, that the certificate is
not expired, or that it is not revoked: a trusted chain with a wrong SAN, an expired leaf or a revoked certificate is
reported as such by the other controls, and the findings stay. Reports (HTML, Markdown, CSV, CBOM, metadata) carry the
store names with their version; the metadata also holds the content hash and the anchors, never raw certificates.

## Standalone engine

Nothing changes for the YAML engine: `checks.certificate.trust.custom_stores` (files and directories) still works. The
WebUI refuses `custom_stores` paths and raw `inline_stores` in a profile: certificates only come from the administered
stores. Internally the WebUI uses the engine's new `inline_stores` (PEM content, anchors + intermediates), validated with
the same code (`tls_scanner.pki`).

## API (ADMIN)

`GET/POST /api/admin/trust-stores`, `POST /api/admin/trust-stores/inspect` (dry run), `GET/PUT/DELETE
/api/admin/trust-stores/{id}`, `POST /api/admin/trust-stores/{id}/versions`, `GET …/versions/{n}`; `GET /api/trust-stores`
(USER+, selection list without certificate content). Audited actions: `trust_store.create`, `.version_publish`,
`.activate`, `.deactivate`, `.update`, `.delete` and `profiles.trust_stores_change` (certificate content is never logged).
