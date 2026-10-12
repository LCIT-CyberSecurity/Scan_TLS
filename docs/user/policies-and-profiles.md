# Cryptographic policies and technical profiles

**Policy** = what is acceptable. **Profile** = how checks are executed. They are versioned separately.

## Policy content
Exactly the engine's fields (same semantics as `config/encryption_policy/*.yaml`):
`allowed_versions`, `allowed_cipher_algorithms`, `allowed_signature_hashes`, `minimum_rsa_bits`.
Several policies can be applied to one scan (`strict_all`: every policy must pass — the only mode the engine has).
*Import YAML* accepts the Standalone policy format; *YAML* exports it back.

## Profile content
`scan.ports` (`fast`, `all`, or a list/range), `scan.crypto` (`standard` | `pqc`), `scan.resolve_dns`,
`scan.workers`, `checks.certificate.*` (expiry warning, chain trust, OCSP/CRL revocation). It is validated by the
engine's own YAML parser: what the WebUI accepts is exactly what the Standalone accepts. Unsupported keys are
refused. Custom trust-store files are not available in the WebUI V1 (they read server paths). The PQC profile needs
OpenSSL ≥ 3.5 in the worker image; otherwise the run fails with the engine's explicit prerequisite error.

## Complementary TLS checks
Under the existing options, the profile form has a **Complementary TLS checks** zone (YAML: `checks.tls`). The recommended
controls are listed and pre-selected **for new profiles only**; untick one to remove it, or use *Add checks* for the others
(ECDHE / FFDHE groups). An existing profile (without `checks.tls`) shows them unticked and keeps its behaviour until you tick one.
`Fast` / `All` still only mean port discovery. The list comes from the engine's catalogue (`GET /api/tls-checks`), so only
implemented checks are offered. Reference, statuses, limits and YAML: [Complementary TLS checks](tls-checks.md). Their results do not
change the grade, and PKI trust / revocation stay in their own options above.

## Lifecycle
`draft → published → archived`. Editing a published item creates a **new draft**; publishing archives the previous
version. Published versions are never modified: each run stores the exact version ids it used and the snapshot of
their content, so history is never re-evaluated. Re-evaluating old results against a new policy is V2.
Duplicate creates an independent copy; *Archive* hides an item from new definitions without touching history.
