# VPN IPsec / IKE checks

TLS and IPsec are separate control families. IPsec profiles and policies are versioned independently from TLS profiles and policies; scan definitions bind to exactly one family. Existing definitions without a `control_type` are migrated as `tls`.

The first IPsec implementation runs bounded, unauthenticated probes using the Debian `ike-scan` package (GPL-3.0). IKEv1 uses its default Main Mode exchange; Aggressive Mode is not enabled. Up to four explicitly selected IKEv1 transforms can be sent; their numeric fields are validated against the tool's supported encryption, hash, authentication and DH identifiers. UDP 500 and 4500 are individually configurable, and port 4500 uses the tool's NAT-T encapsulation by default. Timeouts are limited to 100–5000 ms and retransmissions to 0–2.

`ike-scan` IKEv2 support is experimental and sends only its default proposal. A response therefore proves only that the particular exchange and proposal were observed; it does not enumerate every proposal supported by the gateway. IKEv1's default proposal set and decoder also limit the crypto facts this initial integration can report. Missing PRF or transform attributes force an `indeterminate` policy verdict. No response is not evidence that a service is absent or compliant.

This scanner does not authenticate, collect PSKs, perform dictionary tests, send ESP/AH traffic, change remote configuration, or establish a Child SA. ESP/Child-SA algorithms, authenticated identities/certificates, negotiated PFS, and operational tunnel behavior are not evaluated. Those checks are presented as unavailable, never as passing.

The IKE evidence is persisted in `run_ipsec_observations`, separate from TLS endpoints, grades, and findings. Existing target scope, scan execution, RBAC, history and report downloads are reused.
