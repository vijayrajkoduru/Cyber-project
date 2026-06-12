"""tier5_passkey - modern passwordless (Passkey / WebAuthn / magic-link) audits.

Probes inspect the configuration exposed by passwordless flows:
  - webauthn_config_audit:   userVerification / attestation / algorithm posture
                             read from a WebAuthn options endpoint.
  - magic_link_entropy_audit: token entropy / length / charset of customer-
                             supplied magic links (offline analysis, no network).
"""
