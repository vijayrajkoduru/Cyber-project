"""tier4_saml - SAML / federation configuration audits.

Probes inspect SAML metadata + the signature-validation posture of the
relying party:
  - saml_metadata_audit: weak signature algorithm (SHA-1), unsigned-assertion
                         acceptance (WantAssertionsSigned=false), expired /
                         soon-expiring certificates, weak cert key size.
The active signature-wrapping probe lives in tier1_token/saml_signature_audit.
"""
