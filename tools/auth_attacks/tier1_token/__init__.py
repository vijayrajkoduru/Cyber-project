"""tier1_token - JWT + SAML token-layer attacks.

Probes target the cryptographic primitives of the auth tokens themselves:
  - jwt_secret_audit:     alg=none, weak HS256 secret, RS256->HS256 confusion, kid injection
  - saml_signature_audit: XSW1-XSW8 wrapping, signature stripping, XML comment injection
"""
