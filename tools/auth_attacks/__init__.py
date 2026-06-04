"""auth_attacks module - modern web/SaaS authentication attack probes.

Per module_playbooks/17_auth_attacks.md - 7 sections, 74 techniques.
Starter set (5 scanners) covers the highest-impact playbook items:
  - tier1_token  (§5 JWT / §4 SAML): jwt_secret_audit, saml_signature_audit
  - tier2_flow   (§3 OAuth):         oauth_redirect_audit, session_fixation_test
  - tier3_mfa    (§2 MFA Bypass):    mfa_bypass_test
More scanners will be added per playbook section in subsequent commits.

Customer input pattern: every scanner accepts ScanRequest.options.* -
the JWT token, OAuth authorize URL, SAML metadata + ACS URL + sample
response, login creds, etc. Probes use real PyJWT / httpx / lxml calls;
no scaffolds. Every successful attack -> CRITICAL finding with CWE +
OWASP + remediation.
"""
