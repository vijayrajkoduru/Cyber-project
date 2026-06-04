"""tier3_mfa - Multi-Factor Authentication bypass probes.

Probes target the MFA gate itself:
  - mfa_bypass_test: skip MFA step, forge mfa_verified flag, replay another
                     user's MFA response, direct access to protected resource
"""
