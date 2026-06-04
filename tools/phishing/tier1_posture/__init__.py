"""tier1_posture - Email security posture probes for the target domain.

Covers:
  - spf_dkim_dmarc_audit   (SPF / DMARC / DKIM TXT records via DNS)
  - lookalike_domain_scan  (typosquat / homoglyph / TLD-swap A-record probe)
  - mailbox_security_audit (STARTTLS handshake + cipher + cert on MX:25)
"""
