"""tier1_posture - Email-security + impersonation-exposure probes for the
target domain. Every scanner here is a REAL external detection probe (no
scaffolds): DNS, TLS, HTTP and public-API inspection only.

Covers:
  - spf_dkim_dmarc_audit   (SPF / DMARC / DKIM TXT records via DNS)
  - lookalike_domain_scan  (typosquat / homoglyph / TLD-swap A-record probe)
  - mailbox_security_audit (STARTTLS handshake + cipher + cert on MX:25)
  - mta_sts_tls_audit      (MTA-STS policy + TLS-RPT + DANE TLSA transport
                            fence via DNS + the well-known HTTPS endpoint)
  - ct_log_lookalike_scan  (Certificate-Transparency lookalike-cert search
                            via the crt.sh public log mirror)
  - oauth_tenant_exposure  (public Microsoft Entra ID OAuth surface: tenant
                            discovery, realm type, device-code endpoint)
"""
