"""mailbox_security_audit - findings rules.

Severity model (a mail server's TLS posture is the customer's only
defense against passive collection of inbound credentials, internal
financial chatter, and HR PII traversing public links):

  HIGH    - cleartext SMTP (no STARTTLS) on port 25
  HIGH    - TLS<=1.1 (RFC 8996 deprecation since 2021)
  HIGH    - certificate expired / not-yet-valid
  HIGH    - hostname does not match cert SAN
  MEDIUM  - weak cipher (RC4 / 3DES / NULL / EXPORT / anon)
  MEDIUM  - CBC-mode cipher (BEAST/Lucky13 surface in TLS<=1.2)
  MEDIUM  - cert expires within 30 days (rotation overdue)
  INFO    - customer didn't supply mail_server + no MX -> nothing probed
  INFO    - connect failure / port closed
  POSITIVE - TLSv1.3 + GCM cipher + valid + host-matched cert
"""

_CWE_TRANSMISSION = "CWE-319"   # Cleartext Transmission of Sensitive Info
_CWE_PROTOCOL = "CWE-757"       # Selection of Less-Secure Algorithm
_CWE_CERT = "CWE-295"           # Improper Certificate Validation
_CWE_VERIFY = "CWE-345"
_NIST = "NIST 800-53 SC-8 (Transmission Confidentiality and Integrity)"


def rule_no_input(s):
    if not s.get("mailbox_input_missing"):
        return None
    return {
        "name": ("Mailbox TLS probe skipped - no options.mail_server and "
                 "no MX record for the target domain"),
        "severity": "INFO",
        "evidence": (
            f"No options.mail_server was supplied and an MX lookup on "
            f"{s.get('mailbox_target_domain', 'target')} returned no "
            "records. The probe cannot pick a host to test."
        ),
        "remediation": (
            "Re-run this scan with options.mail_server set to your "
            "actual mail server hostname (e.g. `mx1.acme.com` or "
            "`acme-com.mail.protection.outlook.com`). If your mail is "
            "hosted in M365/Google, the MX should exist — confirm DNS "
            "is healthy before re-running."
        ),
        "cwe": "CWE-1006",
    }


def _primary(s) -> dict:
    return s.get("mailbox_primary") or {}


def rule_connect_error(s):
    p = _primary(s)
    err = p.get("error")
    if not err or p.get("starttls_ok"):
        return None
    return {
        "name": (f"Could not probe SMTP TLS on "
                 f"{s.get('mailbox_mail_host', '?')}:"
                 f"{s.get('mailbox_test_port', 25)}"),
        "severity": "INFO",
        "evidence": (
            f"Connection attempt to {s.get('mailbox_mail_host')}:"
            f"{s.get('mailbox_test_port')} failed with: {err}. "
            "TLS posture cannot be evaluated."
        ),
        "remediation": (
            "Confirm the host is publicly reachable from this scanner's "
            "egress IP. If your mail server is restricted by allowlist, "
            "add the VulnusLab scanner IP to the inbound SMTP filter."
        ),
        "cwe": "CWE-1006",
    }


def rule_no_starttls(s):
    p = _primary(s)
    if p.get("error"):
        return None
    if p.get("starttls_offered"):
        return None
    # Cleartext SMTP on the negotiated port
    return {
        "name": (f"STARTTLS not offered on "
                 f"{s.get('mailbox_mail_host')}:{s.get('mailbox_test_port', 25)} "
                 "- mail is sent in cleartext"),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": _CWE_TRANSMISSION,
        "cwe_name": "Cleartext Transmission of Sensitive Information",
        "owasp": "A02:2021",
        "evidence": (
            f"EHLO response from the server did not advertise the "
            "STARTTLS extension. All inbound mail to this host is "
            "transmitted in cleartext over the public internet — "
            "passive observers (ISP, transit, nation-state) read "
            "every message verbatim."
        ),
        "remediation": (
            "Enable STARTTLS on the SMTP receiver and present a valid "
            "certificate. Postfix: `smtpd_tls_security_level = may` "
            "(opportunistic) or `encrypt` (enforce). Exchange: "
            "configure Receive Connector TLS auth. Then publish a "
            "DANE TLSA record or join the MTA-STS allowlist so sender "
            "MTAs require encryption. "
            f"Compliance: {_NIST}, RFC 8460 (TLS-RPT)."
        ),
    }


def rule_old_tls(s):
    p = _primary(s)
    ver = (p.get("tls_version") or "").upper()
    if ver in ("TLSV1", "TLSV1.0", "TLSV1.1"):
        return {
            "name": f"Mail TLS negotiated {ver} (deprecated by RFC 8996)",
            "severity": "HIGH",
            "cvss": "7.4",
            "cwe": _CWE_PROTOCOL,
            "owasp": "A02:2021",
            "evidence": (
                f"STARTTLS handshake completed with {ver}. RFC 8996 "
                "deprecated TLS 1.0/1.1 in 2021 due to BEAST, POODLE "
                "and downgrade-attack risk. Major mail providers "
                "(Google, Microsoft) refuse to deliver into hosts "
                "stuck on these versions and silently downgrade to "
                "cleartext or skip the user's MX entirely."
            ),
            "remediation": (
                "Force TLS 1.2 minimum, prefer 1.3. Postfix: "
                "`smtpd_tls_protocols = !SSLv2 !SSLv3 !TLSv1 !TLSv1.1`. "
                "Test post-change with `openssl s_client -starttls smtp "
                f"-connect {s.get('mailbox_mail_host')}:25 "
                "-tls1_3`. "
                f"{_NIST}."
            ),
        }
    return None


def rule_cert_expired(s):
    p = _primary(s)
    if not p.get("cert_expired") and not p.get("cert_not_yet"):
        return None
    state = "expired" if p.get("cert_expired") else "not yet valid"
    return {
        "name": f"Mail server certificate is {state}",
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": _CWE_CERT,
        "cwe_name": "Improper Certificate Validation",
        "owasp": "A05:2021",
        "evidence": (
            f"Certificate notBefore={p.get('cert_not_before')}, "
            f"notAfter={p.get('cert_not_after')}, "
            f"days_left={p.get('cert_days_left')}. "
            f"Subject: {p.get('cert_subject')!r}. "
            "Many sender MTAs treat an expired/not-yet-valid cert as "
            "a downgrade signal and fall back to cleartext — silently "
            "removing the encryption layer your DMARC + DKIM rely on."
        ),
        "remediation": (
            "Rotate the certificate immediately (Let's Encrypt + "
            "certbot-renew is the minimum). Add a calendar / Nagios "
            "/ Prometheus alert at notAfter-30d, notAfter-7d, "
            "notAfter-1d so this never recurs."
        ),
    }


def rule_cert_host_mismatch(s):
    p = _primary(s)
    if p.get("cert_host_match") is None:
        return None
    if p.get("cert_host_match"):
        return None
    return {
        "name": (f"Mail server cert SAN does not include "
                 f"{s.get('mailbox_mail_host')}"),
        "severity": "HIGH",
        "cvss": "5.9",
        "cwe": _CWE_CERT,
        "owasp": "A02:2021",
        "evidence": (
            f"Connected to {s.get('mailbox_mail_host')} but the "
            "presented certificate's subjectAltName list "
            f"({p.get('cert_sans')}) does not match. Strict-TLS "
            "senders (Office 365 / Google when DANE-aware) refuse "
            "the connection."
        ),
        "remediation": (
            "Re-issue the certificate listing every hostname the "
            f"mail server uses (including {s.get('mailbox_mail_host')} "
            "and any CNAME aliases) in the SAN list. SAN matters "
            "more than CN — modern browsers and MTAs ignore CN."
        ),
    }


def rule_weak_cipher(s):
    p = _primary(s)
    if not p.get("weak_cipher"):
        return None
    return {
        "name": f"Mail server negotiates a weak cipher: {p.get('cipher')}",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": _CWE_PROTOCOL,
        "owasp": "A02:2021",
        "evidence": (
            f"TLS handshake used cipher `{p.get('cipher')}` "
            f"({p.get('cipher_version')}, {p.get('cipher_bits')} bits). "
            "The suite name matches a deprecated class (RC4 / 3DES / "
            "NULL / EXPORT / anon) — passive collection or active "
            "downgrade is feasible."
        ),
        "remediation": (
            "Restrict the cipher list to AEAD suites only "
            "(`ECDHE-ECDSA-AES256-GCM-SHA384` / "
            "`ECDHE-RSA-AES256-GCM-SHA384` / TLS1.3 mandatory). "
            "Postfix: `smtpd_tls_ciphers = high` + "
            "`tls_high_cipherlist = ...`. "
            "Run `testssl.sh --starttls smtp host:25` to verify."
        ),
    }


def rule_cbc_cipher(s):
    p = _primary(s)
    if not p.get("cbc_cipher"):
        return None
    if p.get("weak_cipher"):
        # Already covered by rule_weak_cipher
        return None
    return {
        "name": f"Mail server cipher uses CBC mode: {p.get('cipher')}",
        "severity": "MEDIUM",
        "cvss": "4.3",
        "cwe": _CWE_PROTOCOL,
        "owasp": "A02:2021",
        "evidence": (
            f"TLS handshake selected `{p.get('cipher')}`. CBC-mode "
            "ciphers in TLS <=1.2 are vulnerable to BEAST and "
            "Lucky13 timing side-channels. Authenticated-encryption "
            "(GCM/CCM/ChaCha20-Poly1305) suites are preferred."
        ),
        "remediation": (
            "Disable CBC ciphers in the SMTP TLS profile. Move to "
            "ECDHE-*-GCM-* or TLS1.3 AEAD-only ciphers."
        ),
    }


def rule_cert_expiring(s):
    p = _primary(s)
    days = p.get("cert_days_left")
    if days is None:
        return None
    if days >= 31 or days < 0:
        return None
    return {
        "name": f"Mail server certificate expires in {days} day(s)",
        "severity": "MEDIUM",
        "cvss": "3.7",
        "cwe": _CWE_CERT,
        "owasp": "A05:2021",
        "evidence": (
            f"Certificate notAfter={p.get('cert_not_after')} "
            f"({days} days remaining). Renewal is overdue per "
            "common 30/45-day rotation policies."
        ),
        "remediation": (
            "Renew the certificate now and confirm auto-renewal "
            "(certbot --pre-hook + --post-hook) is healthy."
        ),
    }


def rule_positive(s):
    p = _primary(s)
    if not p.get("starttls_ok"):
        return None
    ver = (p.get("tls_version") or "").upper()
    if ver not in ("TLSV1.3", "TLSV1.2"):
        return None
    if p.get("weak_cipher") or p.get("cbc_cipher"):
        return None
    if p.get("cert_expired") or p.get("cert_not_yet"):
        return None
    if p.get("cert_host_match") is False:
        return None
    if (p.get("cert_days_left") or 999) <= 30:
        return None
    return {
        "name": ("Mail server TLS posture is strong "
                 f"({ver} + AEAD cipher + valid cert)"),
        "severity": "POSITIVE",
        "evidence": (
            f"STARTTLS handshake completed with {ver} and cipher "
            f"`{p.get('cipher')}`. Certificate valid through "
            f"{p.get('cert_not_after')} "
            f"({p.get('cert_days_left')} days left)."
        ),
        "remediation": (
            "Maintain: keep cert auto-renewal healthy + publish "
            "MTA-STS + TLS-RPT (RFC 8460) for inbound deliverability "
            "visibility + consider DANE TLSA if your DNS is "
            "DNSSEC-signed."
        ),
        "cwe": _CWE_VERIFY,
        "owasp": "A02:2021",
    }


MAILBOX_SECURITY_AUDIT_FINDING_RULES = [
    rule_no_input,
    rule_connect_error,
    rule_no_starttls,
    rule_old_tls,
    rule_cert_expired,
    rule_cert_host_mismatch,
    rule_weak_cipher,
    rule_cbc_cipher,
    rule_cert_expiring,
    rule_positive,
]
