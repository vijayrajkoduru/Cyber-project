"""TLS Deep Audit — findings rules library.

State shape (populated by tools/recon/tls_deep.py):
  host, supported_protocols (list: ["SSLv3","TLSv1","TLSv1.2","TLSv1.3"]),
  negotiated_protocol (str — what server picked when client allows all),
  negotiated_cipher (tuple — (name, version, bits)),
  cipher_strength_summary (dict — modern/weak/forbidden counts),
  cert (dict — subject, issuer, not_before, not_after, days_until_expiry,
                key_type, key_size, sig_algo, san[], wildcard, self_signed,
                chain_length),
  hsts (str|None), hsts_max_age (int|None), hsts_subdomains (bool),
                hsts_preload (bool),
  ocsp_stapling (bool), alpn_protocols (list),
  vuln_indicators (list of strings — Heartbleed/POODLE/BEAST/etc.),
"""
import re


# ───────────────────────── Protocol rules ─────────────────────────

def rule_sslv2_supported(s):
    if "SSLv2" not in (s.get("supported_protocols") or []): return None
    return {"name": "SSLv2 enabled (catastrophic — DROWN attack)",
            "severity": "CRITICAL",
            "cwe": "CWE-326",
            "evidence": "Server accepts SSLv2 handshake — completely broken protocol",
            "remediation": "Disable SSLv2 IMMEDIATELY. SSLv2 has been broken since 1995. DROWN attack (CVE-2016-0800) can recover keys."}


def rule_sslv3_supported(s):
    if "SSLv3" not in (s.get("supported_protocols") or []): return None
    return {"name": "SSLv3 enabled (POODLE vulnerable)",
            "severity": "HIGH",
            "cwe": "CWE-326",
            "evidence": "Server accepts SSLv3 — broken since 2014",
            "remediation": "Disable SSLv3. CVE-2014-3566 (POODLE) allows padding-oracle attacks."}


def rule_tls10_supported(s):
    if "TLSv1" not in (s.get("supported_protocols") or []): return None
    return {"name": "TLS 1.0 enabled (deprecated since 2018)",
            "severity": "MEDIUM",
            "cwe": "CWE-326",
            "evidence": "Server accepts TLS 1.0",
            "remediation": "Disable TLS 1.0. PCI-DSS requires TLS 1.2+ since 2018. BEAST attack (CVE-2011-3389) targets TLS 1.0."}


def rule_tls11_supported(s):
    if "TLSv1.1" not in (s.get("supported_protocols") or []): return None
    return {"name": "TLS 1.1 enabled (deprecated since 2020)",
            "severity": "MEDIUM",
            "cwe": "CWE-326",
            "evidence": "Server accepts TLS 1.1",
            "remediation": "Disable TLS 1.1. RFC 8996 deprecated both TLS 1.0 and 1.1 in March 2021."}


def rule_tls12_supported(s):
    if "TLSv1.2" not in (s.get("supported_protocols") or []): return None
    return {"name": "TLS 1.2 supported",
            "severity": "POSITIVE",
            "evidence": "Modern protocol available"}


def rule_tls13_supported(s):
    if "TLSv1.3" not in (s.get("supported_protocols") or []): return None
    return {"name": "TLS 1.3 supported (modern + forward-secret by default)",
            "severity": "POSITIVE",
            "evidence": "Latest protocol — improved performance + security"}


def rule_no_tls13(s):
    sp = s.get("supported_protocols") or []
    if "TLSv1.3" in sp: return None
    if not any(p.startswith("TLS") for p in sp): return None  # no TLS at all — different rule
    return {"name": "TLS 1.3 not supported",
            "severity": "LOW",
            "evidence": f"Server supports: {', '.join(sp)} — but not TLSv1.3",
            "remediation": "Enable TLS 1.3 on your web server / load balancer. Significantly faster (1-RTT handshake) and removes legacy crypto."}


# ───────────────────────── Cipher rules ─────────────────────────

def rule_weak_cipher_negotiated(s):
    cipher = s.get("negotiated_cipher")
    if not cipher: return None
    name = cipher[0] if isinstance(cipher, (list, tuple)) else str(cipher)
    bad_patterns = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon"]
    for bp in bad_patterns:
        if bp in name:
            return {"name": f"Weak cipher in use: {name}",
                    "severity": "HIGH",
                    "cwe": "CWE-327",
                    "evidence": f"Server negotiated {name} when client offered modern ciphers",
                    "remediation": f"Disable {bp}-based ciphers. Use AEAD: ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384, TLS_AES_256_GCM_SHA384."}
    return None


def rule_cipher_strength_summary(s):
    summary = s.get("cipher_strength_summary") or {}
    weak = summary.get("weak", 0)
    if weak == 0: return None
    return {"name": f"{weak} weak cipher(s) accepted",
            "severity": "MEDIUM",
            "cwe": "CWE-327",
            "evidence": f"Weak: {weak}; Modern (AEAD): {summary.get('modern', 0)}; Forbidden: {summary.get('forbidden', 0)}",
            "remediation": "Restrict cipher list. Mozilla intermediate profile is a good default: https://wiki.mozilla.org/Security/Server_Side_TLS"}


def rule_no_forward_secrecy(s):
    cipher = s.get("negotiated_cipher")
    if not cipher: return None
    name = cipher[0] if isinstance(cipher, (list, tuple)) else str(cipher)
    # TLS 1.3 ciphers (TLS_AES_*, TLS_CHACHA20_*) inherently use forward secrecy
    # — TLS 1.3 mandates ECDHE/X25519 key exchange.
    if name.startswith("TLS_"): return None
    if "ECDHE" in name or "DHE" in name: return None
    return {"name": "No forward secrecy in negotiated cipher",
            "severity": "MEDIUM",
            "cwe": "CWE-326",
            "evidence": f"Cipher: {name} — no DHE or ECDHE (and not TLS 1.3)",
            "remediation": "Prefer ECDHE-based ciphers. Without forward secrecy, a future private-key compromise decrypts ALL past sessions."}


# ───────────────────────── Cert rules ─────────────────────────

def rule_cert_expired(s):
    cert = s.get("cert") or {}
    d = cert.get("days_until_expiry")
    if d is None or d >= 0: return None
    return {"name": f"TLS certificate EXPIRED {-d} days ago",
            "severity": "CRITICAL",
            "cwe": "CWE-298",
            "evidence": f"Cert notAfter: {cert.get('not_after')}",
            "remediation": "Renew immediately. Customers see browser warnings; SMTP/API integrations fail. Set up auto-renewal (Let's Encrypt + certbot, or registrar autorenew)."}


def rule_cert_expiring_soon(s):
    cert = s.get("cert") or {}
    d = cert.get("days_until_expiry")
    if d is None or d < 0 or d > 30: return None
    return {"name": f"TLS certificate expires in {d} days",
            "severity": "HIGH",
            "cwe": "CWE-298",
            "evidence": f"Cert notAfter: {cert.get('not_after')}",
            "remediation": "Renew within 2 weeks. Configure auto-renewal."}


def rule_cert_expiring_90(s):
    cert = s.get("cert") or {}
    d = cert.get("days_until_expiry")
    if d is None or d <= 30 or d > 90: return None
    return {"name": f"TLS certificate expires in {d} days",
            "severity": "MEDIUM",
            "cwe": "CWE-298",
            "evidence": f"Cert notAfter: {cert.get('not_after')}",
            "remediation": "Schedule renewal."}


def rule_self_signed(s):
    cert = s.get("cert") or {}
    if not cert.get("self_signed"): return None
    return {"name": "Self-signed TLS certificate",
            "severity": "HIGH",
            "cwe": "CWE-295",
            "evidence": f"Subject == Issuer: {cert.get('subject', {}).get('commonName', '?')}",
            "remediation": "Use a CA-issued cert. Let's Encrypt is free + automated. Self-signed certs trigger browser warnings + can't be programmatically trusted."}


def rule_weak_key(s):
    cert = s.get("cert") or {}
    ks = cert.get("key_size")
    if ks is None: return None
    if cert.get("key_type", "").upper() == "RSA" and ks < 2048:
        return {"name": f"Weak RSA key size: {ks} bits",
                "severity": "HIGH",
                "cwe": "CWE-326",
                "evidence": f"RSA-{ks} cert in production",
                "remediation": "Reissue with RSA-2048 minimum (RSA-4096 recommended). NIST deprecated <2048-bit RSA in 2014."}
    if cert.get("key_type", "").upper() == "EC" and ks < 256:
        return {"name": f"Weak EC key size: {ks} bits",
                "severity": "HIGH",
                "cwe": "CWE-326",
                "evidence": f"ECDSA-{ks} cert",
                "remediation": "Reissue with EC P-256 or P-384."}
    return None


def rule_sha1_signature(s):
    cert = s.get("cert") or {}
    sig = (cert.get("sig_algo") or "").lower()
    if "sha1" not in sig: return None
    return {"name": "Cert signed with SHA-1 (deprecated)",
            "severity": "MEDIUM",
            "cwe": "CWE-327",
            "evidence": f"Signature algorithm: {cert.get('sig_algo')}",
            "remediation": "Reissue with SHA-256 or SHA-384. SHA-1 collisions are practical (SHAttered)."}


def rule_wildcard_cert(s):
    cert = s.get("cert") or {}
    if not cert.get("wildcard"): return None
    return {"name": "Wildcard certificate in use",
            "severity": "INFO",
            "evidence": f"Wildcard SAN found in cert",
            "remediation": "Wildcards are convenient but increase blast radius — a compromised private key authenticates ALL subdomains. Consider scoped certs for sensitive subdomains."}


def rule_short_chain(s):
    cert = s.get("cert") or {}
    cl = cert.get("chain_length")
    if cl is None or cl >= 2: return None
    return {"name": "Cert chain incomplete (length < 2)",
            "severity": "MEDIUM",
            "cwe": "CWE-295",
            "evidence": f"Chain length: {cl} — intermediate(s) missing",
            "remediation": "Most CAs require an intermediate cert. Missing intermediates cause browsers/clients to reject."}


# ───────────────────────── HSTS rules ─────────────────────────

def rule_hsts_missing(s):
    if s.get("hsts"): return None
    return {"name": "HSTS header missing",
            "severity": "MEDIUM",
            "cwe": "CWE-319",
            "evidence": "No Strict-Transport-Security header on HTTPS response",
            "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"}


def rule_hsts_short_max_age(s):
    ma = s.get("hsts_max_age")
    if ma is None: return None
    if ma >= 31536000: return None  # 1 year
    return {"name": f"HSTS max-age too short ({ma}s)",
            "severity": "LOW",
            "evidence": f"max-age={ma} — under 1 year",
            "remediation": "Set max-age=31536000 (1 year) minimum. HSTS preload list requires this."}


def rule_hsts_good(s):
    ma = s.get("hsts_max_age")
    if ma is None or ma < 31536000: return None
    parts = []
    if s.get("hsts_subdomains"): parts.append("includeSubDomains")
    if s.get("hsts_preload"): parts.append("preload")
    suffix = f" + {', '.join(parts)}" if parts else ""
    return {"name": f"HSTS properly configured (max-age 1y+){suffix}",
            "severity": "POSITIVE",
            "evidence": f"max-age={ma}, includeSubDomains={s.get('hsts_subdomains')}, preload={s.get('hsts_preload')}"}


# ───────────────────────── Other security rules ─────────────────────────

def rule_ocsp_stapling(s):
    if s.get("ocsp_stapling"):
        return {"name": "OCSP stapling enabled",
                "severity": "POSITIVE",
                "evidence": "Server staples OCSP response — faster revocation checks"}
    return None


def rule_alpn_h2(s):
    alpn = s.get("alpn_protocols") or []
    if "h2" in alpn:
        return {"name": "HTTP/2 (ALPN h2) supported",
                "severity": "POSITIVE",
                "evidence": f"ALPN protocols: {', '.join(alpn)}"}
    return None


# ───────────────────────── Vulnerability rules ─────────────────────────

def rule_vuln_summary(s):
    vi = s.get("vuln_indicators") or []
    if not vi: return None
    return {"name": f"Known TLS vulnerabilities possible ({len(vi)})",
            "severity": "HIGH",
            "cwe": "CWE-310",
            "evidence": "Indicators: " + ", ".join(vi[:5]),
            "remediation": "Review each indicator. Most are addressed by enforcing TLS 1.2+, modern ciphers (AEAD), and disabling SSL compression."}


TLS_FINDING_RULES = [
    rule_sslv2_supported, rule_sslv3_supported,
    rule_tls10_supported, rule_tls11_supported,
    rule_tls12_supported, rule_tls13_supported, rule_no_tls13,
    rule_weak_cipher_negotiated, rule_cipher_strength_summary,
    rule_no_forward_secrecy,
    rule_cert_expired, rule_cert_expiring_soon, rule_cert_expiring_90,
    rule_self_signed, rule_weak_key, rule_sha1_signature,
    rule_wildcard_cert, rule_short_chain,
    rule_hsts_missing, rule_hsts_short_max_age, rule_hsts_good,
    rule_ocsp_stapling, rule_alpn_h2,
    rule_vuln_summary,
]
