"""recon_ssl_deep -- isolated tool (Kali-style architecture).

Route: /api/recon/ssl_deep
Split from recon_module.py monolith by scripts/split_recon_module.py.
Failure here is quarantined by the healing autoloader -- other tools unaffected.
"""

import asyncio
import base64
import datetime
import hashlib
import re
import socket
from typing import Optional
import requests
import dns.resolver
import dns.asyncresolver
import whois as whois_lib
from fastapi import APIRouter, Depends
from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)
import aiohttp as _aiohttp_crawl
import ssl as _ssl_mod

from fastapi import APIRouter, Depends

router = APIRouter()

def _test_protocol(host, port, version_enum):
    try:
        ctx = _ssl_mod.SSLContext(_ssl_mod.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl_mod.CERT_NONE
        ctx.minimum_version = version_enum
        ctx.maximum_version = version_enum
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except Exception:
        return False

@router.post("/api/recon/ssl_deep")
async def recon_ssl_deep(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    port = 443
    try:
        ctx = _ssl_mod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl_mod.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                cipher = ssock.cipher()
                current_proto = ssock.version()
    except Exception as e:
        return {"ok": False, "skipped_reason": f"TLS handshake failed on {host}:{port} — {e}",
                "engine": "pure-Python SSL/TLS deep scan"}

    protocol_tests = [
        ("TLSv1.0", _ssl_mod.TLSVersion.TLSv1),
        ("TLSv1.1", _ssl_mod.TLSVersion.TLSv1_1),
        ("TLSv1.2", _ssl_mod.TLSVersion.TLSv1_2),
        ("TLSv1.3", _ssl_mod.TLSVersion.TLSv1_3),
    ]
    protocols_supported = {}
    for name, ver in protocol_tests:
        protocols_supported[name] = _test_protocol(host, port, ver)

    cert_details = {
        "subject": cert_dict.get("subject"),
        "issuer": cert_dict.get("issuer"),
        "not_before": cert_dict.get("notBefore"),
        "not_after": cert_dict.get("notAfter"),
        "san": [v for k, v in cert_dict.get("subjectAltName", []) if k == "DNS"],
    }
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        cert_details["signature_algorithm"] = cert.signature_hash_algorithm.name.lower()
        pub = cert.public_key()
        cert_details["public_key_type"] = type(pub).__name__
        cert_details["public_key_bits"] = pub.key_size
    except Exception:
        pass

    not_after_str = cert_dict.get("notAfter")
    days_until_expiry = None
    if not_after_str:
        try:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_until_expiry = (not_after - datetime.datetime.utcnow()).days
            cert_details["days_until_expiry"] = days_until_expiry
        except Exception:
            pass

    vulnerabilities = []
    if protocols_supported.get("TLSv1.0"):
        vulnerabilities.append({"name": "TLS 1.0 enabled", "severity": "MEDIUM",
                                "cve": "CVE-2011-3389 (BEAST)",
                                "description": "TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST attacks via CBC ciphers.",
                                "remediation": "Disable TLS 1.0 in server config. Enforce TLS 1.2+ minimum."})
    if protocols_supported.get("TLSv1.1"):
        vulnerabilities.append({"name": "TLS 1.1 enabled", "severity": "MEDIUM", "cve": "N/A",
                                "description": "TLS 1.1 is deprecated by RFC 8996.",
                                "remediation": "Disable TLS 1.1 in server config."})
    if not protocols_supported.get("TLSv1.2") and not protocols_supported.get("TLSv1.3"):
        vulnerabilities.append({"name": "Modern TLS not supported", "severity": "CRITICAL", "cve": "N/A",
                                "description": "Neither TLS 1.2 nor TLS 1.3 supported — only deprecated protocols.",
                                "remediation": "Enable TLS 1.2 and TLS 1.3."})
    sa = (cert_details.get("signature_algorithm") or "").lower()
    if sa in ("md5", "sha1"):
        vulnerabilities.append({"name": f"Weak certificate signature: {sa.upper()}",
                                "severity": "HIGH", "cve": "CWE-327",
                                "description": f"Certificate signed with {sa.upper()} — cryptographically broken.",
                                "remediation": "Reissue with SHA-256+ signature."})
    pk_type = cert_details.get("public_key_type", "")
    pk_bits = cert_details.get("public_key_bits", 0) or 0
    if "RSA" in pk_type and 0 < pk_bits < 2048:
        vulnerabilities.append({"name": f"Weak RSA key ({pk_bits} bits)",
                                "severity": "HIGH", "cve": "CWE-326",
                                "description": f"RSA key only {pk_bits} bits — below 2048-bit minimum.",
                                "remediation": "Reissue with 2048-bit+ RSA or ECDSA."})
    if days_until_expiry is not None and days_until_expiry < 0:
        vulnerabilities.append({"name": "Certificate expired", "severity": "CRITICAL", "cve": "CWE-298",
                                "description": f"TLS certificate expired {abs(days_until_expiry)} days ago.",
                                "remediation": "Renew the certificate immediately."})
    elif days_until_expiry is not None and days_until_expiry <= 30:
        vulnerabilities.append({"name": f"Certificate expires in {days_until_expiry} days",
                                "severity": "HIGH", "cve": "N/A",
                                "description": f"TLS certificate expires in {days_until_expiry} days.",
                                "remediation": "Renew within two weeks."})

    hsts = None
    try:
        hr = requests.get(f"https://{host}", timeout=8, verify=False,
                          headers={"User-Agent": "VulnusLab/1.0"}, allow_redirects=False)
        hsts = hr.headers.get("Strict-Transport-Security")
    except Exception:
        pass
    if not hsts:
        vulnerabilities.append({"name": "HSTS header missing", "severity": "MEDIUM", "cve": "CWE-319",
                                "description": "Strict-Transport-Security header not set — TLS downgrade possible.",
                                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."})

    return {
        "ok": True, "host": host, "port": port,
        "current_protocol": current_proto,
        "current_cipher": list(cipher) if cipher else None,
        "protocols_supported": protocols_supported,
        "certificate": cert_details,
        "hsts": hsts,
        "vulnerabilities": vulnerabilities,
        "total_vulnerabilities": len(vulnerabilities),
        "engine": "pure-Python SSL/TLS deep scan (cert + 4 protocol tests + HSTS + vuln synthesis)",
    }


def register(app):
    app.include_router(router)
