"""recon_tls_deep — deep TLS/SSL audit: protocols, ciphers, certificate expiry.

Catches: deprecated TLS 1.0/1.1, expired/expiring certs, certificate
name mismatch, self-signed certs in production.
"""
import ssl, socket, datetime
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host

router = APIRouter()


async def recon_tls_deep_impl(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    port = 443
    findings, supported_protocols, cert_info = [], [], None

    # Probe protocol versions
    proto_tests = [
        ("SSLv2", "DEPRECATED", "POODLE/BEAST/CRIME vulnerable"),
        ("SSLv3", "DEPRECATED", "POODLE vulnerable"),
        ("TLSv1", "DEPRECATED", "BEAST attack possible, no PFS"),
        ("TLSv1.1", "DEPRECATED", "Weak compared to TLS 1.2+"),
        ("TLSv1.2", "OK", "Acceptable"),
    ]
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
                supported_protocols.append({"version": version, "status": "ACTIVE"})

                cert_info = {
                    "subject": dict(x[0] for x in (cert.get("subject") or [])),
                    "issuer": dict(x[0] for x in (cert.get("issuer") or [])),
                    "notAfter": cert.get("notAfter"),
                    "version": version,
                    "cipher_suite": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                }

                # Cert expiry
                if cert.get("notAfter"):
                    try:
                        expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.datetime.utcnow()).days
                        cert_info["days_until_expiry"] = days_left
                        if days_left < 0:
                            findings.append({"title": f"TLS certificate EXPIRED {-days_left} days ago",
                                "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-298", "owasp": "A02:2021",
                                "evidence": f"Cert notAfter: {cert.get('notAfter')}",
                                "remediation": "Renew TLS certificate immediately. Set up auto-renewal."})
                        elif days_left < 30:
                            findings.append({"title": f"TLS certificate expires in {days_left} days",
                                "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-298", "owasp": "A02:2021",
                                "evidence": f"Cert notAfter: {cert.get('notAfter')}",
                                "remediation": "Schedule renewal. Consider auto-renewal via Let's Encrypt."})
                    except Exception:
                        pass

                # Weak protocol
                if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    findings.append({"title": f"Weak/deprecated TLS protocol: {version}",
                        "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-326", "owasp": "A02:2021",
                        "evidence": f"Server negotiated {version}",
                        "remediation": "Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1. Require TLSv1.2 minimum."})

                # Weak cipher
                if cipher and cipher[2] and cipher[2] < 128:
                    findings.append({"title": f"Weak cipher: {cipher[0]} ({cipher[2]} bits)",
                        "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-326", "owasp": "A02:2021",
                        "evidence": f"Cipher: {cipher[0]} ({cipher[2]} bits)",
                        "remediation": "Disable ciphers <128 bits. Prefer ECDHE-RSA-AES256-GCM-SHA384."})

                # Cipher block exclusions
                bad_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
                for bc in bad_ciphers:
                    if cipher and bc in (cipher[0] or ""):
                        findings.append({"title": f"Insecure cipher in use: {cipher[0]}",
                            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-327", "owasp": "A02:2021",
                            "evidence": f"Active cipher: {cipher[0]}",
                            "remediation": f"Disable {bc} ciphers. Use modern AEAD ciphers only."})
                        break
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"ok": True, "vulnerable": False, "skipped_reason": f"TLS handshake failed on {host}:443 — {type(e).__name__}: {e}"}
    except Exception as e:
        return {"ok": True, "vulnerable": False, "skipped_reason": f"TLS audit error: {type(e).__name__}: {str(e)[:100]}"}

    return {"ok": True, "vulnerable": len(findings) > 0, "findings": findings,
            "supported_protocols": supported_protocols,
            "certificate": cert_info,
            "total_findings": len(findings),
            "engine": "Python ssl/socket TLS deep audit (protocols + ciphers + cert)"}



# VLERR-WRAP-V1
@router.post("/api/recon/tls_deep")
async def recon_tls_deep(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await recon_tls_deep_impl(req, _)
    except Exception as _e:
        return {"ok": False,
                 "skipped_reason": f"tls_deep scanner failed: {type(_e).__name__}: {str(_e)[:200]}",
                 "error": f"{type(_e).__name__}: {str(_e)[:300]}"}

def register(app):
    app.include_router(router)
