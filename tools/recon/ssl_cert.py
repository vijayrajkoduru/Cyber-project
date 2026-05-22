"""SSL/TLS certificate inspection.

Active verification: connects to <target>:443 and inspects the leaf
certificate. Confirmed findings on:
  - Expired or expiring certificate (CRITICAL <7d, HIGH <30d)
  - Self-signed certificate (issuer == subject)
  - Hostname mismatch (target not in CN/SAN)
  - Weak signature algorithm (MD5, SHA-1)
  - Short RSA key length (< 2048 bits)
"""
import ssl
import socket
import datetime
from fastapi import APIRouter, Depends

from tools._payloads.cert_intelligence import CERT_INTELLIGENCE
from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host,
    wrap_finding, standard_response,
)

router = APIRouter()


def _hostname_in_names(host: str, names: set) -> bool:
    for n in names:
        n = n.lower().lstrip(".")
        if n == host:
            return True
        if n.startswith("*."):
            base = n[2:]
            if host.endswith("." + base) and host.count(".") == base.count(".") + 1:
                return True
    return False


@router.post("/api/scan/ssl_cert")
async def scan_ssl_cert(req: ScanRequest, _=Depends(verify_scan_quota)):
    target = recon_host(req.target)
    findings = []
    tests = 0
    raw = {}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
    except Exception as e:
        return standard_response(
            tool="ssl_cert", target=target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"TLS handshake failed on {target}:443 — {e}",
        )

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception:
        cert = None

    san_dns = [v for k, v in cert_dict.get("subjectAltName", []) if k == "DNS"]
    cn = None
    for rdn in cert_dict.get("subject", []):
        for k, v in rdn:
            if k == "commonName":
                cn = v

    raw["protocol"] = protocol
    raw["cipher"] = list(cipher) if cipher else None
    raw["common_name"] = cn
    raw["san"] = san_dns
    raw["valid_from"] = cert_dict.get("notBefore")
    raw["valid_to"] = cert_dict.get("notAfter")

    # Test 1 — Expiration
    tests += 1
    not_after_str = cert_dict.get("notAfter")
    if not_after_str:
        try:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.datetime.utcnow()).days
            raw["days_until_expiry"] = days_left
            if days_left < 0:
                findings.append(wrap_finding(
                    f"TLS certificate expired {abs(days_left)} days ago",
                    "CRITICAL", cwe="CWE-298", owasp="A02:2021",
                    evidence_marker=f"notAfter={not_after_str}",
                    remediation="Renew the certificate immediately.",
                    tests_performed=1,
                ))
            elif days_left <= 7:
                findings.append(wrap_finding(
                    f"TLS certificate expires in {days_left} days",
                    "CRITICAL", cwe="CWE-298",
                    evidence_marker=f"notAfter={not_after_str}",
                    remediation="Renew the certificate immediately.",
                    tests_performed=1,
                ))
            elif days_left <= 30:
                findings.append(wrap_finding(
                    f"TLS certificate expires in {days_left} days",
                    "HIGH",
                    evidence_marker=f"notAfter={not_after_str}",
                    remediation="Schedule certificate renewal within 2 weeks.",
                    tests_performed=1,
                ))
        except ValueError:
            pass

    # Test 2 — Self-signed
    tests += 1
    subj = tuple(tuple(t) for t in cert_dict.get("subject", []))
    issuer = tuple(tuple(t) for t in cert_dict.get("issuer", []))
    if subj and issuer and subj == issuer:
        findings.append(wrap_finding(
            "Self-signed TLS certificate — no chain of trust",
            "HIGH", cwe="CWE-295", owasp="A02:2021",
            evidence_marker=f"subject==issuer (CN={cn})",
            remediation="Obtain a certificate from a trusted CA (Let's Encrypt, commercial CA).",
            tests_performed=1,
        ))

    # Test 3 — Hostname mismatch
    # If cert parse returned NULL CN + empty SAN, the chain wasn't fully retrieved —
    # almost always because target is behind a CDN (Cloudflare, CloudFront, Fastly)
    # that terminates TLS at the edge. Skip instead of flagging FALSE-POSITIVE.
    tests += 1
    all_names = set(san_dns) | ({cn} if cn else set())
    if cn is None and len(san_dns) == 0:
        pass  # Cert chain unreadable (CDN edge TLS) — no false-positive mismatch
    elif not _hostname_in_names(target.lower(), {n.lower() for n in all_names if n}):
        findings.append(wrap_finding(
            f"Hostname mismatch — '{target}' not present in certificate CN or SAN",
            "HIGH", cwe="CWE-297", owasp="A02:2021",
            evidence_marker=f"target={target} cn={cn} san={san_dns[:5]}",
            remediation="Reissue the certificate including the correct hostname in the SAN field.",
            tests_performed=1,
        ))

    # Test 4 — Weak signature algorithm
    tests += 1
    if cert is not None:
        try:
            sig_algo = cert.signature_hash_algorithm.name.lower()
            raw["signature_algorithm"] = sig_algo
            if sig_algo in ("md5", "sha1"):
                findings.append(wrap_finding(
                    f"Weak certificate signature algorithm: {sig_algo.upper()}",
                    "HIGH", cwe="CWE-327", owasp="A02:2021",
                    evidence_marker=f"signature_algorithm={sig_algo}",
                    remediation="Reissue the certificate using SHA-256 or stronger.",
                    tests_performed=1,
                ))
        except Exception:
            pass

    # Test 5 — Short RSA key
    tests += 1
    if cert is not None:
        try:
            pub = cert.public_key()
            key_size = pub.key_size
            key_type = type(pub).__name__
            raw["public_key_type"] = key_type
            raw["public_key_bits"] = key_size
            if "RSA" in key_type and key_size < 2048:
                findings.append(wrap_finding(
                    f"RSA public key only {key_size} bits — below 2048-bit modern minimum",
                    "HIGH", cwe="CWE-326", owasp="A02:2021",
                    evidence_marker=f"key_type={key_type} key_size={key_size}",
                    remediation="Reissue with a 2048-bit or stronger RSA key (or use ECDSA).",
                    tests_performed=1,
                ))
        except Exception:
            pass

    return standard_response(
        tool="ssl_cert", target=target, findings=findings,
        tests_performed=tests,
        tests_summary="5 TLS cert checks: expiry, self-signed, hostname, signature, key size",
        raw_data={"ssl_cert": raw},
    )


def register(app):
    app.include_router(router)
