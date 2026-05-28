"""SSL/TLS Audit v2 — VL-FORGE. Cert chain + protocol/cipher audit + SSL Labs-style grade.
Route: /api/recon/ssl_tls_audit
"""
import asyncio
import ssl
import socket
from datetime import datetime
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner

router = APIRouter()

_TLS_VERSIONS = [
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, True),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, True),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, False),  # deprecated
    ("TLSv1.0", ssl.TLSVersion.TLSv1,   False),
]

_WEAK_CIPHERS = ["RC4","3DES","DES","MD5","NULL","EXPORT","ANON","ADH"]

def _connect_get_cert(host, port=443):
    """Connect, get cert + protocol version + cipher in use."""
    ctx_def = ssl.create_default_context()
    ctx_def.check_hostname = False
    ctx_def.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx_def.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                der = ssock.getpeercert(binary_form=True)
                return {
                    "cert": cert,
                    "der_size": len(der),
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                }
    except Exception as e:
        return {"error": str(e)[:200]}

def _test_protocol(host, version_enum, port=443):
    """Test specific TLS version support."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version_enum
        ctx.maximum_version = version_enum
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.version() is not None
    except Exception:
        return False

async def gather(ctx: ScanContext):
    host = ctx.host
    primary = await asyncio.to_thread(_connect_get_cert, host)
    if "error" in primary:
        ctx.state["target_reachable"] = False
        ctx.state["error"] = primary["error"]
        return
    ctx.state["target_reachable"] = True
    ctx.source("tls-handshake")

    # Parse cert
    cert = primary.get("cert") or {}
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    issuer = dict(x[0] for x in (cert.get("issuer") or [])) if cert.get("issuer") else {}
    subject = dict(x[0] for x in (cert.get("subject") or [])) if cert.get("subject") else {}
    san = [x[1] for x in (cert.get("subjectAltName") or []) if x[0] == "DNS"]

    days_to_expiry = None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_to_expiry = (exp - datetime.utcnow()).days
        except Exception:
            pass

    ctx.state.update({
        "tls_version_negotiated": primary.get("protocol"),
        "cipher_negotiated": primary.get("cipher",["?"])[0] if primary.get("cipher") else None,
        "cert_issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "cert_subject_cn": subject.get("commonName"),
        "cert_san": san[:10],
        "cert_not_before": not_before,
        "cert_not_after": not_after,
        "cert_days_to_expiry": days_to_expiry,
    })
    if days_to_expiry is not None: ctx.source(f"cert-expiry-{days_to_expiry}d")

    # Probe TLS versions in parallel
    proto_tests = await asyncio.gather(
        *[asyncio.to_thread(_test_protocol, host, ev) for _, ev, _ in _TLS_VERSIONS],
        return_exceptions=True)
    supported = {}
    for (name, _, ok_to_have), res in zip(_TLS_VERSIONS, proto_tests):
        supported[name] = bool(res) if not isinstance(res, Exception) else False
    ctx.state["protocols_supported"] = supported
    ctx.source(f"protocols-{sum(supported.values())}")

    # Grade
    grade = "A"
    if supported.get("TLSv1.0") or supported.get("TLSv1.1"):
        grade = "C"
    if not supported.get("TLSv1.2") and not supported.get("TLSv1.3"):
        grade = "F"
    if days_to_expiry is not None and days_to_expiry < 0:
        grade = "F"
    elif days_to_expiry is not None and days_to_expiry < 14:
        grade = min(grade, "C")
    cipher = (ctx.state.get("cipher_negotiated") or "").upper()
    if any(w in cipher for w in _WEAK_CIPHERS):
        grade = min(grade, "D")
    ctx.state["tls_grade"] = grade

def r_expired(s):
    d = s.get("cert_days_to_expiry")
    if d is None or d >= 0: return None
    return {"name":f"TLS cert EXPIRED {abs(d)} days ago","severity":"CRITICAL","cvss":9.5,
            "cwe":"CWE-298","evidence":f"notAfter: {s.get('cert_not_after')}",
            "remediation":"Renew cert immediately. Setup Let's Encrypt auto-renew via certbot."}

def r_expires_soon(s):
    d = s.get("cert_days_to_expiry")
    if d is None or d < 0 or d > 14: return None
    return {"name":f"TLS cert expires in {d} days","severity":"HIGH","cvss":7.0,
            "cwe":"CWE-298","evidence":f"notAfter: {s.get('cert_not_after')}",
            "remediation":"Renew within 1 week. Setup auto-renew."}

def r_old_tls(s):
    sup = s.get("protocols_supported") or {}
    old = [v for v in ("TLSv1.0","TLSv1.1") if sup.get(v)]
    if not old: return None
    return {"name":f"Deprecated TLS version(s) enabled: {', '.join(old)}",
            "severity":"HIGH","cvss":7.5,"cwe":"CWE-326","owasp":"A02:2021",
            "evidence":f"Server accepts: {', '.join(old)}",
            "remediation":"Disable TLS 1.0/1.1. nginx: ssl_protocols TLSv1.2 TLSv1.3;"}

def r_no_tls13(s):
    sup = s.get("protocols_supported") or {}
    if sup.get("TLSv1.3"): return None
    if not sup.get("TLSv1.2"): return None
    return {"name":"TLS 1.3 not supported (only TLS 1.2)","severity":"LOW","cwe":"CWE-327",
            "evidence":"Recommended modern protocol missing",
            "remediation":"Enable TLS 1.3 — better performance + security. nginx: ssl_protocols TLSv1.2 TLSv1.3;"}

def r_weak_cipher(s):
    c = (s.get("cipher_negotiated") or "").upper()
    weak = [w for w in _WEAK_CIPHERS if w in c]
    if not weak: return None
    return {"name":f"Weak cipher negotiated: {s['cipher_negotiated']}",
            "severity":"HIGH","cvss":7.0,"cwe":"CWE-327","owasp":"A02:2021",
            "evidence":f"Weakness flags: {', '.join(weak)}",
            "remediation":"Restrict ciphers to TLS_AES_*GCM_SHA*, ECDHE-*-GCM-*. Disable RC4/3DES/DES/MD5."}

def r_grade(s):
    g = s.get("tls_grade")
    if not g: return None
    sev = "POSITIVE" if g == "A" else ("INFO" if g == "B" else ("LOW" if g == "C" else ("MEDIUM" if g == "D" else "HIGH")))
    return {"name":f"TLS configuration grade: {g}","severity":sev,
            "evidence":f"Based on cert validity, TLS versions, cipher strength"}

def r_self_signed(s):
    issuer = s.get("cert_issuer") or ""
    subject = s.get("cert_subject_cn") or ""
    if not issuer or not subject: return None
    if issuer != subject: return None
    return {"name":"Self-signed certificate","severity":"HIGH","cvss":7.0,"cwe":"CWE-295",
            "evidence":f"Issuer == Subject == {issuer}",
            "remediation":"Use Let's Encrypt for free trusted cert."}

def r_long_runway(s):
    d = s.get("cert_days_to_expiry")
    if d is None or d < 60: return None
    return {"name":f"TLS cert has {d} days runway","severity":"POSITIVE",
            "evidence":f"notAfter: {s.get('cert_not_after')}"}

def r_unreach(s):
    if s.get("target_reachable"): return None
    return {"name":"TLS endpoint unreachable","severity":"INFO",
            "evidence":s.get("error","Connection failed")}

FINDING_RULES = [r_expired, r_expires_soon, r_old_tls, r_no_tls13, r_weak_cipher,
                 r_self_signed, r_grade, r_long_runway, r_unreach]

INTEL_FIELDS = [("Target reachable","target_reachable"),("TLS version","tls_version_negotiated"),
                ("Cipher","cipher_negotiated"),("Issuer","cert_issuer"),
                ("CN","cert_subject_cn"),("Expires","cert_not_after"),
                ("Days to expiry","cert_days_to_expiry"),("Grade","tls_grade")]

@router.post("/api/recon/ssl_tls_audit")
async def recon_ssl_tls_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="ssl_tls_audit",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["cert_issuer","cert_not_after","tls_grade",
                         "protocols_supported","cipher_negotiated"])

def register(app): app.include_router(router)
