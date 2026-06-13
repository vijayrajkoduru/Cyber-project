"""TLS Quantum Exposure - assess a target's HTTPS transport against the
post-quantum threat (harvest-now-decrypt-later).

Detection-only, zero new dependency:
  - stdlib `ssl` handshake  -> negotiated cipher + TLS version + peer cert
  - `cryptography`          -> cert signature algorithm + public-key type/size
  - a hand-rolled TLS 1.3 ClientHello probe -> does the server offer/select a
    post-quantum HYBRID group (X25519MLKEM768)?  (no OpenSSL 3.5 / sslyze needed)

All findings are advisory/LOW: this is a FUTURE risk (a CRQC does not exist
today), so it is never graded High. The probe is conservative - any ambiguity
or error reports "not observed", never a false positive.
"""
import asyncio
import os
import socket
import ssl

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._payloads.quantum_readiness._loader import (
    PQC_COMPLIANCE, symmetric_margin,
)

router = APIRouter()
_PORT = 443


# ───────────────────────────── live handshake ─────────────────────────────
def _tls_info(host, port=_PORT, timeout=8):
    """(tls_version, (cipher_name, proto, bits), cert_der) or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.version(), ss.cipher(), ss.getpeercert(binary_form=True)
    except Exception:
        return None


def _cert_crypto(der):
    """(signature_algorithm, key_type_string) from a DER cert, best-effort."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
        cert = x509.load_der_x509_certificate(der)
        try:
            sig = cert.signature_algorithm_oid._name
        except Exception:
            sig = "unknown"
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            kt = f"RSA-{pub.key_size}"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            kt = f"ECDSA-{pub.curve.name}"
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            kt = "Ed25519"
        elif isinstance(pub, ed448.Ed448PublicKey):
            kt = "Ed448"
        else:
            kt = type(pub).__name__
        return sig, kt
    except Exception:
        return None, None


# ─────────────────── raw TLS 1.3 PQC-hybrid probe (stdlib) ───────────────────
def _u16(n):
    return n.to_bytes(2, "big")


def _u24(n):
    return n.to_bytes(3, "big")


def _client_hello(host):
    """A TLS 1.3 ClientHello offering supported_groups = [X25519MLKEM768,
    X25519] with a real X25519 key_share. A PQC-capable server that prefers
    the hybrid replies HelloRetryRequest selecting 0x11EC; we read that group."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    x_pub = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    rnd, sid = os.urandom(32), os.urandom(32)
    host_b = host.encode("ascii", "ignore")

    def ext(t, body):
        return _u16(t) + _u16(len(body)) + body

    sni_name = b"\x00" + _u16(len(host_b)) + host_b
    e_sni = ext(0x0000, _u16(len(sni_name)) + sni_name)
    e_ver = ext(0x002b, b"\x02\x03\x04")                       # supported_versions: TLS1.3
    grp = _u16(0x11EC) + _u16(0x001D)
    e_grp = ext(0x000a, _u16(len(grp)) + grp)                  # supported_groups
    sigs = _u16(0x0804) + _u16(0x0403) + _u16(0x0401) + _u16(0x0805) + _u16(0x0806)
    e_sig = ext(0x000d, _u16(len(sigs)) + sigs)                # signature_algorithms
    ks_entry = _u16(0x001D) + _u16(len(x_pub)) + x_pub
    e_ks = ext(0x0033, _u16(len(ks_entry)) + ks_entry)         # key_share (X25519)
    exts = e_sni + e_ver + e_grp + e_sig + e_ks

    body = (b"\x03\x03" + rnd + bytes([len(sid)]) + sid
            + _u16(6) + b"\x13\x01\x13\x02\x13\x03"            # 3 cipher suites
            + b"\x01\x00"                                       # compression: null
            + _u16(len(exts)) + exts)
    hs = b"\x01" + _u24(len(body)) + body
    return b"\x16\x03\x01" + _u16(len(hs)) + hs


def _recv_n(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _selected_group(p):
    """Parse the key_share group out of a ServerHello / HelloRetryRequest."""
    try:
        i = 4 + 2 + 32                       # msg_type+len(3), legacy_version, random
        sid_len = p[i]; i += 1 + sid_len
        i += 2 + 1                           # cipher_suite, compression
        ext_total = int.from_bytes(p[i:i + 2], "big"); i += 2
        end = i + ext_total
        while i + 4 <= end:
            et = int.from_bytes(p[i:i + 2], "big")
            el = int.from_bytes(p[i + 2:i + 4], "big")
            i += 4
            body = p[i:i + el]; i += el
            if et == 0x0033 and len(body) >= 2:
                return int.from_bytes(body[0:2], "big")
        return None
    except Exception:
        return None


def _probe_pqc(host, port=_PORT, timeout=6):
    """'supported' only on a clear positive (server selects X25519MLKEM768),
    else 'not_observed'. Never raises."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(_client_hello(host))
        hdr = _recv_n(s, 5)
        if len(hdr) == 5 and hdr[0] == 0x16:
            payload = _recv_n(s, int.from_bytes(hdr[3:5], "big"))
        else:
            payload = b""
        s.close()
        if payload[:1] == b"\x02" and _selected_group(payload) == 0x11EC:
            return "supported"
        return "not_observed"
    except Exception:
        return "not_observed"


# ───────────────────────────────── gather ─────────────────────────────────
async def gather(ctx):
    host = (ctx.host or "").strip()
    if not host:
        ctx.source("no target")
        return
    info = await asyncio.to_thread(_tls_info, host)
    if not info:
        ctx.state["reachable"] = False
        ctx.source(f"{host}:{_PORT} TLS not reachable")
        return
    tls_version, cipher, der = info
    sig, kt = _cert_crypto(der) if der else (None, None)
    pqc = await asyncio.to_thread(_probe_pqc, host)
    ctx.source(f"{host}:{_PORT} {tls_version} {cipher[0] if cipher else '?'} pqc={pqc}")
    ctx.state.update({
        "reachable": True,
        "tls_version": tls_version,
        "cipher_name": cipher[0] if cipher else None,
        "cipher_bits": cipher[2] if cipher else None,
        "cert_sig": sig,
        "key_type": kt,
        "pqc_status": pqc,
    })


# ───────────────────────────── finding rules ──────────────────────────────
def _r_hndl(s):
    if not s.get("reachable") or s.get("pqc_status") == "supported":
        return None
    return {"name": "No post-quantum key exchange (harvest-now-decrypt-later exposure)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-327", "owasp": "A02:2021",
            "evidence": ("TLS negotiates a classical key exchange and the server did not "
                         "offer a post-quantum hybrid (X25519MLKEM768). An adversary recording "
                         "this traffic today can decrypt it once a CRQC exists."),
            "compliance": PQC_COMPLIANCE,
            "remediation": "Enable a hybrid PQC key exchange (X25519MLKEM768) on the TLS terminator."}


def _r_pqc_ok(s):
    if s.get("pqc_status") != "supported":
        return None
    return {"name": "Post-quantum hybrid key exchange offered (X25519MLKEM768)",
            "severity": "POSITIVE",
            "evidence": "Server selected the X25519MLKEM768 hybrid group - key exchange is quantum-safe."}


def _r_pubkey(s):
    kt = s.get("key_type")
    if not s.get("reachable") or not kt:
        return None
    return {"name": f"Quantum-vulnerable certificate key ({kt})",
            "severity": "INFO", "cwe": "CWE-327",
            "evidence": (f"Certificate public key is {kt} and is signed with {s.get('cert_sig') or 'unknown'} - "
                         "both are breakable by Shor's algorithm on a future quantum computer."),
            "compliance": PQC_COMPLIANCE,
            "remediation": "Track CA support for ML-DSA (FIPS 204) certificates per the NIST IR 8547 timeline."}


def _r_symmetric(s):
    name, bits = s.get("cipher_name"), s.get("cipher_bits")
    if not s.get("reachable") or not bits:
        return None
    margin, verdict = symmetric_margin(name, bits)
    if verdict != "weak":
        return None
    return {"name": f"Symmetric cipher below long-term quantum margin ({name})",
            "severity": "LOW", "cvss": 2.6, "cwe": "CWE-326",
            "evidence": (f"{name} ({bits}-bit) gives ~{margin}-bit effective strength under Grover's "
                         "algorithm. AES-256 is advised for data that must stay secret for 10+ years."),
            "compliance": PQC_COMPLIANCE,
            "remediation": "Prefer AES-256-GCM / ChaCha20 for long-lived confidentiality."}


FINDING_RULES = [_r_hndl, _r_pqc_ok, _r_pubkey, _r_symmetric]
INTEL_FIELDS = [
    ("TLS version", "tls_version"),
    ("Cipher", "cipher_name"),
    ("Cert signature", "cert_sig"),
    ("Cert key type", "key_type"),
    ("PQC hybrid", "pqc_status"),
]


@router.post("/api/quantum_readiness/tls_quantum_exposure")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=recon_host(req.target), tool="tls_quantum_exposure",
        gather_func=gather, finding_rules=FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=["pqc_status", "key_type"],
    )


def register(app):
    app.include_router(router)
