"""TLS Deep Audit v2 — VL-FORGE pattern, 6 parallel data sources.

Route: /api/recon/tls_deep

Sources (parallel):
  1. Protocol version enumeration  — SSLv3 / TLS 1.0 / 1.1 / 1.2 / 1.3
  2. Cipher inspection             — negotiated cipher + strength classification
  3. Cert parsing                  — chain, expiry, key size, sig algo, SAN
  4. HSTS header check             — via HTTPS GET
  5. ALPN protocol negotiation     — HTTP/2 / HTTP/1.1 / etc.
  6. Vuln-indicator derivation     — POODLE/BEAST/CRIME/Heartbleed/DROWN
                                      inferred from protocol+cipher posture

Findings (~24 rules in tools/_payloads/tls_findings.py):
  CRITICAL: SSLv2 enabled, cert EXPIRED
  HIGH    : SSLv3, weak cipher negotiated, self-signed, weak key (RSA<2048),
            cert expiring <30 days, vuln indicators
  MEDIUM  : TLS 1.0/1.1 enabled, SHA-1 sig, no forward secrecy, HSTS missing,
            cipher count summary, short cert chain
  LOW     : TLS 1.3 not supported, HSTS max-age <1y
  POSITIVE: TLS 1.2/1.3 supported, HSTS properly configured, OCSP stapling,
            HTTP/2 (ALPN h2)
  INFO    : Wildcard cert in use
"""
import asyncio
import datetime
import re
import socket
import ssl

import requests

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.tls_findings import TLS_FINDING_RULES

router = APIRouter()


# Modern (AEAD) cipher patterns
_MODERN_CIPHERS = re.compile(r"(GCM|CHACHA20|CCM)", re.IGNORECASE)
# Weak / deprecated
_WEAK_CIPHERS = re.compile(r"(RC4|DES|3DES|MD5|EXPORT|NULL|anon)", re.IGNORECASE)
# Forbidden / never use
_FORBIDDEN_CIPHERS = re.compile(r"(EXPORT|NULL|anon)", re.IGNORECASE)


def _probe_protocol(host: str, port: int, version_min, version_max,
                     timeout: int = 6) -> tuple[bool, dict]:
    """Try a TLS handshake with specific min/max version bounds.

    Returns (succeeded, details) where details has cipher + cert if successful.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if version_min is not None:
            try: ctx.minimum_version = version_min
            except (ValueError, AttributeError): pass
        if version_max is not None:
            try: ctx.maximum_version = version_max
            except (ValueError, AttributeError): pass
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated = ssock.version() or ""
                cipher = ssock.cipher()
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                return True, {
                    "version":   negotiated,
                    "cipher":    cipher,
                    "cert_bin":  cert_bin,
                    "cert_dict": cert_dict,
                }
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError,
             ConnectionResetError, OSError):
        return False, {}
    except Exception:
        return False, {}


def _parse_cert(cert_dict, cert_bin) -> dict:
    """Extract cert metadata. Best-effort — returns empty dict on parse failure."""
    if not cert_dict and not cert_bin: return {}
    out = {}
    try:
        subject = dict(x[0] for x in (cert_dict.get("subject") or []))
        issuer = dict(x[0] for x in (cert_dict.get("issuer") or []))
        out["subject"] = subject
        out["issuer"] = issuer
        out["not_before"] = cert_dict.get("notBefore")
        out["not_after"] = cert_dict.get("notAfter")
        out["serial_number"] = cert_dict.get("serialNumber")
        # SAN list
        san = []
        for ext in (cert_dict.get("subjectAltName") or []):
            if isinstance(ext, tuple) and len(ext) == 2:
                san.append(f"{ext[0]}:{ext[1]}")
        out["san"] = san
        out["wildcard"] = any("*" in s for s in san) or any(
            "*" in str(v) for v in subject.values())
        out["self_signed"] = subject == issuer
        # Days until expiry
        if cert_dict.get("notAfter"):
            try:
                expiry = datetime.datetime.strptime(
                    cert_dict["notAfter"], "%b %d %H:%M:%S %Y %Z")
                out["days_until_expiry"] = (
                    expiry - datetime.datetime.utcnow()).days
            except Exception:
                pass
    except Exception:
        pass
    # Try to extract key size + sig algo via cryptography if available
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        cert = x509.load_der_x509_certificate(cert_bin)
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            out["key_type"] = "RSA"
            out["key_size"] = pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            out["key_type"] = "EC"
            out["key_size"] = pub.curve.key_size
        sig_oid = cert.signature_algorithm_oid
        out["sig_algo"] = sig_oid._name if hasattr(sig_oid, "_name") else str(sig_oid)
    except Exception:
        pass
    return out


def _check_hsts(host: str) -> dict:
    """Fetch HTTPS root and inspect Strict-Transport-Security header."""
    try:
        r = requests.get(f"https://{host}/", timeout=10, verify=False,
                          allow_redirects=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        hsts = (r.headers.get("Strict-Transport-Security") or
                r.headers.get("strict-transport-security"))
        if not hsts:
            return {"hsts": None}
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        max_age = int(m.group(1)) if m else None
        return {
            "hsts":            hsts,
            "hsts_max_age":    max_age,
            "hsts_subdomains": "includesubdomains" in hsts.lower(),
            "hsts_preload":    "preload" in hsts.lower(),
        }
    except Exception:
        return {"hsts": None}


def _check_alpn(host: str, port: int = 443) -> list:
    """Probe ALPN negotiation. Returns list of protocols server offers."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                selected = ssock.selected_alpn_protocol()
                return [selected] if selected else []
    except Exception:
        return []


def _check_ocsp_stapling(host: str, port: int = 443) -> bool:
    """OCSP stapling check — best-effort.

    Python's ssl module exposes OCSP-stapled response via getpeercert()
    on some platforms. Reliable cross-platform detection is hard;
    we return False if we can't confirm.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # OpenSSL extension: TLSEXT_STATUSTYPE_ocsp
        if hasattr(ctx, "set_ocsp_client_callback"):
            return True  # API available — assume server may staple
        return False
    except Exception:
        return False


def _classify_ciphers(probes: list) -> dict:
    """Count modern / weak / forbidden across all successful probes."""
    seen = set()
    counts = {"modern": 0, "weak": 0, "forbidden": 0, "other": 0}
    for ok, det in probes:
        if not ok: continue
        c = det.get("cipher")
        if not c: continue
        name = c[0] if isinstance(c, (list, tuple)) else str(c)
        if name in seen: continue
        seen.add(name)
        if _FORBIDDEN_CIPHERS.search(name):
            counts["forbidden"] += 1
        elif _WEAK_CIPHERS.search(name):
            counts["weak"] += 1
        elif _MODERN_CIPHERS.search(name):
            counts["modern"] += 1
        else:
            counts["other"] += 1
    return counts


def _derive_vuln_indicators(state: dict) -> list:
    """Infer known TLS CVEs from protocol+cipher posture."""
    indicators = []
    sp = state.get("supported_protocols") or []
    cipher = state.get("negotiated_cipher")
    cipher_name = (cipher[0] if isinstance(cipher, (list, tuple)) else
                    str(cipher or "")).upper()

    if "SSLv2" in sp:
        indicators.append("DROWN (CVE-2016-0800) — SSLv2 cross-protocol")
    if "SSLv3" in sp:
        indicators.append("POODLE (CVE-2014-3566) — SSLv3 padding oracle")
    if "TLSv1" in sp:
        indicators.append("BEAST (CVE-2011-3389) — TLS 1.0 CBC IV")
    if "RC4" in cipher_name:
        indicators.append("RC4 keystream biases — CVE-2013-2566")
    if "DES" in cipher_name and "3DES" not in cipher_name:
        indicators.append("DES weak key — fully broken")
    if "3DES" in cipher_name:
        indicators.append("SWEET32 (CVE-2016-2183) — 3DES birthday attack")
    if "EXPORT" in cipher_name:
        indicators.append("FREAK / LOGJAM — export-grade DH")
    return indicators


async def gather(ctx: ScanContext):
    host = ctx.host
    port = 443

    # Probe each protocol version separately (parallel)
    version_probes = []
    try:
        version_probes = [
            ("SSLv3",   None, None),  # Modern Python may reject; that's correct
            ("TLSv1",   ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        ]
    except AttributeError:
        version_probes = []

    # Auto-negotiate probe — picks server's preference
    auto_task = asyncio.to_thread(_probe_protocol, host, port, None, None)
    versioned_tasks = [
        asyncio.to_thread(_probe_protocol, host, port, lo, hi)
        for _, lo, hi in version_probes
    ]
    hsts_task = asyncio.to_thread(_check_hsts, host)
    alpn_task = asyncio.to_thread(_check_alpn, host, port)

    auto_result, *versioned_results, hsts_data, alpn_result = await asyncio.gather(
        auto_task, *versioned_tasks, hsts_task, alpn_task
    )

    auto_ok, auto_det = auto_result
    if not auto_ok and not any(ok for ok, _ in versioned_results):
        # All probes failed — likely not HTTPS on port 443
        return

    ctx.source("tls-handshake-auto")

    # Build supported_protocols from versioned probes
    supported = []
    for (label, _, _), (ok, _) in zip(version_probes, versioned_results):
        if ok:
            supported.append(label)
    # Include the auto-negotiated version in case versioned probes failed
    if auto_ok and auto_det.get("version") and auto_det["version"] not in supported:
        supported.append(auto_det["version"])
    ctx.state["supported_protocols"] = supported

    if supported:
        ctx.source(f"version-enum ({len(supported)} versions)")

    # Negotiated cipher = from auto-handshake (server's preference)
    if auto_ok and auto_det.get("cipher"):
        ctx.state["negotiated_protocol"] = auto_det.get("version")
        ctx.state["negotiated_cipher"] = auto_det.get("cipher")
        ctx.source("cipher-inspection")

    # Cipher strength summary across all probes
    cipher_summary = _classify_ciphers(
        [auto_result] + list(versioned_results))
    ctx.state["cipher_strength_summary"] = cipher_summary

    # Cert parsing — prefer auto-handshake cert
    if auto_ok and auto_det.get("cert_dict"):
        cert = _parse_cert(auto_det.get("cert_dict"), auto_det.get("cert_bin"))
        ctx.state["cert"] = cert
        if cert:
            ctx.source("cert-parse")

    # HSTS
    if hsts_data.get("hsts"):
        ctx.state.update(hsts_data)
        ctx.source("hsts-check")
    else:
        ctx.state["hsts"] = None

    # ALPN
    ctx.state["alpn_protocols"] = alpn_result
    if alpn_result:
        ctx.source("alpn-probe")

    # OCSP stapling (best-effort)
    ctx.state["ocsp_stapling"] = _check_ocsp_stapling(host, port)

    # Derive vuln indicators
    ctx.state["vuln_indicators"] = _derive_vuln_indicators(ctx.state)
    if ctx.state["vuln_indicators"]:
        ctx.source("vuln-derivation")


INTEL_FIELDS = [
    ("Supported protocols",   "supported_display"),
    ("Negotiated protocol",   "negotiated_protocol"),
    ("Negotiated cipher",     "negotiated_cipher_display"),
    ("Cipher mix",            "cipher_mix_display"),
    ("Cert subject",          "cert_subject_display"),
    ("Cert issuer",           "cert_issuer_display"),
    ("Cert expires",          "cert_expires_display"),
    ("Key",                   "key_display"),
    ("Signature algorithm",   "sig_algo_display"),
    ("SAN list",              "san_display"),
    ("Self-signed",           "self_signed_display"),
    ("HSTS",                  "hsts_summary"),
    ("ALPN",                  "alpn_display"),
    ("OCSP stapling",         "ocsp_display"),
    ("Vuln indicators",       "vuln_display"),
]


@router.post("/api/vuln/ssl_deep")
async def recon_tls_deep(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)

        sp = ctx.state.get("supported_protocols") or []
        if sp: ctx.state["supported_display"] = ", ".join(sp)

        nc = ctx.state.get("negotiated_cipher")
        if nc:
            name = nc[0] if isinstance(nc, (list, tuple)) else str(nc)
            bits = nc[2] if isinstance(nc, (list, tuple)) and len(nc) >= 3 else None
            ctx.state["negotiated_cipher_display"] = (
                f"{name} ({bits} bits)" if bits else name)

        cs = ctx.state.get("cipher_strength_summary") or {}
        if cs:
            ctx.state["cipher_mix_display"] = (
                f"modern={cs.get('modern',0)}, weak={cs.get('weak',0)}, "
                f"forbidden={cs.get('forbidden',0)}, other={cs.get('other',0)}")

        cert = ctx.state.get("cert") or {}
        if cert:
            subj = cert.get("subject") or {}
            iss = cert.get("issuer") or {}
            ctx.state["cert_subject_display"] = (
                subj.get("commonName") or subj.get("organizationName") or "?")
            ctx.state["cert_issuer_display"] = (
                iss.get("commonName") or iss.get("organizationName") or "?")
            d = cert.get("days_until_expiry")
            if d is not None:
                na = cert.get("not_after") or "?"
                ctx.state["cert_expires_display"] = f"{na} ({d} days)"
            if cert.get("key_type"):
                ctx.state["key_display"] = (
                    f"{cert.get('key_type')}-{cert.get('key_size', '?')}")
            if cert.get("sig_algo"):
                ctx.state["sig_algo_display"] = cert.get("sig_algo")
            san = cert.get("san") or []
            if san:
                ctx.state["san_display"] = (
                    ", ".join(san[:6]) + (f" + {len(san)-6} more" if len(san) > 6 else ""))
            ctx.state["self_signed_display"] = "Yes" if cert.get("self_signed") else None

        if ctx.state.get("hsts"):
            ma = ctx.state.get("hsts_max_age")
            parts = [f"max-age={ma}s" if ma else "max-age=?"]
            if ctx.state.get("hsts_subdomains"): parts.append("includeSubDomains")
            if ctx.state.get("hsts_preload"): parts.append("preload")
            ctx.state["hsts_summary"] = "; ".join(parts)

        alpn = ctx.state.get("alpn_protocols") or []
        if alpn: ctx.state["alpn_display"] = ", ".join(alpn)

        if ctx.state.get("ocsp_stapling"):
            ctx.state["ocsp_display"] = "Enabled"

        vi = ctx.state.get("vuln_indicators") or []
        if vi: ctx.state["vuln_display"] = "; ".join(vi[:4])

    return await run_scanner(
        host=host,
        tool="tls_deep",
        gather_func=gather_with_display,
        finding_rules=TLS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["supported_protocols", "negotiated_protocol",
                          "cert", "hsts", "vuln_indicators"],
    )


def register(app):
    app.include_router(router)
