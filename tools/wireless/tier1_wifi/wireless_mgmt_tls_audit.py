"""wireless_mgmt_tls_audit - inspect the TLS posture of an internet-exposed
wireless management / RADIUS plane (playbook §4 #35 EAP-TLS cert-chain audit
context, plus management-plane TLS hygiene).

Genuinely SaaS-probeable: when a wireless AP / WLAN controller / RADIUS server
exposes an HTTPS (or RADSEC/EAP-TLS-style) endpoint to the public internet, the
served certificate + negotiated TLS parameters are observable remotely with no
RF hardware. This probe connects, reads the leaf certificate + negotiated
protocol/cipher, and flags ONLY actively-confirmed weaknesses:

  - Expired or not-yet-valid certificate (date math on the served cert).
  - Default / vendor self-signed certificate (issuer == subject and issuer/CN
    matches a known AP/controller vendor default-cert string).
  - Deprecated TLS protocol negotiated (TLSv1.0 / TLSv1.1 / SSLv3).

Everything else is INFO / POSITIVE context. No exploitation, no downgrade
attack, no flooding — a single read-only TLS handshake.

Customer input:
  ScanRequest.target            = hostname / IP of the mgmt plane.
  ScanRequest.options.port      = HTTPS/TLS port (default 443).
"""
from __future__ import annotations
import asyncio
import contextvars
import datetime
import re
import socket
import ssl
from fastapi import APIRouter, Depends, Request
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.wireless_mgmt_tls_audit_findings import (
    WIRELESS_MGMT_TLS_AUDIT_FINDING_RULES,
)

router = APIRouter()
TLS_TIMEOUT = 6.0
DEFAULT_PORT = 443

_REQ_OPTS: contextvars.ContextVar = contextvars.ContextVar("wtls_opts", default={})

# Strings that strongly indicate a default / vendor-shipped self-signed cert on
# a wireless AP or controller. Matched against issuer/subject CN + org fields.
_DEFAULT_CERT_MARKERS = [
    "ubnt", "ubiquiti", "unifi",
    "cisco", "airespace", "meraki",
    "aruba", "instant", "clearpass",
    "ruckus", "smartzone",
    "mikrotik", "routeros",
    "openwrt", "lede", "dd-wrt",
    "tp-link", "tplink", "omada",
    "netgear",
    "default", "self-signed", "selfsigned",
    "localhost", "example.com", "snakeoil",
    "freeradius", "radius",
]

_DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}


def _parse_cert_dt(value: str):
    """Parse an OpenSSL cert date like 'Jun  1 12:00:00 2027 GMT'."""
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.datetime.strptime(value, fmt)
        except Exception:
            continue
    return None


def _flatten_name(name_tuples) -> dict:
    """Flatten getpeercert() subject/issuer tuple-of-tuples into a dict."""
    out: dict[str, str] = {}
    try:
        for rdn in (name_tuples or ()):
            for k, v in rdn:
                out[str(k)] = str(v)
    except Exception:
        pass
    return out


def _tls_inspect_blocking(host: str, port: int) -> dict:
    """Single read-only TLS handshake; return cert + protocol details.
    Never raises — returns {'error': ...} on failure."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                proto = ssock.version() or ""
                cipher = ssock.cipher() or ("", "", 0)
                subj = _flatten_name(cert.get("subject"))
                issuer = _flatten_name(cert.get("issuer"))
                return {
                    "reachable": True,
                    "protocol": proto,
                    "cipher": cipher[0] if cipher else "",
                    "subject": subj,
                    "issuer": issuer,
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "san": [v for (_t, v) in cert.get("subjectAltName", ())],
                }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"reachable": False, "error": "tcp/tls connect failed"}
    except ssl.SSLError as e:
        # Endpoint answered but TLS handshake had an issue — still informative.
        return {"reachable": True, "error": f"ssl: {str(e)[:160]}", "protocol": ""}
    except Exception as e:
        return {"reachable": False, "error": str(e)[:160]}


async def gather(ctx: ScanContext):
    opts = _REQ_OPTS.get() or {}
    raw = (ctx.host or "").strip()
    if not raw:
        ctx.state["no_target"] = True
        ctx.state["wireless_mgmt_tls_audit_total"] = 0
        ctx.source("no target")
        return

    host = raw
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/]+)", raw)
    if m:
        host = m.group(1)
    host = host.split("/")[0].split("?")[0]
    if "@" in host:
        host = host.split("@")[-1]
    port = DEFAULT_PORT
    try:
        if opts.get("port"):
            port = int(opts["port"])
    except Exception:
        port = DEFAULT_PORT
    if host.count(":") == 1 and not host.startswith("["):
        h, maybe_port = host.split(":")
        host = h
        try:
            port = int(maybe_port)
        except Exception:
            pass
    host = host.strip("[]")

    # Resolve first — internal-only hosts are correctly out of scope.
    try:
        resolved_ip = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.gethostbyname(host)
        )
    except Exception:
        ctx.state["resolve_failed"] = host
        ctx.state["wireless_mgmt_tls_audit_total"] = 0
        ctx.source(f"could not resolve {host}")
        return
    ctx.state["resolved_ip"] = resolved_ip
    ctx.state["target_host"] = host
    ctx.state["tls_port"] = port

    info = await asyncio.get_event_loop().run_in_executor(
        None, _tls_inspect_blocking, host, port
    )
    if not info.get("reachable"):
        ctx.state["tls_unreachable"] = True
        ctx.state["tls_error"] = info.get("error", "")
        ctx.state["wireless_mgmt_tls_audit_total"] = 0
        ctx.source(f"{host}:{port} TLS not reachable")
        return

    proto = info.get("protocol", "") or ""
    subj = info.get("subject", {})
    issuer = info.get("issuer", {})
    not_after = info.get("not_after", "")
    not_before = info.get("not_before", "")

    # --- Confirmed conditions (date math + string match on the served cert) ---
    now = datetime.datetime.utcnow()
    na_dt = _parse_cert_dt(not_after)
    nb_dt = _parse_cert_dt(not_before)
    cert_expired = bool(na_dt and na_dt < now)
    cert_not_yet_valid = bool(nb_dt and nb_dt > now)

    issuer_cn = (issuer.get("commonName", "") or "")
    issuer_org = (issuer.get("organizationName", "") or "")
    subject_cn = (subj.get("commonName", "") or "")
    subject_org = (subj.get("organizationName", "") or "")
    self_signed = bool(issuer) and (issuer == subj)
    id_blob = f"{issuer_cn} {issuer_org} {subject_cn} {subject_org}".lower()
    vendor_default = self_signed and any(mk in id_blob for mk in _DEFAULT_CERT_MARKERS)

    proto_norm = proto.replace(" ", "")
    deprecated_tls = proto_norm in _DEPRECATED_PROTOCOLS

    ctx.state["tls_protocol"] = proto
    ctx.state["tls_cipher"] = info.get("cipher", "")
    ctx.state["cert_subject_cn"] = subject_cn
    ctx.state["cert_issuer_cn"] = issuer_cn
    ctx.state["cert_not_before"] = not_before
    ctx.state["cert_not_after"] = not_after
    ctx.state["cert_san"] = info.get("san", [])
    ctx.state["cert_expired"] = cert_expired
    ctx.state["cert_not_yet_valid"] = cert_not_yet_valid
    ctx.state["cert_self_signed"] = self_signed
    ctx.state["cert_vendor_default"] = vendor_default
    ctx.state["tls_deprecated_protocol"] = deprecated_tls

    graded = sum([
        1 if cert_expired or cert_not_yet_valid else 0,
        1 if vendor_default else 0,
        1 if deprecated_tls else 0,
    ])
    ctx.state["wireless_mgmt_tls_audit_total"] = graded
    ctx.source(
        f"{host}:{port} TLS {proto}; cert '{subject_cn or 'n/a'}' issued by "
        f"'{issuer_cn or 'n/a'}'; expired={cert_expired} "
        f"vendor_default={vendor_default} deprecated_tls={deprecated_tls}"
    )


INTEL_FIELDS = [
    ("Target host", "target_host"),
    ("Resolved IP", "resolved_ip"),
    ("TLS port", "tls_port"),
    ("Negotiated protocol", "tls_protocol"),
    ("Negotiated cipher", "tls_cipher"),
    ("Cert subject CN", "cert_subject_cn"),
    ("Cert issuer CN", "cert_issuer_cn"),
    ("Cert valid from", "cert_not_before"),
    ("Cert valid until", "cert_not_after"),
    ("Cert SAN", "cert_san"),
]


@router.post("/api/wireless/wireless_mgmt_tls_audit")
async def wireless_wireless_mgmt_tls_audit(req: ScanRequest, request: Request,
                                           _=Depends(verify_scan_quota)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    _REQ_OPTS.set(body.get("options") or {})
    return await run_scanner(host=req.target, tool="wireless_mgmt_tls_audit",
        gather_func=gather, finding_rules=WIRELESS_MGMT_TLS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
