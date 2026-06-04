"""mailbox_security_audit - STARTTLS + cipher + cert audit on the
customer's mail server (playbook §1 #4, §2 cross-ref).

If the customer supplies options.mail_server (e.g. mail.acme.com) and
optionally options.test_smtp_port (default 25), this probe:

  1. Opens a raw socket to mail_server:port and reads the SMTP banner
  2. Sends EHLO, parses the advertised extensions (STARTTLS, AUTH,
     SIZE, PIPELINING, etc.)
  3. If STARTTLS is advertised: issues `STARTTLS\r\n`, completes the
     TLS handshake using ssl.SSLContext(default), captures:
       - negotiated protocol (TLSv1/1.1/1.2/1.3)
       - negotiated cipher suite (name + version + bits)
       - peer certificate (subject, issuer, validity dates, SAN list)
  4. If no STARTTLS is advertised on port 25 BUT options.also_test_465
     is true, also tests implicit-TLS on port 465 (SMTPS / "submissions").
  5. Reports per-issue findings:
       HIGH     - STARTTLS not advertised on port 25 (cleartext SMTP)
       HIGH     - TLS version <= 1.1 (deprecated, RFC 8996)
       HIGH     - cert expired / not-yet-valid / hostname mismatch
       MEDIUM   - cipher uses CBC mode or NULL / EXPORT class
       MEDIUM   - cert SAN does not include mail_server host
       INFO     - missing customer input (no probe run)
       POSITIVE - TLSv1.3 + ECDHE-AES-GCM cipher + valid cert

If the customer does NOT supply options.mail_server, the probe attempts
to derive it from the target domain's MX record (dnspython). This lets
the customer run the probe with just target=acme.com.

Customer input via ScanRequest.options:
  - mail_server      = explicit mail-server hostname (overrides MX)
  - test_smtp_port   = port to test (default 25)
  - also_test_465    = bool, also test implicit-TLS 465 if 25 lacks STARTTLS
  - timeout_sec      = per-connect timeout (default 10s, hard cap 30)

References:
  - RFC 3207 (STARTTLS)
  - RFC 8996 (deprecation of TLS 1.0/1.1)
  - RFC 7672 (DANE for SMTP)
"""
from __future__ import annotations
import asyncio
import socket
import ssl
import time
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.mailbox_security_audit_findings import (
    MAILBOX_SECURITY_AUDIT_FINDING_RULES,
)

router = APIRouter()


class MailboxSecurityRequest(ScanRequest):
    options: Optional[dict] = None


WEAK_CIPHER_KEYWORDS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon")
# CBC mode in TLS<=1.2 is vulnerable to BEAST/Lucky13; flag as MEDIUM.
CBC_CIPHER_MARK = "CBC"


def _normalize_domain(target: str) -> str:
    d = (target or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    if d.lower().startswith("www."):
        d = d[4:]
    return d.lower().rstrip(".")


def _read_smtp_response(sock: socket.socket, timeout: float = 5.0) -> str:
    """Read until we see a multi-line SMTP response is complete.
    SMTP lines look like `250-EXT\r\n` (continues) or `250 EXT\r\n` (last).
    """
    sock.settimeout(timeout)
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        # Look at the most-recent line: if it starts with a 3-digit code
        # followed by a SPACE (not a dash), the response is complete.
        try:
            text = buf.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        last_line = text.strip().split("\r\n")[-1] if text else ""
        if (len(last_line) >= 4 and last_line[:3].isdigit()
                and last_line[3] == " "):
            break
    return buf.decode("utf-8", errors="ignore")


def _parse_ehlo(ehlo_response: str) -> list[str]:
    """Return the list of advertised extensions (everything after `250-`/`250 `)."""
    out = []
    for line in (ehlo_response or "").split("\r\n"):
        line = line.strip()
        if not line or not line[:3].isdigit():
            continue
        body = line[4:].strip()
        if body and not body.lower().startswith(("mail.", "hello")):
            out.append(body)
    return out


def _parse_x509_dates(cert: dict) -> tuple[Optional[datetime], Optional[datetime]]:
    """ssl.getpeercert() returns dates as 'Jul 15 14:25:36 2025 GMT'."""
    nb = na = None
    fmt = "%b %d %H:%M:%S %Y %Z"
    nb_s = cert.get("notBefore") if cert else None
    na_s = cert.get("notAfter") if cert else None
    try:
        nb = datetime.strptime(nb_s, fmt) if nb_s else None
    except Exception:
        nb = None
    try:
        na = datetime.strptime(na_s, fmt) if na_s else None
    except Exception:
        na = None
    return nb, na


def _extract_sans(cert: dict) -> list[str]:
    sans = []
    if not cert:
        return sans
    for kind, name in cert.get("subjectAltName") or []:
        if kind.lower() == "dns":
            sans.append(name.lower())
    return sans


def _hostname_matches(host: str, sans: list[str], cn: str = "") -> bool:
    """Wildcard-aware host match."""
    h = host.lower().rstrip(".")
    candidates = list(sans)
    if cn:
        candidates.append(cn.lower())
    for c in candidates:
        if c == h:
            return True
        if c.startswith("*."):
            suffix = c[2:]
            # Wildcard matches exactly one label
            if h.endswith("." + suffix) and h.count(".") == suffix.count(".") + 1:
                return True
    return False


def _resolve_mx(domain: str) -> Optional[str]:
    """Pure-Python MX resolution via dnspython. Returns top-priority MX host."""
    try:
        import dns.resolver
    except ImportError:
        return None
    try:
        ans = dns.resolver.resolve(domain, "MX", lifetime=8.0)
    except Exception:
        return None
    best = None
    best_pref = 10_000
    for r in ans:
        try:
            pref = int(getattr(r, "preference", 9999))
            host = str(getattr(r, "exchange", "")).rstrip(".")
            if host and pref < best_pref:
                best = host
                best_pref = pref
        except Exception:
            continue
    return best


def _probe_starttls(host: str, port: int, timeout: float) -> dict:
    """Connect, EHLO, STARTTLS, capture TLS + cert info.
    All exceptions are caught and returned as `error` in the result
    dict — we want one row per port, never a crashed scan."""
    out: dict = {
        "host":             host,
        "port":             port,
        "banner":           None,
        "ehlo_extensions":  [],
        "starttls_offered": False,
        "starttls_ok":      False,
        "tls_version":      None,
        "cipher":           None,
        "cipher_version":   None,
        "cipher_bits":      None,
        "weak_cipher":      False,
        "cbc_cipher":       False,
        "cert_subject":     None,
        "cert_issuer":      None,
        "cert_not_before":  None,
        "cert_not_after":   None,
        "cert_days_left":   None,
        "cert_expired":     False,
        "cert_not_yet":     False,
        "cert_sans":        [],
        "cert_host_match":  None,
        "error":            None,
    }
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        # Implicit TLS on 465: wrap the socket right away.
        implicit_tls = (port == 465)
        if implicit_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False    # we'll validate manually
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            out["starttls_offered"] = True
            out["starttls_ok"] = True
            sock = tls_sock
        else:
            banner = _read_smtp_response(sock, timeout=timeout)
            out["banner"] = banner.strip()[:200]
            sock.sendall(f"EHLO vulnuslab.probe\r\n".encode())
            ehlo = _read_smtp_response(sock, timeout=timeout)
            out["ehlo_extensions"] = _parse_ehlo(ehlo)
            offered = any(e.upper().startswith("STARTTLS")
                          for e in out["ehlo_extensions"])
            out["starttls_offered"] = offered
            if not offered:
                return out
            sock.sendall(b"STARTTLS\r\n")
            resp = _read_smtp_response(sock, timeout=timeout)
            if not resp.strip().startswith("220"):
                out["error"] = f"STARTTLS rejected: {resp.strip()[:120]}"
                return out
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            out["starttls_ok"] = True
            sock = tls_sock
        # Capture TLS details
        try:
            out["tls_version"] = sock.version()
        except Exception:
            pass
        try:
            cipher = sock.cipher() or ()
            if cipher:
                out["cipher"] = cipher[0]
                out["cipher_version"] = cipher[1]
                out["cipher_bits"] = cipher[2]
                cu = (cipher[0] or "").upper()
                out["weak_cipher"] = any(k in cu for k in WEAK_CIPHER_KEYWORDS)
                out["cbc_cipher"] = CBC_CIPHER_MARK in cu
        except Exception:
            pass
        try:
            der = sock.getpeercert(binary_form=False) or {}
            # Subject + issuer come as tuple-of-tuples
            subj = ", ".join(f"{k}={v}" for tu in (der.get("subject") or [])
                              for k, v in tu)
            iss = ", ".join(f"{k}={v}" for tu in (der.get("issuer") or [])
                              for k, v in tu)
            out["cert_subject"] = subj or None
            out["cert_issuer"] = iss or None
            nb, na = _parse_x509_dates(der)
            if nb:
                out["cert_not_before"] = nb.isoformat() + "Z"
            if na:
                out["cert_not_after"] = na.isoformat() + "Z"
                now = datetime.utcnow()
                out["cert_days_left"] = (na - now).days
                out["cert_expired"] = now > na
            if nb:
                now = datetime.utcnow()
                out["cert_not_yet"] = now < nb
            sans = _extract_sans(der)
            out["cert_sans"] = sans
            # Common-name fallback for hostname match
            cn = ""
            for tu in (der.get("subject") or []):
                for k, v in tu:
                    if k.lower() == "commonname":
                        cn = v
            out["cert_host_match"] = _hostname_matches(host, sans, cn)
        except Exception:
            pass
    except (socket.timeout, ConnectionRefusedError, socket.gaierror,
            OSError, ssl.SSLError) as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:120]}"
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:120]}"
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
    return out


async def gather(ctx: ScanContext):
    domain = _normalize_domain(ctx.host or "")
    if not domain:
        ctx.source("no-target")
        return

    opts = ctx.state.get("_options") or {}
    explicit_host = (opts.get("mail_server") or "").strip()
    try:
        port = int(opts.get("test_smtp_port") or 25)
    except (TypeError, ValueError):
        port = 25
    try:
        timeout = min(max(int(opts.get("timeout_sec") or 10), 3), 30)
    except (TypeError, ValueError):
        timeout = 10
    also_test_465 = bool(opts.get("also_test_465"))

    mx_used = False
    if explicit_host:
        mail_host = explicit_host
    else:
        mx = await asyncio.get_event_loop().run_in_executor(None, _resolve_mx, domain)
        if not mx:
            ctx.state["mailbox_input_missing"] = True
            ctx.state["mailbox_target_domain"] = domain
            ctx.source("no mail_server + no MX record")
            return
        mail_host = mx
        mx_used = True

    ctx.state["mailbox_target_domain"] = domain
    ctx.state["mailbox_mail_host"] = mail_host
    ctx.state["mailbox_test_port"] = port
    ctx.state["mailbox_mx_derived"] = mx_used

    # Run the socket-blocking probe in a thread so we don't stall the loop
    loop = asyncio.get_event_loop()
    primary = await loop.run_in_executor(
        None, _probe_starttls, mail_host, port, float(timeout)
    )
    ctx.state["mailbox_primary"] = primary
    ctx.source(
        f"SMTP {mail_host}:{port} -> "
        f"{'STARTTLS ok' if primary.get('starttls_ok') else 'no STARTTLS'}"
        + (f" ({primary['error']})" if primary.get("error") else "")
    )

    secondary = None
    if also_test_465 and not primary.get("starttls_ok") and port != 465:
        secondary = await loop.run_in_executor(
            None, _probe_starttls, mail_host, 465, float(timeout)
        )
        ctx.state["mailbox_secondary_465"] = secondary
        ctx.source(
            f"SMTPS {mail_host}:465 -> "
            f"{'TLS ok' if secondary.get('starttls_ok') else 'failed'}"
        )


INTEL_FIELDS = [
    ("Target domain",         "mailbox_target_domain"),
    ("Mail host probed",      "mailbox_mail_host"),
    ("Derived via MX",        "mailbox_mx_derived"),
    ("Port probed",           "mailbox_test_port"),
    ("Primary probe result",  "mailbox_primary"),
    ("Implicit-TLS 465 probe", "mailbox_secondary_465"),
]


@router.post("/api/phishing/mailbox_security_audit")
async def phishing_mailbox_security_audit(req: MailboxSecurityRequest,
                                            _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="mailbox_security_audit",
        gather_func=_gather_with_options,
        finding_rules=MAILBOX_SECURITY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
