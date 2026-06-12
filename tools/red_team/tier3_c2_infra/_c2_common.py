"""Shared READ-ONLY helpers for red_team tier3_c2_infra exposure probes.

All helpers perform external, unauthenticated inspection only — base-URL
normalisation, HTTP GET with header/body capture, and a passive TLS
certificate read. No mutating verbs, no payloads, no credential attempts.
Everything degrades safely on error (returns None / empty, never raises).
"""
from __future__ import annotations

import socket
import ssl
from urllib.parse import urlsplit, urlunsplit


def normalize_base(target: str) -> str | None:
    """Turn a customer target (URL or bare host[:port]) into scheme://host[:port]
    with no path. Returns None for empty/garbage input."""
    if not target:
        return None
    t = target.strip()
    if not t:
        return None
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    try:
        parts = urlsplit(t)
        if not parts.netloc:
            return None
        return urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    except Exception:
        return None


def base_variants(target: str) -> list[str]:
    """De-duplicated scheme variants to probe (https + http) for a bare host,
    or just the supplied scheme if the customer was explicit."""
    if not target:
        return []
    t = target.strip()
    explicit_scheme = t.startswith(("http://", "https://"))
    base = normalize_base(t)
    if not base:
        return []
    if explicit_scheme:
        return [base]
    parts = urlsplit(base)
    https = urlunsplit(("https", parts.netloc, "", "", ""))
    http = urlunsplit(("http", parts.netloc, "", "", ""))
    out = []
    for u in (https, http):
        if u not in out:
            out.append(u)
    return out


def host_port_from_base(base: str, default_port: int | None = None) -> tuple[str, int] | None:
    """Extract (host, port) from a normalized base URL."""
    try:
        parts = urlsplit(base)
        host = parts.hostname
        if not host:
            return None
        port = parts.port
        if port is None:
            if default_port is not None:
                port = default_port
            else:
                port = 443 if parts.scheme == "https" else 80
        return host, int(port)
    except Exception:
        return None


def safe_join(base: str, path: str) -> str:
    if not base.endswith("/") and not path.startswith("/"):
        return base + "/" + path
    if base.endswith("/") and path.startswith("/"):
        return base + path[1:]
    return base + path


def build_headers(ua: str, extra_headers=None) -> dict:
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/json,application/xhtml+xml,*/*",
    }
    if isinstance(extra_headers, dict):
        for k, v in extra_headers.items():
            try:
                headers[str(k)] = str(v)
            except Exception:
                continue
    return headers


def body_excerpt(text, limit: int = 220) -> str:
    """Single-line trimmed excerpt for evidence."""
    if not text:
        return ""
    try:
        s = text if isinstance(text, str) else str(text)
    except Exception:
        return ""
    s = " ".join(s.split())
    return (s[:limit] + "...") if len(s) > limit else s


def read_tls_cert(host: str, port: int, timeout: float = 6.0) -> dict | None:
    """Passive TLS handshake -> certificate subject/issuer/SAN read.

    Read-only: we open a socket, complete the handshake, read the peer cert,
    then close. No data is sent on the channel. Returns None on any error.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
    except Exception:
        return None

    def _flatten(rdns):
        out = {}
        for rdn in rdns or ():
            for k, v in rdn:
                out[k] = v
        return out

    try:
        subject = _flatten(cert.get("subject"))
        issuer = _flatten(cert.get("issuer"))
        sans = [v for (t, v) in cert.get("subjectAltName", ()) if t == "DNS"]
        return {
            "subject": subject,
            "issuer": issuer,
            "subject_cn": subject.get("commonName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "san": sans,
            "serialNumber": cert.get("serialNumber", ""),
            "notBefore": cert.get("notBefore", ""),
            "notAfter": cert.get("notAfter", ""),
            "tls_version": version,
            "cipher": cipher[0] if cipher else "",
        }
    except Exception:
        return None
