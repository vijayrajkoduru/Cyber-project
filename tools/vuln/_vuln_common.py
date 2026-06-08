"""tools/vuln/_vuln_common.py - shared probe helpers for Vuln scanners.
Underscore-prefixed so the autoloader skips it (helper, not a scanner)."""
import json
import socket
import ssl
import urllib.error
import urllib.request

_UA = "Mozilla/5.0 (VulnusLab Vuln)"
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


def tcp_probe(host, port, payload=b"", read=256, timeout=4):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return False, b""
    try:
        if payload:
            s.sendall(payload)
        s.settimeout(timeout)
        try:
            data = s.recv(read)
        except Exception:
            data = b""
        return True, data
    finally:
        try:
            s.close()
        except Exception:
            pass


def port_open(host, port, timeout=4):
    ok, _ = tcp_probe(host, port, b"", 1, timeout)
    return ok


def http_get(url, timeout=10, read=200000):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            body = r.read(read)
            return {"status": r.status,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": body.decode("utf-8", "ignore")}
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return {"status": e.code, "headers": hdrs, "body": ""}
    except Exception:
        return None


def http_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            return json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return None


# ── Web-probe helpers (used by tier3_web_active + tier4_auth_scan passives) ──
def http_get_h(url, headers=None, timeout=10, read=200000):
    """HTTP GET with custom headers (CORS, Host injection, etc)."""
    h = {"User-Agent": _UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, method="GET", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            body = r.read(read)
            return {"status": r.status,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": body.decode("utf-8", "ignore"),
                    "url": r.url}
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return {"status": e.code, "headers": hdrs, "body": "", "url": url}
    except Exception:
        return None


def http_post(url, data=b"", headers=None, timeout=10):
    """HTTP POST raw body."""
    h = {"User-Agent": _UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method="POST", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            body = r.read(200000)
            return {"status": r.status,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": body.decode("utf-8", "ignore")}
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return {"status": e.code, "headers": hdrs, "body": ""}
    except Exception:
        return None


def probe_url(host, path="/", scheme=None, timeout=10):
    """Smart URL probe: tries https first, falls back to http. Returns (url, response)."""
    if scheme:
        url = f"{scheme}://{host}{path}"
        r = http_get(url, timeout=timeout)
        return (url, r)
    # Try https first
    for s in ("https", "http"):
        url = f"{s}://{host}{path}"
        r = http_get(url, timeout=timeout)
        if r is not None:
            return (url, r)
    return (None, None)


# SQL error fingerprints (used by SQLi passive detection)
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",        # MySQL
    r"warning.*mysql_",                              # MySQL php
    r"unclosed quotation mark after the character",  # MSSQL
    r"microsoft odbc.*sql server",                   # MSSQL
    r"odbc microsoft access driver",                 # Access
    r"pg_query\(\)",                                 # Postgres
    r"postgresql.*error",                            # Postgres
    r"ora-\d{5}",                                    # Oracle
    r"sqlite_error",                                 # SQLite
    r"sqlitemanager",                                # SQLite
    r"db2 sql error",                                # DB2
]

# Command injection output fingerprints
CMD_PATTERNS = [r"uid=\d+\(", r"gid=\d+\(", r"root:[x*]:0:0:", r"groups=\d+\("]


def decode_jwt(token):
    """Decode JWT header + payload (no signature verify). Returns (header, payload) or (None, None)."""
    import base64
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None, None
        def _pad(s):
            return s + "=" * (-len(s) % 4)
        hdr = json.loads(base64.urlsafe_b64decode(_pad(parts[0])).decode("utf-8", "ignore"))
        pld = json.loads(base64.urlsafe_b64decode(_pad(parts[1])).decode("utf-8", "ignore"))
        return hdr, pld
    except Exception:
        return None, None
