"""tools/vuln/_vuln_common.py - shared probe helpers for Vuln scanners.
Underscore-prefixed so the autoloader skips it (helper, not a scanner)."""
import asyncio
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


# ── ASYNC WRAPPERS — eliminate event-loop blocking ─────────────────────
# All the http_* helpers above use synchronous urllib. Calling them from
# `async def gather()` BLOCKS the event loop for the duration of the HTTP
# call. The orchestrator wraps each scanner in asyncio.wait_for(...) with
# a per-scanner cap; when a sync urllib call exceeds that cap, the task
# can't be cancelled cleanly and the scanner gets marked ERROR.
#
# Fix: run the sync call inside asyncio.to_thread, which puts it on a
# worker thread so the event loop stays free and wait_for can cancel.

async def http_get_async(url, timeout=10, read=200000):
    return await asyncio.to_thread(http_get, url, timeout, read)


async def http_get_h_async(url, headers=None, timeout=10, read=200000):
    return await asyncio.to_thread(http_get_h, url, headers, timeout, read)


async def http_post_async(url, data=b"", headers=None, timeout=10):
    return await asyncio.to_thread(http_post, url, data, headers, timeout)


async def probe_url_async(host, path="/", scheme=None, timeout=10):
    """Async version of probe_url. Tries https then http, returns (url, response)."""
    if scheme:
        url = f"{scheme}://{host}{path}"
        r = await http_get_async(url, timeout=timeout)
        return (url, r)
    for s in ("https", "http"):
        url = f"{s}://{host}{path}"
        r = await http_get_async(url, timeout=timeout)
        if r is not None:
            return (url, r)
    return (None, None)


# VL-VERIFY (SPA catch-all detection) was promoted to tools/_framework/spa_canary.py
# so Recon + Webapp + Vuln share one canonical implementation. Re-exported here
# for backward compatibility with the 5 Vuln scanners that import from this
# module directly (multirole_privesc, horizontal_access_idor, vertical_access_admin,
# a05_security_misconfig, api_versioning_skew).
from tools._vl_core.spa_canary import (  # noqa: E402,F401
    detect_spa_catchall,
    is_same_as_canary,
)


async def bounded_gather_probes(probes, per_probe_timeout=8, max_total=50):
    """Run a list of awaitable probe-coroutines with a hard per-probe timeout
    and a soft cap on total wall-clock. Returns list of results (None for the
    ones that errored or timed out). Use this in scanner gather() functions to
    guarantee they never exceed `max_total` seconds regardless of network."""
    async def _one(coro):
        try:
            return await asyncio.wait_for(coro, timeout=per_probe_timeout)
        except Exception:
            return None
    try:
        return await asyncio.wait_for(
            asyncio.gather(*(_one(p) for p in probes)),
            timeout=max_total,
        )
    except asyncio.TimeoutError:
        return [None] * len(probes)


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
