"""SPA-canary helpers — VL-VERIFY pattern, shared across modules.

Problem: React/Vue/Angular SPAs serve `index.html` for ANY unknown path
(catch-all routing). A scanner that flags "200 + body present = exposed"
will false-positive on every probe against an SPA target.

Solution: probe one deliberately-bogus path BEFORE the real probes. If
that returns 200 with substantial body, the target is an SPA. Any later
probe that returns a body matching the canary body is a catch-all, not
a real exposure.

Usage (sync caller — most scanners):

    from tools._framework.spa_canary import detect_spa_catchall_sync, is_same_as_canary

    spa = detect_spa_catchall_sync(base_url)   # one extra HTTP call
    for r in suspicious_responses:
        if spa["is_spa"] and is_same_as_canary(r.text, spa["canary_body"]):
            continue        # SPA catch-all -> drop as FP
        # real finding processing here

Usage (async caller):

    from tools._framework.spa_canary import detect_spa_catchall, is_same_as_canary

    spa = await detect_spa_catchall(base_url)
    # ... same content match as sync

Originally lived in tools/vuln/_vuln_common.py; promoted to _framework so
Recon + Webapp + Vuln all import from the same place. The Vuln module
keeps a re-export shim for backward compatibility.
"""
import asyncio
import ssl
import time
import urllib.error
import urllib.request

_UA = "Mozilla/5.0 (VulnusLab VL-VERIFY)"
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


def _http_get(url, timeout=6, read=20000):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            body = r.read(read)
            return {"status": r.status, "body": body.decode("utf-8", "ignore")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": ""}
    except Exception:
        return None


def _canary_path():
    # Random-ish path no real app would route. ASCII-only so path-traversal
    # filters never block it.
    return f"/__vl_canary_{int(time.time() * 1000) % 1000000}_zzzqxq"


def detect_spa_catchall_sync(base_url, timeout=6):
    """Sync version — for scanners that use plain `requests` calls.

    Returns dict with:
      - is_spa (bool)
      - canary_status (int)
      - canary_body (str, first 2000 chars)
      - canary_len (int, full length)
    """
    url = f"{base_url.rstrip('/')}{_canary_path()}"
    r = _http_get(url, timeout=timeout, read=20000)
    if not r:
        return {"is_spa": False, "canary_status": 0, "canary_body": "", "canary_len": 0}
    status = r.get("status", 0)
    body = r.get("body", "") or ""
    is_spa = (status == 200 and len(body) > 200)
    return {
        "is_spa": is_spa,
        "canary_status": status,
        "canary_body": body[:2000],
        "canary_len": len(body),
    }


async def detect_spa_catchall(base_url, timeout=6):
    """Async version — for scanners running inside asyncio gather()."""
    return await asyncio.to_thread(detect_spa_catchall_sync, base_url, timeout)


def is_same_as_canary(response_body, canary_body, threshold=0.9):
    """Return True if response_body matches the SPA canary body closely
    enough to conclude it's the SPA catch-all rather than a real resource.

    Uses prefix comparison rather than full-body diff for speed. Two cases:
      1. Exact 2000-char prefix match — most SPAs serve byte-identical
         index.html for every path.
      2. First-200-char match — SPAs that inject per-request meta tags
         (CSP nonce, build hash) still share the leading shell.
    """
    if not response_body or not canary_body:
        return False
    rb = response_body[:2000]
    cb = canary_body[:2000]
    if rb == cb:
        return True
    return rb[:200] == cb[:200]
