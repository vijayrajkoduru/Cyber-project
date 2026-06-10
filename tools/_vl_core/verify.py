"""VL-VERIFY — universal zero-FP guards as a decorator.

Drop @vl_verify(...) on any scanner endpoint to apply pre-flight FP
guards consistently. Default guards (always on):

  * Reserved-domain skip — RFC 2606 / RFC 6761 targets (example.com,
    *.test, *.invalid, *.localhost) get short-circuited cleanly. Stops
    the OSINT-on-example.com 50-FP cascade.

Opt-in guards (per scanner):

  * SPA canary — probe /__vl_canary_<ts>_zzzqxq before the real scan.
    If the SPA catch-all returns the same body as the probe path, every
    subsequent "found at /admin", "found at /api/foo" etc. is an SPA
    FP. The cache in tools._vl_core.spa_canary keeps the canary result
    for 60s per target so 30 scanners running against the same SPA
    don't fire 30 canary probes.

  * Brand stem — for OSINT-style username/handle scanners, target
    "example.com" → "example" so the scanner doesn't search the domain
    string as a username on platforms that 200 for invalid handles.

Usage:

    from tools._vl_core import vl_verify

    @router.post("/api/osint/foo")
    @vl_verify()                          # reserved-domain only (default)
    async def scan_foo(req): ...

    @router.post("/api/webapp/scan/foo")
    @vl_verify(check_spa=True)            # + SPA canary check
    async def scan_foo(req): ...

    @router.post("/api/osint/sherlock_username")
    @vl_verify(brand_stem=True)           # + extract brand stem from domain
    async def scan_foo(req): ...

The decorator handles both sync and async scanner bodies via the same
sync→async bridge as @vl_turbo. Often you'll stack them:

    @router.post(...)
    @vl_turbo(timeout_s=45)
    @vl_verify(check_spa=True)
    def scan_X(req): ...
"""
from __future__ import annotations
import asyncio
from functools import wraps
from typing import Optional

from tools._vl_core.reserved_domains import is_reserved, reason as reserved_reason


_KNOWN_TLDS = {"com","net","org","co","io","ai","app","dev","me","us","uk",
                "in","de","fr","ca","au","jp","cn","ru","br","es","it","nl"}


def _to_brand_stem(target: str) -> str:
    """Strip URL scheme, www., port, path, TLD — return the brand stem.

    "dasplc.com"          -> "dasplc"
    "www.example.com"     -> "example"
    "admin.acme.co.uk"    -> "acme"
    "@cooluser"           -> "cooluser"
    """
    t = (target or "").strip().lstrip("@")
    for pfx in ("http://", "https://"):
        if t.startswith(pfx):
            t = t[len(pfx):]
    t = t.split("/", 1)[0].split(":", 1)[0]
    if t.startswith("www."):
        t = t[4:]
    parts = t.lower().split(".")
    if len(parts) >= 2 and parts[-1] in _KNOWN_TLDS:
        if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"}:
            return parts[-3]
        return parts[-2]
    return t


def vl_verify(*, check_reserved: bool = True,
                check_spa: bool = False,
                brand_stem: bool = False):
    """Universal scanner FP-guard decorator. See module docstring."""

    def _decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        fn_name = getattr(fn, "__name__", "unknown")

        @wraps(fn)
        async def _wrapper(*args, **kwargs):
            req = kwargs.get("req") or (args[0] if args else None)
            target = getattr(req, "target", "") if req else ""

            # Guard 1: RFC 2606 reserved-domain skip
            if check_reserved and target and is_reserved(target):
                from tools._shared import standard_response
                return standard_response(
                    tool=fn_name, target=target, findings=[],
                    tests_performed=0, vulnerable=False,
                    skipped_reason=reserved_reason(target),
                )

            # Guard 2: brand-stem extraction (for username/handle scanners
            # where the domain-shaped target would 200 on invalid handles)
            if brand_stem and target and "." in target:
                try:
                    stem = _to_brand_stem(target)
                    if stem and stem != target and hasattr(req, "target"):
                        req.target = stem  # mutate request in place
                except Exception:
                    pass  # fall through; downstream handles invalid

            # Guard 3: SPA canary pre-flight
            if check_spa and target:
                try:
                    from tools._vl_core.spa_canary import detect_spa_catchall_sync
                    spa = await asyncio.to_thread(detect_spa_catchall_sync, target)
                    # If target is a clear SPA catch-all, ANY scanner that
                    # would react to 200 responses is FP-prone. We don't
                    # short-circuit the scan (some scanners legitimately
                    # work in SPA mode), but we set a marker on the request
                    # the scanner CAN consult.
                    if spa and req:
                        setattr(req, "_vl_spa_detected", spa)
                except Exception:
                    pass  # SPA cache unavailable; fall through

            # Run the wrapped scanner (sync or async)
            if is_async:
                return await fn(*args, **kwargs)
            return await asyncio.to_thread(fn, *args, **kwargs)

        return _wrapper

    return _decorator
