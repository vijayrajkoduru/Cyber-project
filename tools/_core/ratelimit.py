"""Rate limiting — per-client fixed-window limiter, dependency-free.

Why fixed-window (not a third-party limiter): zero new dependencies, O(1)
memory per active client, and trivially correct under the GIL. For a single
backend process behind nginx this is sufficient; a multi-instance deployment
should move the counter to Redis (see docs/POSTGRES-MIGRATION.md companion
note), which is why the store is isolated behind _hit().

Production-safe behaviour:
  * FAIL-OPEN. Any internal error in the limiter lets the request through —
    a bug in rate limiting must never take the API down.
  * Health/metrics are never limited (load balancers + Prometheus scrape).
  * Disabled in one env flip: RATE_LIMIT_ENABLED=0.

Env:
  RATE_LIMIT_ENABLED   default "1"   ("0"/"false" disables)
  RATE_LIMIT_PER_MIN   default "120" per client IP per 60s window
  RATE_LIMIT_BURST     default = RATE_LIMIT_PER_MIN (reserved for future use)

Wire-up (main.py):
    from tools._core.ratelimit import install_rate_limit
    install_rate_limit(app)
"""
from __future__ import annotations

import logging
import os
import threading
import time

log = logging.getLogger("vulnuslab.ratelimit")

_EXEMPT_PATHS = frozenset({"/api/health", "/api/metrics"})

_LOCK = threading.Lock()
# client_key -> [window_start_epoch, count]
_windows: dict[str, list] = {}
_last_gc = 0.0


def _client_key(request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _gc(now: float, window: float) -> None:
    """Drop stale windows so the dict can't grow unbounded under IP churn."""
    global _last_gc
    if now - _last_gc < 60:
        return
    _last_gc = now
    stale = [k for k, (start, _) in _windows.items() if now - start > window * 2]
    for k in stale:
        _windows.pop(k, None)


def _hit(key: str, limit: int, window: float) -> tuple[bool, int, int]:
    """Return (allowed, remaining, retry_after_seconds)."""
    now = time.time()
    with _LOCK:
        _gc(now, window)
        entry = _windows.get(key)
        if entry is None or now - entry[0] >= window:
            _windows[key] = [now, 1]
            return True, limit - 1, 0
        entry[1] += 1
        if entry[1] > limit:
            retry = int(window - (now - entry[0])) + 1
            return False, 0, retry
        return True, limit - entry[1], 0


def install_rate_limit(app) -> None:
    enabled = os.getenv("RATE_LIMIT_ENABLED", "1").lower() not in ("0", "false", "no")
    try:
        limit = max(1, int(os.getenv("RATE_LIMIT_PER_MIN", "120")))
    except ValueError:
        limit = 120
    window = 60.0

    if not enabled:
        log.info("rate limiting disabled (RATE_LIMIT_ENABLED=0)")
        return
    log.info("rate limiting active: %d req/%ds per client IP", limit, int(window))

    from starlette.responses import JSONResponse

    @app.middleware("http")
    async def _rate_limit(request, call_next):
        path = request.url.path
        if path in _EXEMPT_PATHS:
            return await call_next(request)
        try:
            allowed, remaining, retry = _hit(_client_key(request), limit, window)
        except Exception:  # fail-open: never block on limiter bugs
            return await call_next(request)
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded. Slow down and retry.",
                 "limit": limit, "window_seconds": int(window)},
                status_code=429,
                headers={"Retry-After": str(retry),
                         "X-RateLimit-Limit": str(limit),
                         "X-RateLimit-Remaining": "0"},
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
