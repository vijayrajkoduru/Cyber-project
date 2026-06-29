"""Observability — dependency-free metrics, request-id, structured access log.

ZERO new hard dependencies. Metrics are pure-stdlib counters rendered in
Prometheus text format. Never raises into the request path (bookkeeping
errors are swallowed). Bounded cardinality — keyed by matched route template,
not raw URL, so high-variance paths can't blow up memory.

Wire-up (main.py):  from tools._core.observability import install_observability
                    install_observability(app)
"""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from collections import defaultdict

log = logging.getLogger("vulnuslab.access")

_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)
_LOCK = threading.Lock()
_req_total: dict[tuple, int] = defaultdict(int)
_latency: dict[tuple, dict] = defaultdict(lambda: defaultdict(int))
_req_in_flight = 0
_boot_time = time.time()


def _route_template(request) -> str:
    route = request.scope.get("route")
    return getattr(route, "path", None) or "__unmatched__"


def _observe(method: str, template: str, status: int, elapsed: float) -> None:
    with _LOCK:
        _req_total[(method, template, f"{status // 100}xx")] += 1
        b = _latency[(method, template)]
        for upper in _BUCKETS:
            if elapsed <= upper:
                b[upper] += 1
        b["+Inf"] += 1
        b["_sum"] = b.get("_sum", 0.0) + elapsed
        b["_count"] = b.get("_count", 0) + 1


async def _middleware(request, call_next):
    global _req_in_flight
    rid = request.headers.get("x-request-id") or uuid.uuid4().hex
    request.state.request_id = rid
    start = time.perf_counter()
    with _LOCK:
        _req_in_flight += 1
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        response.headers["X-Request-ID"] = rid
        return response
    finally:
        elapsed = time.perf_counter() - start
        with _LOCK:
            _req_in_flight -= 1
        try:
            _observe(request.method, _route_template(request), status, elapsed)
            xff = request.headers.get("x-forwarded-for", "")
            ip = xff.split(",")[0].strip() if xff else (
                request.client.host if request.client else "-")
            log.info('%s %s %s %.1fms rid=%s ip=%s',
                     request.method, request.url.path, status, elapsed * 1000, rid, ip)
        except Exception:
            pass


def render_prometheus() -> str:
    lines: list[str] = []
    with _LOCK:
        total = dict(_req_total)
        latency = {k: dict(v) for k, v in _latency.items()}
        in_flight = _req_in_flight
    lines.append("# HELP vl_http_requests_total Total HTTP requests by route + status class.")
    lines.append("# TYPE vl_http_requests_total counter")
    for (method, tmpl, sc), n in sorted(total.items()):
        lines.append(f'vl_http_requests_total{{method="{method}",route="{tmpl}",status="{sc}"}} {n}')
    lines.append("# HELP vl_http_request_duration_seconds Request latency histogram.")
    lines.append("# TYPE vl_http_request_duration_seconds histogram")
    for (method, tmpl), b in sorted(latency.items()):
        labels = f'method="{method}",route="{tmpl}"'
        for upper in _BUCKETS:
            lines.append(f'vl_http_request_duration_seconds_bucket{{{labels},le="{upper}"}} {b.get(upper, 0)}')
        lines.append(f'vl_http_request_duration_seconds_bucket{{{labels},le="+Inf"}} {b.get("+Inf", 0)}')
        lines.append(f'vl_http_request_duration_seconds_sum{{{labels}}} {b.get("_sum", 0.0)}')
        lines.append(f'vl_http_request_duration_seconds_count{{{labels}}} {b.get("_count", 0)}')
    lines.append("# HELP vl_http_requests_in_flight Requests currently being served.")
    lines.append("# TYPE vl_http_requests_in_flight gauge")
    lines.append(f"vl_http_requests_in_flight {in_flight}")
    lines.append("# HELP vl_process_uptime_seconds Seconds since process boot.")
    lines.append("# TYPE vl_process_uptime_seconds gauge")
    lines.append(f"vl_process_uptime_seconds {time.time() - _boot_time:.1f}")
    return "\n".join(lines) + "\n"


def init_error_tracking() -> bool:
    """Initialise Sentry IFF sentry_sdk is installed and SENTRY_DSN is set."""
    dsn = os.getenv("SENTRY_DSN", "").strip()
    if not dsn:
        return False
    try:
        import sentry_sdk
        sentry_sdk.init(dsn=dsn,
                        traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.0")),
                        environment=os.getenv("SENTRY_ENV", "production"))
        log.info("error tracking: Sentry active")
        return True
    except Exception as exc:
        log.warning("error tracking: SENTRY_DSN set but init failed (%s)", exc)
        return False


def install_observability(app) -> None:
    from starlette.responses import PlainTextResponse
    init_error_tracking()
    app.middleware("http")(_middleware)

    @app.get("/api/metrics")
    async def metrics():
        return PlainTextResponse(render_prometheus(), media_type="text/plain; version=0.0.4")
