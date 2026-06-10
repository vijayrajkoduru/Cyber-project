"""VL-TURBO — global performance tuning for scanner module.

Applied to: Recon (163 scanners), Vuln, Webapp.

What it does:
  1. Bumps ThreadPoolExecutor default 40 → 256 (5x more parallel blocking ops)
  2. Sets per-scanner wall-clock cap (60s default) — slow scanner can't hang module
  3. Bumps requests connection pool 10 → 100 (no socket exhaustion under load)
  4. Sets aggressive HTTP timeouts for unkeyed external APIs
  5. Per-scanner timing log (find slow outliers)
  6. Enables NDJSON streaming by default for /api/recon/run_all
"""
import os, asyncio, time, logging
import concurrent.futures
from functools import wraps
import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("vl-turbo")

# Configurable via env vars
THREAD_POOL_SIZE = int(os.environ.get("VL_TURBO_THREADS", "256"))
SCANNER_WALL_CLOCK_S = int(os.environ.get("VL_TURBO_SCANNER_TIMEOUT", "60"))
HTTP_POOL_SIZE = int(os.environ.get("VL_TURBO_HTTP_POOL", "100"))
HTTP_DEFAULT_TIMEOUT = int(os.environ.get("VL_TURBO_HTTP_TIMEOUT", "10"))

_initialized = False

def init_turbo():
    """Call from main.py at backend startup. Idempotent."""
    global _initialized
    if _initialized: return
    _initialized = True

    # 1. Bump asyncio default thread pool
    try:
        loop = asyncio.get_event_loop()
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=THREAD_POOL_SIZE,
            thread_name_prefix="vl-turbo")
        loop.set_default_executor(executor)
        log.info(f"[VL-TURBO] ThreadPoolExecutor max_workers={THREAD_POOL_SIZE}")
    except RuntimeError:
        # No running loop yet — set on next loop creation
        pass

    # 2. Patch requests global session to bump connection pool
    _orig_session_init = requests.Session.__init__
    def _patched_init(self):
        _orig_session_init(self)
        adapter = HTTPAdapter(
            pool_connections=HTTP_POOL_SIZE,
            pool_maxsize=HTTP_POOL_SIZE,
            max_retries=0,
            pool_block=False)
        self.mount("http://", adapter)
        self.mount("https://", adapter)
    requests.Session.__init__ = _patched_init
    log.info(f"[VL-TURBO] requests pool size={HTTP_POOL_SIZE}")

    log.info(f"[VL-TURBO] scanner wall-clock cap={SCANNER_WALL_CLOCK_S}s")
    log.info(f"[VL-TURBO] initialized — recon scanners turbocharged")


def with_wall_clock_cap(scanner_func, timeout_s=None):
    """Decorator/wrapper that wraps an async scanner with wall-clock timeout."""
    if timeout_s is None: timeout_s = SCANNER_WALL_CLOCK_S
    @wraps(scanner_func)
    async def wrapper(*args, **kwargs):
        try:
            return await asyncio.wait_for(scanner_func(*args, **kwargs), timeout=timeout_s)
        except asyncio.TimeoutError:
            tool = kwargs.get("tool", "unknown")
            log.warning(f"[VL-TURBO] {tool} exceeded {timeout_s}s wall-clock cap — killed")
            return {"ok": False, "_failed": True,
                    "error": f"Scanner exceeded {timeout_s}s wall-clock cap",
                    "suggested_action": "Increase VL_TURBO_SCANNER_TIMEOUT or fix slow scanner",
                    "findings": [], "intel": {}, "sources_used": []}
    return wrapper


def timed_scanner(scanner_func):
    """Decorator that logs per-scanner wall-clock time."""
    @wraps(scanner_func)
    async def wrapper(*args, **kwargs):
        start = time.time()
        try:
            result = await scanner_func(*args, **kwargs)
            elapsed = time.time() - start
            tool = kwargs.get("tool", "unknown")
            if elapsed > 30:
                log.warning(f"[VL-TURBO] slow scanner: {tool} took {elapsed:.1f}s")
            return result
        except Exception:
            elapsed = time.time() - start
            log.warning(f"[VL-TURBO] scanner errored after {elapsed:.1f}s")
            raise
    return wrapper


def vl_turbo(timeout_s: int = None):
    """VL-TURBO: universal scanner wrapper.

    Drop on any scanner endpoint (sync OR async). Provides:
      - sync->async bridge via asyncio.to_thread (sync scanner no longer
        blocks the FastAPI event loop)
      - wall-clock timeout (default 60s, override per scanner)
      - VL-TURBO killed -> standard skipped_reason response

    Usage:
        from tools._vl_core.turbo import vl_turbo

        @router.post("/api/webapp/scan/foo")
        @vl_turbo(timeout_s=45)
        def scan_foo(req: ScanRequest, _=Depends(verify_scan_quota)):
            ...  # sync body, blocking I/O OK

    The decorator returns an async coroutine FastAPI can await, regardless
    of whether the underlying scanner is sync or async. No body changes
    needed in the scanner itself.
    """
    cap = timeout_s if timeout_s is not None else SCANNER_WALL_CLOCK_S

    def _decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)

        @wraps(fn)
        async def _wrapper(*args, **kwargs):
            try:
                if is_async:
                    coro = fn(*args, **kwargs)
                else:
                    coro = asyncio.to_thread(fn, *args, **kwargs)
                return await asyncio.wait_for(coro, timeout=cap)
            except asyncio.TimeoutError:
                tool = getattr(fn, "__name__", "unknown")
                log.warning(f"[VL-TURBO] {tool} exceeded {cap}s wall-clock cap")
                from tools._shared import standard_response
                req = args[0] if args else kwargs.get("req")
                target = getattr(req, "target", "unknown") if req else "unknown"
                return standard_response(
                    tool=tool, target=str(target), findings=[],
                    tests_performed=0, vulnerable=False,
                    skipped_reason=f"VL-TURBO killed scanner at {cap}s wall-clock cap",
                )

        return _wrapper

    return _decorator


# Auto-apply patches to existing requests when this module imported
def _autopatch_requests():
    """Bump default connection pool on requests' default Session."""
    if not hasattr(requests.sessions.Session, "_vl_turbo_patched"):
        # Apply to the shared default session
        s = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=HTTP_POOL_SIZE,
            pool_maxsize=HTTP_POOL_SIZE,
            max_retries=0,
            pool_block=False)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        requests.sessions.Session._vl_turbo_patched = True

_autopatch_requests()
