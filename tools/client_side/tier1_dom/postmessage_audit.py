"""postmessage_audit - window.postMessage listener origin-check audit
(playbook §5 #41 + §7 #67).

window.addEventListener("message", handler) is the cross-origin RPC
mechanism for everything from OAuth popup callbacks to embedded
chat widgets. A listener that doesn't verify event.origin is a
"universal receiver" — ANY attacker page that can open the target
in an iframe or window can inject messages.

This probe uses Playwright (sync API, headless Chromium) to load the
URL, then hooks into window.addEventListener BEFORE any page script
runs (via addInitScript). Every postMessage listener registered on
window is recorded along with the source code of its callback.
Static analysis is then performed on each handler body:

  - "origin" or "event.origin" substring check?      → maybe safe
  - "indexOf(" or "===" comparing origin to a list?   → safer
  - regex against e.origin?                            → safer
  - NONE of the above?                                 → HIGH

If Chromium is not bundled in the runtime image, the probe returns
INFO with the install hint (`playwright install chromium`).

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.wait_ms     = post-load settle delay (default 4000ms)
  - options.user_agent  = optional UA override

This is DETECTION ONLY — we record listeners and statically analyse
their source; no real cross-origin postMessage is fired.
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.postmessage_audit_findings import POSTMESSAGE_AUDIT_FINDING_RULES

router = APIRouter()


class PostMessageRequest(ScanRequest):
    options: Optional[dict] = None


# JS that runs BEFORE page scripts. It wraps addEventListener so every
# call with type "message" is captured along with the callback's source.
PRELOAD_JS = r"""
(() => {
  window.__vlPostMessageListeners = [];
  const _orig = window.addEventListener;
  window.addEventListener = function(type, listener, options) {
    try {
      if (type === 'message' && listener) {
        let src = '';
        try { src = listener.toString(); } catch (e) { src = '[unserializable]'; }
        window.__vlPostMessageListeners.push({
          listener_source: src,
          options: (typeof options === 'object' ? JSON.stringify(options) : String(options)),
          registered_at: new Date().toISOString()
        });
      }
    } catch (e) { /* never crash the page */ }
    return _orig.apply(this, arguments);
  };
  // Also wrap window.onmessage = ...
  let _onmsg = null;
  Object.defineProperty(window, 'onmessage', {
    get() { return _onmsg; },
    set(fn) {
      try {
        if (fn) {
          let src = '';
          try { src = fn.toString(); } catch (e) { src = '[unserializable]'; }
          window.__vlPostMessageListeners.push({
            listener_source: src,
            options: '(via window.onmessage)',
            registered_at: new Date().toISOString()
          });
        }
      } catch (e) {}
      _onmsg = fn;
    },
    configurable: true
  });
})();
"""


def _analyze_handler(src: str) -> dict:
    """Return signals about an origin check in the listener source."""
    out = {
        "has_origin_substring":   False,
        "uses_equality_check":    False,
        "uses_indexof_or_includes": False,
        "uses_regex":             False,
        "uses_allowlist_array":   False,
        "has_no_origin_check":    True,
        "source_size":            len(src),
    }
    if not src:
        return out
    lower = src.lower()
    has_origin = (
        ".origin" in lower
        or "event.origin" in lower
        or " origin " in lower
    )
    out["has_origin_substring"] = has_origin
    if not has_origin:
        return out
    # Equality / inequality against a literal string
    if re.search(r"""\.origin\s*===?\s*['"`]""", src) or \
       re.search(r"""\.origin\s*!==?\s*['"`]""", src):
        out["uses_equality_check"] = True
    # indexOf / includes / startsWith
    if re.search(r"""\.origin\s*\.\s*(?:indexOf|includes|startsWith|endsWith)\s*\(""", src):
        out["uses_indexof_or_includes"] = True
    # regex test
    if re.search(r"""\.test\s*\(\s*[a-zA-Z_$][\w$]*\.origin""", src) or \
       re.search(r"""\.origin\s*\.\s*match\s*\(\s*/""", src):
        out["uses_regex"] = True
    # whitelist array check
    if re.search(r"""\.origin\s*\)?\s*$|allowed\s*[oO]rigins|trustedOrigins""", src):
        out["uses_allowlist_array"] = True
    # If ANY positive check signal present → not unguarded
    if (out["uses_equality_check"] or out["uses_indexof_or_includes"]
            or out["uses_regex"] or out["uses_allowlist_array"]):
        out["has_no_origin_check"] = False
    elif has_origin:
        # Origin is referenced but no clear check pattern matched — treat
        # as "probably checked" but flag as ambiguous
        out["has_no_origin_check"] = False
        out["ambiguous_origin_use"] = True
    return out


def _sync_playwright_run(target: str, ua: str, wait_ms: int) -> dict:
    """Sync helper run inside a thread executor — Playwright sync API
    can't be called from inside an already-running asyncio loop."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"_error": "playwright python lib not installed (pip install playwright)"}
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True,
                                              args=["--no-sandbox", "--disable-dev-shm-usage"])
            except Exception as e:
                return {"_error": ("playwright browser not installed; install "
                                    f"with `playwright install chromium` ({e})")}
            try:
                ctx = browser.new_context(user_agent=ua,
                                           ignore_https_errors=True,
                                           viewport={"width": 1280, "height": 800})
                ctx.add_init_script(PRELOAD_JS)
                page = ctx.new_page()
                final_url = ""
                status = 0
                try:
                    resp = page.goto(target, wait_until="domcontentloaded",
                                      timeout=20000)
                    final_url = page.url
                    status = resp.status if resp is not None else 0
                except Exception as e:
                    return {"_error": f"page.goto failed: {type(e).__name__}: {str(e)[:120]}"}
                # Let onload + late-binding listeners run
                page.wait_for_timeout(wait_ms)
                listeners = page.evaluate("() => (window.__vlPostMessageListeners || [])")
                if not isinstance(listeners, list):
                    listeners = []
                return {
                    "listeners":  listeners,
                    "final_url":  final_url,
                    "status":     status,
                }
            finally:
                try: browser.close()
                except Exception: pass
    except Exception as e:
        return {"_error": f"playwright wrapper failed: {type(e).__name__}: {str(e)[:160]}"}


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.source("no-target")
        return
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    opts = ctx.state.get("_options") or {}
    wait_ms = min(max(int(opts.get("wait_ms") or 4000), 500), 15000)
    ua = opts.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None, _sync_playwright_run, target, ua, wait_ms
        )
    except Exception as e:
        ctx.state["postmessage_error"] = f"executor failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("playwright executor failed")
        return

    if isinstance(result, dict) and result.get("_error"):
        ctx.state["postmessage_error"] = result["_error"]
        ctx.source(f"playwright error: {result['_error'][:80]}")
        return

    listeners = result.get("listeners") or []
    analyzed: list[dict] = []
    unguarded: list[dict] = []
    ambiguous: list[dict] = []
    for i, ent in enumerate(listeners):
        src = ent.get("listener_source") or ""
        sig = _analyze_handler(src)
        rec = {
            "index":      i,
            "source_size": sig.get("source_size", 0),
            "signals":    sig,
            "snippet":    src[:320],
        }
        analyzed.append(rec)
        if sig.get("has_no_origin_check") and not sig.get("ambiguous_origin_use"):
            unguarded.append(rec)
        elif sig.get("ambiguous_origin_use"):
            ambiguous.append(rec)

    ctx.state["postmessage_target_url"] = result.get("final_url") or target
    ctx.state["postmessage_http_status"] = result.get("status", 0)
    ctx.state["postmessage_listeners_total"] = len(listeners)
    ctx.state["postmessage_listeners"] = analyzed[:20]
    ctx.state["postmessage_unguarded"] = unguarded[:10]
    ctx.state["postmessage_ambiguous"] = ambiguous[:10]
    ctx.source(f"playwright -> {len(listeners)} listener(s); "
               f"{len(unguarded)} unguarded; {len(ambiguous)} ambiguous")


INTEL_FIELDS = [
    ("Target URL (final)",         "postmessage_target_url"),
    ("HTTP status",                "postmessage_http_status"),
    ("postMessage listeners",      "postmessage_listeners_total"),
    ("Unguarded listeners",        "postmessage_unguarded"),
    ("Ambiguous listeners",        "postmessage_ambiguous"),
    ("Listener breakdown",         "postmessage_listeners"),
]


@router.post("/api/client_side/postmessage_audit")
async def client_side_postmessage_audit(req: PostMessageRequest,
                                         _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="postmessage_audit",
        gather_func=_gather_with_options,
        finding_rules=POSTMESSAGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
