"""Reflected XSS scanner — canary-based detection + payload-library confirmation.

Two-stage zero-FP gate:
  1. Send a benign canary, look for un-escaped reflection in an exploitable
     context (html / attribute / js). Skip safe contexts (JSON, comments,
     <noscript>, <title>, <style>, <textarea>).
  2. Replay with real XSS_PAYLOADS picked for the detected context. Only
     ship a finding when one of those payloads renders un-encoded.

Payload source: tools/_payloads/xss.py (XSS_PAYLOADS, 265 entries).
"""
import re, secrets
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools._payloads.xss import XSS_PAYLOADS
from tools.webapp._webapp_common import vuln_response
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
# Merge baked-in 265-entry XSS library with AI-curated extras (DOM sinks, polyglot, mutation).
_AI_EXTRA_XSS = load_json("xss_extra_payloads", fallback=[])
_MERGED_XSS = list(XSS_PAYLOADS) + [p for p in _AI_EXTRA_XSS if isinstance(p, dict) and "payload" in p and "context" in p]

_CTX_PAYLOAD_CAP = 4   # confirm a reflection with up to N payloads per ctx


def _payloads_for_context(ctx):
    """Pick first N merged-library payloads whose context matches detected reflection.
    Library is ordered strongest-first, so top-N slice is the budget choice."""
    out = [p for p in _MERGED_XSS if p.get("context") == ctx]
    return out[:_CTX_PAYLOAD_CAP]


def _extract_param_urls(base_url, html):
    urls = set()
    parsed = urlparse(base_url)
    if parsed.query: urls.add(base_url)
    for m in re.finditer(r'href=["\']([^"\']*\?[^"\']+)["\']', html or "", re.I):
        href = m.group(1)
        if href.startswith("http"): urls.add(href)
        elif href.startswith("/"): urls.add(f"{parsed.scheme}://{parsed.netloc}{href}")
        elif href.startswith("#"):
            # SPA hash route — try the params on the root path too
            urls.add(f"{parsed.scheme}://{parsed.netloc}/{href}")
            frag_qs = href[1:].split("?", 1)
            if len(frag_qs) == 2 and frag_qs[1]:
                urls.add(f"{parsed.scheme}://{parsed.netloc}/?{frag_qs[1]}")
    for action in re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html or "", re.I):
        if action.startswith("http"): urls.add(action)
        elif action.startswith("/"): urls.add(f"{parsed.scheme}://{parsed.netloc}{action}")
    return list(urls)[:12]


def _is_in_safe_context(body, idx):
    """True if the canary at idx is inside a context where it CANNOT execute
    even if reflected unescaped — JSON blobs, comments, noscript, title, style.
    Eliminates the bulk of XSS false positives on SPAs that hydrate state via
    <script type=application/json>__NEXT_DATA__."""
    before = body[:idx]
    for safe_open, safe_close in [
        ('<script type="application/json"', '</script'),
        ("<script type='application/json'", "</script"),
        ('<!--', '-->'),
        ('<noscript', '</noscript'),
        ('<title', '</title'),
        ('<style', '</style'),
        ('<textarea', '</textarea'),
    ]:
        last_open = before.lower().rfind(safe_open.lower())
        if last_open == -1: continue
        last_close = before.lower().rfind(safe_close.lower())
        if last_close < last_open:
            return True
    return False


def _reflection_context(canary, body):
    if not body or canary not in body: return None
    idx = body.find(canary)
    if _is_in_safe_context(body, idx): return None
    if "<script" in body[max(0, idx-300):idx]: return "js"
    if re.search(r'=["\'][^"\']*$', body[:idx]): return "attribute"
    return "html"


def _confirm_with_library(url, key, params, req, ctx):
    """Zero-FP gate: replay with real XSS_PAYLOADS for the detected context.
    Returns (severity, cvss, payload) on confirmed reflection, else None."""
    samples = _payloads_for_context(ctx)
    if not samples:
        # Fallback for unknown context — original probe shape
        samples = [{"payload": "<vlxss" + secrets.token_hex(3) + "/>",
                    "severity": "HIGH", "cvss": 7.5}]
    parsed = urlparse(url)
    for p in samples:
        new_params = {k: v[0] for k, v in params.items()}
        new_params[key] = p["payload"]
        test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
        r = safe_get(test_url, req=req, allow_redirects=True, timeout=10)
        if r is None or not r.text: continue
        if p["payload"] in r.text:
            sev = str(p.get("severity", "HIGH")).upper()
            return sev, str(p.get("cvss", "7.5")), p["payload"]
    return None


@router.post("/api/webapp/scan/xss")
@vl_turbo()
@vl_verify()
def scan_xss(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    r = safe_get(base, req=req, allow_redirects=True)
    if r is None:
        return standard_response(tool="xss", target=req.target, findings=[],
            tests_performed=1, vulnerable=False, skipped_reason=f"Could not reach {base}")
    urls = _extract_param_urls(base, r.text or "")

    # Augment with SPA-discovered URLs that have query params
    spa = load_spa_state(req.target)
    for spa_url in spa.get("urls", []):
        if "?" in spa_url and spa_url not in urls:
            urls.append(spa_url)

    if not urls:
        return standard_response(tool="xss", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters or form inputs found to test")
    findings, confirmed = [], []

    # VL-TURBO deep: parallelize canary probes across (url, key) jobs,
    # then parallelize the confirm-with-library stage.
    # Was up to 12 URLs * 5 params = 60 sequential canary GETs * 10s = ~600s.
    # Now: canary stage ~10s in pool(12); confirm stage ~10s in pool(6).
    jobs = []
    for u in urls:
        parsed = urlparse(u)
        params = parse_qs(parsed.query)
        if not params:
            continue
        for key in list(params.keys())[:5]:
            jobs.append((u, key, params))
    tests = len(jobs)

    def _canary_probe(job):
        u, key, params = job
        canary = "v" + secrets.token_hex(6) + "x"
        parsed = urlparse(u)
        new_params = {k: v[0] for k, v in params.items()}
        new_params[key] = canary
        test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
        r2 = safe_get(test_url, req=req, allow_redirects=True, timeout=10)
        if r2 is None:
            return None
        ctx = _reflection_context(canary, r2.text or "")
        if not ctx:
            return None
        return (u, key, params, ctx, canary)

    hits = []
    if jobs:
        with ThreadPoolExecutor(max_workers=min(12, len(jobs))) as pool:
            for res in pool.map(_canary_probe, jobs, timeout=60):
                if res is not None:
                    hits.append(res)

    # Preserve original semantics: first confirmed XSS per URL only.
    hits_by_url = {}
    for h in hits:
        hits_by_url.setdefault(h[0], h)

    def _confirm_job(h):
        u, key, params, ctx, canary = h
        result = _confirm_with_library(u, key, params, req, ctx)
        if not result:
            return None
        sev, cvss, payload_used = result
        return (u, key, ctx, canary, sev, cvss, payload_used)

    confirm_jobs = list(hits_by_url.values())
    if confirm_jobs:
        with ThreadPoolExecutor(max_workers=min(6, len(confirm_jobs))) as pool:
            for res in pool.map(_confirm_job, confirm_jobs, timeout=90):
                if res is None:
                    continue
                u, key, ctx, canary, sev, cvss, payload_used = res
                findings.append(wrap_finding(
                    f"Reflected XSS — parameter {key!r} reflects unescaped in {ctx} context",
                    sev, cvss=cvss, cwe="CWE-79", owasp="A03:2021",
                    remediation="Context-aware output encoding (HTML/JS/URL). Use auto-escaping templates.",
                    evidence_marker=(f"canary={canary} reflected in {ctx} context; "
                                     f"payload {payload_used!r} rendered un-encoded")))
                confirmed.append({"url": u, "param": key, "context": ctx,
                                   "payload": payload_used})
    return vuln_response(tool="xss", target=req.target, findings=findings,
        tested=max(tests, 1),
        what_checked=f"URL parameters for reflected XSS (canary + {len(_MERGED_XSS)}-entry merged AI+baked-in payload library)",
        severity_when_clean="POSITIVE",
        tests_summary=(f"Tested {tests} params across {len(urls)} URLs (incl. SPA-discovered) "
                       f"with canary + context-matched confirmation "
                       f"({len(_MERGED_XSS)}-entry library: {len(XSS_PAYLOADS)} baked-in + {len(_AI_EXTRA_XSS)} AI-curated)"),
        raw_data={"xss": {"urls_tested": urls, "tests": tests,
                           "confirmed": confirmed,
                           "library_size": len(_MERGED_XSS),
                           "ai_extras_loaded": len(_AI_EXTRA_XSS)}})


def register(app):
    app.include_router(router)
