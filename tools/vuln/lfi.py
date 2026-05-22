"""Path Traversal / LFI — marker-based zero-FP.

Payload source: tools/_payloads/lfi.py (LFI_PAYLOADS, 142 entries across
linux-passwd / windows-ini / php-filter / proc-self / encoded-bypass /
double-encoded / null-byte / log-poison). Each entry carries its own
matcher regex; php-filter uses a smart base64-decode-and-check-for-<?php
fallback because the literal "{base64 chars}" matcher false-positives on
inline JWTs, CSS, and data URIs.
"""
import base64, re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools._payloads.lfi import LFI_PAYLOADS

router = APIRouter()


def _build_lfi_payloads():
    """Interleave by category so the first per-param HTTP burst exercises
    every variant family — linux-passwd, windows-ini, proc-self,
    encoded-bypass, double-encoded, null-byte, log-poison, php-filter —
    instead of burning the budget on 39 linux-passwd variants in a row.
    """
    order = ["linux-passwd", "windows-ini", "proc-self",
             "encoded-bypass", "double-encoded", "null-byte",
             "log-poison", "php-filter"]
    buckets = {cat: [] for cat in order}
    for p in LFI_PAYLOADS:
        cat = p.get("category")
        if cat not in buckets: continue
        buckets[cat].append({
            "payload":  p["payload"],
            "matcher":  p.get("matcher", ""),
            "category": cat,
            "desc":     f"{cat} ({p.get('target_os', 'any')})",
            "severity": (p.get("severity") or "high").upper(),
            "cvss":     str(p.get("cvss", "7.5")),
        })
    out, idx = [], 0
    while any(idx < len(buckets[cat]) for cat in order):
        for cat in order:
            if idx < len(buckets[cat]):
                out.append(buckets[cat][idx])
        idx += 1
    return out


_PAYLOADS = _build_lfi_payloads()


def _check_marker(body, matcher, category):
    body = body or ""
    if category == "php-filter":
        # Smart fallback: decode any long base64 chunk and check for raw PHP
        for chunk in re.findall(r"[A-Za-z0-9+/=]{40,}", body):
            try:
                decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
                if "<?php" in decoded or "<?PHP" in decoded:
                    return True
            except Exception:
                pass
        if matcher:
            try: return re.search(matcher, body, re.IGNORECASE) is not None
            except Exception: return False
        return False
    if not matcher:
        return False
    try:
        return re.search(matcher, body, re.IGNORECASE) is not None
    except Exception:
        return False


@router.post("/api/scan/lfi")
async def scan_lfi(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    parsed = urlparse(base)
    params_base = parse_qs(parsed.query)
    test_urls = []
    if params_base:
        test_urls.append((base, parsed, params_base))
    # Augment with SPA-discovered URLs
    spa = load_spa_state(req.target)
    for u in spa.get("urls", []):
        try:
            up = urlparse(u)
            ps = parse_qs(up.query)
            if ps:
                test_urls.append((u, up, ps))
        except Exception:
            continue
    if not test_urls:
        return standard_response(tool="lfi", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters present on base or SPA-discovered endpoints")
    findings, tests, confirmed = [], 0, []
    # Per-param cap: 40 covers every interesting variant (Linux + Windows +
    # PHP filter + null-byte + double-encoded). Bounded scan time.
    payload_set = _PAYLOADS[:40]
    for tu_url, tu_parsed, params in test_urls[:8]:
        for key in list(params.keys())[:3]:
            for entry in payload_set:
                tests += 1
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = entry["payload"]
                test_url = urlunparse(tu_parsed._replace(query=urlencode(new_params)))
                r = safe_get(test_url, req=req, allow_redirects=True, timeout=12)
                if r is None or r.status_code != 200: continue
                if _check_marker((r.text or "")[:50000],
                                  entry["matcher"], entry["category"]):
                    findings.append(wrap_finding(
                        f"Path Traversal / LFI in {key!r} — {entry['desc']}",
                        "CRITICAL", cvss="9.8", cwe="CWE-22", owasp="A01:2021",
                        remediation="Validate paths against whitelist; reject '..' and absolute paths.",
                        evidence_marker=(f"param={key} payload={entry['payload']!r} "
                                         f"matched {entry['matcher'] or 'PHP base64'}")))
                    confirmed.append({"param": key, "payload": entry["payload"],
                                      "category": entry["category"]})
                    break
            else:
                continue
            break
    return standard_response(tool="lfi", target=req.target, findings=findings,
        tests_performed=max(tests, 1),
        tests_summary=(f"Path traversal: {tests} variants from {len(payload_set)}-entry library "
                       f"(LFI_PAYLOADS, 8 categories) with marker verification"),
        raw_data={"lfi": {"confirmed": confirmed,
                           "library_size": len(_PAYLOADS)}})


def register(app):
    app.include_router(router)
