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
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify
# AI-curated extras: system files, history, logs, configs, cloud-meta, container indicators.
_AI_EXTRA_LFI = load_json("lfi_extra_paths", fallback=[])
_MERGED_LFI = list(LFI_PAYLOADS) + [p for p in _AI_EXTRA_LFI if isinstance(p, dict) and "payload" in p]

router = APIRouter()


def _build_lfi_payloads():
    """Interleave by category so the first per-param HTTP burst exercises
    every variant family — instead of burning the budget on N linux-passwd
    variants in a row.

    Uses _MERGED_LFI (baked-in LFI_PAYLOADS + AI-curated lfi_extra_paths).
    """
    order = ["linux-passwd", "linux-shadow", "linux-hosts", "linux-ssh",
             "linux-history", "windows-ini", "windows-sam", "proc-self",
             "var-log", "config", "cloud-meta",
             "encoded-bypass", "double-encoded", "null-byte",
             "log-poison", "php-filter", "linux-resolv", "linux-fstab", "linux-issue"]
    buckets = {cat: [] for cat in order}
    for p in _MERGED_LFI:
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
    # An always-true matcher (".+"/".*") has ZERO detection value (it fires on
    # any response) -> drop it so category-specific logic (php-filter decode)
    # decides, never a blind match. Root-cause fix for LFI false positives.
    if matcher and re.fullmatch(r"[()\s]*\.[+*]\??[()\s]*", matcher.strip()):
        matcher = ""
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


@router.post("/api/webapp/scan/lfi")
@vl_turbo()
@vl_verify()
def scan_lfi(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    unreachable = precheck_target(base, req)
    if unreachable:
        return vuln_response(tool="lfi", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
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
    # Per-param cap: 60 covers every interesting variant family (Linux + Windows +
    # PHP filter + null-byte + double-encoded + AI-curated system files / logs / configs).
    payload_set = _PAYLOADS[:60]
    # SPEED-V2 — wall-clock cap to prevent 240s orchestrator-timeout cascades.
    import time as _time
    _wallclock_start = _time.time()
    _WALLCLOCK_BUDGET = 60.0
    _bailed = False
    for tu_url, tu_parsed, params in test_urls[:8]:
        if _bailed: break
        for key in list(params.keys())[:3]:
            if _bailed: break
            for entry in payload_set:
                if _time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
                    _bailed = True; break
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
    summary = (f"Path traversal: {tests} variants from {len(payload_set)}-entry interleaved set "
               f"(merged: {len(LFI_PAYLOADS)} baked-in + {len(_AI_EXTRA_LFI)} AI-curated) "
               f"in {_time.time() - _wallclock_start:.1f}s")
    if _bailed:
        summary += f" — wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return vuln_response(tool="lfi", target=req.target, findings=findings,
        tested=max(tests, 1),
        what_checked=f"URL parameters for path traversal / LFI (marker-verified, {len(_MERGED_LFI)}-entry merged library covering ~19 categories)",
        severity_when_clean="POSITIVE",
        tests_summary=summary,
        raw_data={"lfi": {"confirmed": confirmed,
                           "library_size": len(_PAYLOADS),
                           "merged_size": len(_MERGED_LFI),
                           "ai_extras_loaded": len(_AI_EXTRA_LFI),
                           "wallclock_bailed": _bailed}})


def register(app):
    app.include_router(router)
