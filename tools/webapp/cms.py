"""CMS Detection — fingerprint WordPress / Drupal / Joomla / etc.

Fingerprint dictionary: tools/_payloads/vuln/cms_fingerprints.json
(loaded once at import — 89 entries covering ~50 platforms incl. headless
CMS, static-site generators, e-commerce, forum, LMS, panel software).
Falls back to a 14-entry hardcoded baseline if missing.
"""
"""VL-VERIFY: probes 89 fingerprint paths and matches CMS markers in body.
SPA shells could falsely match generic markers like 'WordPress' if the page
mentions it in marketing copy. SPA-canary check skips paths whose body is
byte-identical to the bogus-path probe."""
import re
import time
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._payloads.webapp._loader import load_json
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary
from tools._vl_core.turbo import vl_turbo
router = APIRouter()

_FALLBACK_FINGERPRINTS = [
    ("WordPress",  "/wp-login.php",                                       r"<title>.*Log In.*WordPress|wp-content", "WordPress login page"),
    ("WordPress",  "/",                                                   r'<meta name="generator" content="WordPress', "WordPress generator meta"),
    ("WordPress",  "/wp-includes/js/wp-emoji-release.min.js",            r"wpemojiSettings|wp-emoji", "WordPress wp-includes"),
    ("WordPress",  "/readme.html",                                        r"WordPress|Welcome\. WordPress is web", "WordPress readme.html"),
    ("Drupal",     "/",                                                   r'<meta name="generator" content="Drupal', "Drupal generator meta"),
    ("Drupal",     "/CHANGELOG.txt",                                      r"Drupal \d+\.\d+", "Drupal CHANGELOG.txt"),
    ("Joomla",     "/",                                                   r'<meta name="generator" content="Joomla', "Joomla generator meta"),
    ("Joomla",     "/administrator/",                                     r"Joomla|com_login", "Joomla admin login"),
    ("Magento",    "/",                                                   r"Magento|/skin/frontend/", "Magento path"),
    ("Shopify",    "/",                                                   r"shopify-checkout-api-token|cdn\.shopify\.com", "Shopify CDN"),
    ("Ghost",      "/",                                                   r'<meta name="generator" content="Ghost', "Ghost generator"),
    ("PrestaShop", "/",                                                   r'<meta name="generator" content="PrestaShop', "PrestaShop generator"),
    ("TYPO3",      "/",                                                   r'<meta name="generator" content="TYPO3', "TYPO3 generator"),
]
_loaded = load_json("cms_fingerprints")
if isinstance(_loaded, list) and _loaded:
    _FINGERPRINTS = [(e["name"], e["path"], e["marker"], e["desc"]) for e in _loaded
                     if all(k in e for k in ("name","path","marker","desc"))]
else:
    _FINGERPRINTS = _FALLBACK_FINGERPRINTS

@router.post("/api/webapp/scan/cms")
@vl_turbo()
def scan_cms(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    unreachable = precheck_target(base, req, active_probes=False)  # read-only fingerprinting — runs behind WAF
    if unreachable:
        return vuln_response(tool="cms", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    spa = detect_spa_catchall_sync(base)
    spa_suppressed = 0
    findings, tests, detected = [], 0, set()
    # VL-TURBO wall-clock cap: 89 fingerprints × 8s × 3 retries = up to 35 min
    # on slow targets. Bail at 30s with whatever we've detected so far.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 30.0
    _bailed = False
    for name, path, marker, desc in _FINGERPRINTS:
        if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
            _bailed = True; break
        if name in detected: continue
        tests += 1
        # retries=0 — fingerprint scanning is best-effort; one shot per path
        r = safe_get(base + path, req=req, allow_redirects=True, timeout=6, retries=0)
        if r is None or r.status_code != 200: continue
        body = (r.text or "")[:20000]
        # SPA catch-all: body matches canary -> match would be SPA-shell FP
        if spa["is_spa"] and is_same_as_canary(body, spa["canary_body"]):
            spa_suppressed += 1
            continue
        if re.search(marker, body, re.IGNORECASE) or re.search(marker, str(dict(r.headers)), re.IGNORECASE):
            detected.add(name)
            version = None
            for vpat in (r"WordPress\s+(\d+\.\d+(?:\.\d+)?)", r"Drupal\s+(\d+\.\d+(?:\.\d+)?)", r"Joomla!?\s*(?:CMS\s*)?(\d+\.\d+(?:\.\d+)?)"):
                m = re.search(vpat, body, re.IGNORECASE)
                if m: version = m.group(1); break
            findings.append(wrap_finding(
                f"CMS detected: {name}" + (f" {version}" if version else ""),
                "LOW", cvss="3.1", cwe="CWE-200", owasp="A05:2021",
                remediation=f"{name} fingerprint exposed publicly. Strip generator meta tags, update plugins/themes, consider WAF.",
                evidence_marker=f"GET {path} matched: {desc}"))
    platform_count = len({e[0] for e in _FINGERPRINTS})
    if not detected:
        reason = "No CMS fingerprint matched on this target"
        if _bailed:
            reason += f" (wall-clock bailed at {_WALLCLOCK_BUDGET}s after {tests} probes — target too slow for full {len(_FINGERPRINTS)}-fingerprint sweep)"
        return vuln_response(tool="cms", target=req.target, findings=[],
            tested=max(tests, 1), skipped_reason=reason,
            raw_data={"cms": {"detected": [], "wordlist_size": len(_FINGERPRINTS),
                              "platforms_covered": platform_count, "wallclock_bailed": _bailed}})
    summary = f"CMS fingerprinting: {tests} checks across {platform_count} platforms; detected: {', '.join(sorted(detected))} in {time.time() - _wallclock_start:.1f}s"
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return vuln_response(tool="cms", target=req.target, findings=findings,
        tested=tests,
        what_checked=f"CMS / framework fingerprints ({len(_FINGERPRINTS)}-entry AI-curated wordlist covering ~{platform_count} platforms)",
        tests_summary=summary,
        raw_data={"cms": {"detected": sorted(detected),
                          "wordlist_size": len(_FINGERPRINTS),
                          "platforms_covered": platform_count,
                          "wallclock_bailed": _bailed,
                          "spa_catchall": spa["is_spa"],
                          "spa_suppressed_count": spa_suppressed}})
def register(app): app.include_router(router)
