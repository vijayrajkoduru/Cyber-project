"""CMS Detection — fingerprint WordPress / Drupal / Joomla / etc.

Fingerprint dictionary: tools/_payloads/vuln/cms_fingerprints.json
(loaded once at import — 89 entries covering ~50 platforms incl. headless
CMS, static-site generators, e-commerce, forum, LMS, panel software).
Falls back to a 14-entry hardcoded baseline if missing.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools.vuln._vuln_common import vuln_response, precheck_target
from tools._payloads.vuln._loader import load_json
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

@router.post("/api/scan/cms")
def scan_cms(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    unreachable = precheck_target(base, req, active_probes=False)  # read-only fingerprinting — runs behind WAF
    if unreachable:
        return vuln_response(tool="cms", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    findings, tests, detected = [], 0, set()
    for name, path, marker, desc in _FINGERPRINTS:
        if name in detected: continue
        tests += 1
        r = safe_get(base + path, req=req, allow_redirects=True, timeout=8)
        if r is None or r.status_code != 200: continue
        body = (r.text or "")[:20000]
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
    if not detected:
        return standard_response(tool="cms", target=req.target, findings=[],
            tests_performed=tests, vulnerable=False,
            skipped_reason="No CMS fingerprint matched on this target")
    platform_count = len({e[0] for e in _FINGERPRINTS})
    return vuln_response(tool="cms", target=req.target, findings=findings,
        tested=tests,
        what_checked=f"CMS / framework fingerprints ({len(_FINGERPRINTS)}-entry AI-curated wordlist covering ~{platform_count} platforms)",
        tests_summary=f"CMS fingerprinting: {tests} checks across {platform_count} platforms; detected: {', '.join(sorted(detected))}",
        raw_data={"cms": {"detected": sorted(detected),
                          "wordlist_size": len(_FINGERPRINTS),
                          "platforms_covered": platform_count}})
def register(app): app.include_router(router)
