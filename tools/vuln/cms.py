"""CMS Detection — fingerprint WordPress / Drupal / Joomla / etc."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()

_FINGERPRINTS = [
    ("WordPress",  "/wp-login.php",                                       r"<title>.*Log In.*WordPress|wp-content", "WordPress login page"),
    ("WordPress",  "/",                                                   r'<meta name="generator" content="WordPress', "WordPress generator meta"),
    ("WordPress",  "/wp-includes/js/wp-emoji-release.min.js",            r"wpemojiSettings|wp-emoji", "WordPress wp-includes"),
    ("WordPress",  "/readme.html",                                        r"WordPress|Welcome\. WordPress is web", "WordPress readme.html"),
    ("Drupal",     "/",                                                   r'<meta name="generator" content="Drupal', "Drupal generator meta"),
    ("Drupal",     "/CHANGELOG.txt",                                      r"Drupal \d+\.\d+", "Drupal CHANGELOG.txt"),
    ("Drupal",     "/sites/default/files/",                              r"Drupal|sites/default", "Drupal sites/default"),
    ("Joomla",     "/",                                                   r'<meta name="generator" content="Joomla', "Joomla generator meta"),
    ("Joomla",     "/administrator/",                                     r"Joomla|com_login", "Joomla admin login"),
    ("Magento",    "/",                                                   r"Magento|/skin/frontend/|/static/version", "Magento path"),
    ("Shopify",    "/",                                                   r"shopify-checkout-api-token|cdn\.shopify\.com", "Shopify CDN"),
    ("Ghost",      "/",                                                   r'<meta name="generator" content="Ghost', "Ghost generator"),
    ("PrestaShop", "/",                                                   r'<meta name="generator" content="PrestaShop', "PrestaShop generator"),
    ("TYPO3",      "/",                                                   r'<meta name="generator" content="TYPO3', "TYPO3 generator"),
]

@router.post("/api/scan/cms")
async def scan_cms(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
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
    return standard_response(tool="cms", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"CMS fingerprinting: {tests} checks across ~15 platforms; detected: {', '.join(sorted(detected))}",
        raw_data={"cms": {"detected": sorted(detected)}})
def register(app): app.include_router(router)
