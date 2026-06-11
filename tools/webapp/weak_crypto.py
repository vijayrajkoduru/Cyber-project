"""Webapp: weak crypto usage detection in JS (MD5/SHA1/DES/RC4)."""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync
from tools._vl_core.verify import vl_verify

router = APIRouter()

# Weak crypto patterns to look for in client-side JS
_WEAK_PATTERNS = [
    ("MD5",          re.compile(r"\bMD5\s*\(|CryptoJS\.MD5|hashlib\.md5|crypto\.createHash\(['\"]md5", re.I), "MD5"),
    ("SHA1",         re.compile(r"\bSHA1\s*\(|CryptoJS\.SHA1|crypto\.createHash\(['\"]sha1", re.I), "SHA1"),
    ("DES",          re.compile(r"CryptoJS\.DES|\bDES\.encrypt|TripleDES\.encrypt", re.I), "DES/3DES"),
    ("RC4",          re.compile(r"CryptoJS\.RC4|\bRC4\s*\(", re.I), "RC4"),
    ("ECB mode",     re.compile(r"mode:\s*CryptoJS\.mode\.ECB|ECB\s*\(", re.I), "AES-ECB"),
    ("Math.random crypto", re.compile(r"Math\.random\(\)[^;]*(?:token|password|secret|key|nonce|salt)", re.I), "Math.random() for crypto"),
]


@router.post("/api/webapp/weak_crypto")
@vl_verify()
async def webapp_weak_crypto(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    tests = 0
    detected = []
    
    # Fetch homepage + extract JS file URLs
    r = safe_get(base + "/", req=req, allow_redirects=True, timeout=10)
    if r is None:
        return standard_response(tool="weak_crypto", target=req.target, findings=[],
                                 tests_performed=0, skipped_reason="Could not reach target")
    js_urls = list(set(re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', r.text or "", re.I)))[:30]
    
    bodies = [("homepage", (r.text or "")[:300000])]
    tests += len(js_urls)

    async def _fetch_js(ju):
        full = ju if ju.startswith("http") else (base + (ju if ju.startswith("/") else "/" + ju))
        jr = await asyncio.to_thread(safe_get, full, req=req, timeout=6)
        return (ju, jr)

    js_results = await asyncio.gather(
        *[_fetch_js(ju) for ju in js_urls],
        return_exceptions=True)
    for jres in js_results:
        if isinstance(jres, BaseException) or jres is None:
            continue
        ju, jr = jres
        if jr is not None and jr.status_code == 200:
            bodies.append((ju, (jr.text or "")[:300000]))
    
    seen = set()
    for source, body in bodies:
        for label, pattern, name in _WEAK_PATTERNS:
            m = pattern.search(body)
            if not m:
                continue
            key = (source, label)
            if key in seen:
                continue
            seen.add(key)
            snippet = body[max(0, m.start()-30):m.end()+30].replace("\n", " ")[:120]
            detected.append({"source": source, "weak": label, "snippet": snippet})
            sev = "MEDIUM" if label in ("MD5","SHA1","Math.random crypto") else "HIGH"
            cvss = "5.3" if sev == "MEDIUM" else "7.5"
            findings.append(wrap_finding(
                f"Weak crypto: {name} used in client-side JS ({source})",
                sev,
                cvss=cvss, cwe="CWE-327",
                cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                owasp="A02:2021",
                remediation=("Replace " + name + " with a strong alternative: "
                             "SHA-256+ for hashing, AES-256-GCM for encryption, "
                             "crypto.getRandomValues() (browser) or crypto.randomBytes() (Node) for randomness. "
                             "Never use Math.random() for tokens/secrets."),
                evidence_marker=f"Pattern '{name}' found in {source}: ...{snippet}...",
            ))

    return standard_response(
        tool="weak_crypto", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Scanned {len(bodies)} JS source(s) for {len(_WEAK_PATTERNS)} weak-crypto patterns",
        raw_data={"weak_crypto": {"detected": detected, "sources_scanned": len(bodies),
                                     "spa_catchall": spa["is_spa"]}},
    )


def register(app):
    app.include_router(router)
