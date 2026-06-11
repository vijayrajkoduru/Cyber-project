"""Webapp secrets scanner — regex match against AI-curated 97-pattern catalog.

Route: POST /api/webapp/secrets
Loads tools/_payloads/secrets_patterns.py (97 handcrafted regex patterns
covering AWS / GCP / Azure / GitHub / Slack / Stripe / Twilio / JWT /
RSA keys / DB connection strings / Indian fintech / AI provider keys).

Workflow:
  1. Fetch homepage + crawl ≤ 10 same-origin JS files
  2. Run every AI pattern against each response body
  3. Emit a finding per (file, pattern) hit — capped at 30 to avoid spam
"""
import re

import httpx

from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()

_FALLBACK_PATTERNS = [
    {"name": "AWS Access Key ID", "regex": r"AKIA[0-9A-Z]{16}",
     "service": "aws", "severity": "CRITICAL", "cvss": "9.8",
     "remediation": "Rotate the AWS key immediately."},
    {"name": "RSA Private Key", "regex": r"-----BEGIN RSA PRIVATE KEY-----",
     "service": "private_key", "severity": "CRITICAL", "cvss": "10.0",
     "remediation": "Rotate key pair IMMEDIATELY."},
    {"name": "JWT Token", "regex": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}",
     "service": "jwt", "severity": "MEDIUM", "cvss": "5.5",
     "remediation": "Move JWT to HttpOnly cookies."},
]
try:
    from tools._payloads.secrets_patterns import SECRETS_PATTERNS as _AI_SECRETS
    _PATTERNS = list(_AI_SECRETS) if isinstance(_AI_SECRETS, list) and _AI_SECRETS else _FALLBACK_PATTERNS
except Exception:
    _PATTERNS = _FALLBACK_PATTERNS

# Pre-compile patterns once for speed
_COMPILED = []
for _p in _PATTERNS:
    try:
        _COMPILED.append((_p, re.compile(_p["regex"], re.IGNORECASE)))
    except Exception:
        continue  # skip malformed regex

_TIMEOUT = httpx.Timeout(connect=4.0, read=6.0, write=3.0, pool=8.0)
_MAX_JS_FILES = 10
_MAX_BODY_BYTES = 1_500_000  # cap per-file scan to 1.5MB
_MAX_FINDINGS = 30


async def _fetch_with_extracted_js(client, base):
    """Fetch homepage; extract up to N same-origin .js URLs; fetch each."""
    bodies = []  # list of (label, content)
    try:
        r = await client.get(base + "/")
        bodies.append((base + "/", (r.text or "")[:_MAX_BODY_BYTES]))
        html = r.text or ""
    except Exception:
        return bodies
    # Extract <script src="..."> URLs (same-origin only)
    src_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
    seen = set()
    for m in src_re.finditer(html):
        url = m.group(1)
        if url.startswith("//"): continue
        if url.startswith("http") and not url.startswith(base): continue
        if not url.startswith("http"):
            url = base + ("" if url.startswith("/") else "/") + url.lstrip("/")
        if url in seen: continue
        seen.add(url)
        if len(seen) > _MAX_JS_FILES: break
        try:
            jr = await client.get(url)
            bodies.append((url, (jr.text or "")[:_MAX_BODY_BYTES]))
        except Exception:
            continue
    return bodies


@router.post("/api/webapp/secrets")
@vl_verify(check_spa=True)
async def webapp_secrets(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    hits = []

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=_TIMEOUT,
        headers={"User-Agent": "VulnusLab/1.0"}
    ) as client:
        bodies = await _fetch_with_extracted_js(client, base)

    # Scan each body against every compiled pattern
    for label, body in bodies:
        if not body: continue
        for entry, compiled in _COMPILED:
            for m in compiled.finditer(body):
                snippet = m.group(0)[:80]
                hits.append({
                    "name": entry["name"], "service": entry["service"],
                    "severity": entry["severity"], "url": label,
                    "snippet": snippet,
                })
                if len(hits) >= _MAX_FINDINGS:
                    break
            if len(hits) >= _MAX_FINDINGS:
                break
        if len(hits) >= _MAX_FINDINGS:
            break

    # Dedupe by (service, snippet) so we don't report the same key twice
    seen = set()
    unique_hits = []
    for h in hits:
        k = (h["service"], h["snippet"])
        if k in seen: continue
        seen.add(k)
        unique_hits.append(h)

    for h in unique_hits[:20]:
        sev = h["severity"] if h["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"
        # Find the original entry to grab cvss + remediation
        orig = next((e for e in _PATTERNS if e.get("name") == h["name"]), {})
        cvss = orig.get("cvss", "5.0")
        rem = orig.get("remediation", "Rotate the leaked credential immediately.")
        findings.append(wrap_finding(
            f"Secret leaked in client-side response: {h['name']}",
            sev, cvss=cvss, cwe="CWE-200",
            cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
            owasp="A02:2021",
            remediation=rem,
            evidence_marker=f"At {h['url']}: matched pattern '{h['name']}' (snippet: {h['snippet'][:60]}...)",
        ))

    return standard_response(
        tool="secrets", target=req.target,
        findings=findings,
        tests_performed=len(_COMPILED) * len(bodies),
        tests_summary=f"Scanned {len(bodies)} response bodies against {len(_COMPILED)} AI-curated regex patterns; {len(unique_hits)} unique leaks found",
        raw_data={"secrets": {
            "patterns_loaded": len(_COMPILED),
            "bodies_scanned": len(bodies),
            "unique_hits": len(unique_hits),
            "wordlist_source": f"AI-curated ({len(_PATTERNS)} patterns)",
            "services_with_hits": sorted({h["service"] for h in unique_hits}),
        }},
    )


def register(app):
    app.include_router(router)
