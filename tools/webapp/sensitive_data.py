"""Sensitive data exposure — regex-scan response bodies for leaked secrets."""
import re
import time
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

# (name, pattern, severity, description)
_PATTERNS = [
    ("aws_access_key",   re.compile(r"AKIA[0-9A-Z]{16}"),         "CRITICAL", "AWS Access Key"),
    ("aws_secret",       re.compile(r"aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]", re.I), "CRITICAL", "AWS Secret"),
    ("rsa_private",      re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "CRITICAL", "RSA/SSH Private Key"),
    ("api_key_generic",  re.compile(r"['\"][A-Za-z0-9_-]{32,64}['\"]\s*[,}]"), "INFO", "Possible API key string"),
    ("password_field",   re.compile(r'"password"\s*:\s*"[^"]{4,}"'), "HIGH", "Password in API response"),
    ("password_hash",    re.compile(r'\$2[abxy]?\$\d+\$[./A-Za-z0-9]{53}'), "HIGH", "bcrypt password hash"),
    ("jwt_token",        re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "MEDIUM", "JWT in response body"),
    ("stripe_key",       re.compile(r"sk_live_[A-Za-z0-9]{24,}"),  "CRITICAL", "Stripe Secret Key"),
    ("ssn_us",           re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),     "HIGH", "US SSN"),
    ("credit_card",      re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "CRITICAL", "Credit Card Number"),
    ("email_bulk",       re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'), "LOW", "Email address"),
]


@router.post("/api/webapp/scan/sensitive_data")
@vl_turbo()
@vl_verify()
def scan_sensitive_data(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = load_spa_state(req.target)
    # Collect URLs to probe — base + SPA-discovered + common API roots
    urls_to_scan = {base, base + "/"}
    for u in (spa.get("urls") or [])[:20]:
        urls_to_scan.add(u)
    for u in list(spa.get("endpoints", {}).keys())[:15]:
        urls_to_scan.add(u if u.startswith("http") else base + u)
    for api in ("/api/users", "/api/Users", "/rest/user", "/api/feedbacks",
                 "/api/Feedbacks", "/api/products", "/api/Products"):
        urls_to_scan.add(base + api)

    findings, tests, hits_by_pattern = [], 0, {}
    seen_values = set()  # dedupe — only report each distinct match once

    # VL-TURBO wall-clock cap: 25 URLs × 8s × retries = up to 10 min without cap.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 45.0
    _bailed = False
    for url in list(urls_to_scan)[:25]:
        if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
            _bailed = True; break
        tests += 1
        r = safe_get(url, req=req, allow_redirects=True, timeout=8)
        if r is None or not r.text:
            continue
        body = r.text[:50000]  # cap per response

        for name, pattern, sev, desc in _PATTERNS:
            matches = pattern.findall(body)
            for m in matches[:3]:  # cap 3 per pattern per URL
                # Skip emails inside this scanner's own infrastructure (vulnuslab.example domains)
                if name == "email_bulk" and ("vulnuslab.example" in m or "canary" in m.lower()):
                    continue
                # Truncate match for safe display
                m_str = str(m)
                display = m_str[:40] + "…" if len(m_str) > 40 else m_str
                key = f"{name}:{display}"
                if key in seen_values:
                    continue
                seen_values.add(key)
                hits_by_pattern[name] = hits_by_pattern.get(name, 0) + 1
                findings.append(wrap_finding(
                    f"Sensitive data exposed: {desc} at {url}",
                    sev,
                    cvss={"CRITICAL": "9.1", "HIGH": "7.5", "MEDIUM": "5.3",
                          "LOW": "3.1", "INFO": "0.0"}.get(sev, "3.1"),
                    cwe="CWE-200", owasp="A02:2021",
                    remediation=("Remove sensitive data from API responses. Mask, tokenise, or "
                               "filter at the serialisation layer. Audit API contracts."),
                    evidence_marker=f"{desc} pattern matched at {url}: {display}"))

    # Suppress email-only findings if they're below a noise threshold (10+ emails = data dump = real)
    if hits_by_pattern.get("email_bulk", 0) < 5:
        findings = [f for f in findings if "Email" not in f.get("detail", "")]

    summary = (f"Sensitive Data: {tests} URLs scanned with {len(_PATTERNS)} regex patterns "
               f"(AWS/Stripe/RSA/bcrypt/JWT/PII) in {time.time() - _wallclock_start:.1f}s")
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return standard_response(tool="sensitive_data", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=summary,
        raw_data={"sensitive_data": {"hits_by_pattern": hits_by_pattern,
                                       "urls_scanned": len(urls_to_scan),
                                       "wallclock_bailed": _bailed}})


def register(app):
    app.include_router(router)
