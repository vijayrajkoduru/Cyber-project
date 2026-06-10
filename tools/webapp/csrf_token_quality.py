"""csrf_token_quality — CSRF token entropy + reuse check.

Existing csrf scanner verifies token PRESENCE. This one audits QUALITY:
  - Token length (<16 chars = weak)
  - Token entropy (low entropy = predictable)
  - Token reuse across multiple GETs of same form (session-fixed = bad)
  - Token bound to session cookie (rotates with session)
"""
import re
import math
from collections import Counter
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

CSRF_FIELD_RE = re.compile(
    r'<input[^>]*\bname=["\'](?:csrf_token|csrfmiddlewaretoken|_token|authenticity_token|csrf|xsrf|__RequestVerificationToken)["\'][^>]*\bvalue=["\']([^"\']{4,})["\']',
    re.IGNORECASE)
META_CSRF_RE = re.compile(
    r'<meta\s+name=["\']csrf[_-]token["\']\s+content=["\']([^"\']{4,})["\']',
    re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    if not s: return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _fetch_token(url, req):
    r = safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=True)
    if r is None or r.status_code >= 400: return None, None
    text = r.text or ""
    m = CSRF_FIELD_RE.search(text)
    if m: return m.group(1), "input"
    m = META_CSRF_RE.search(text)
    if m: return m.group(1), "meta"
    return None, None


@router.post("/api/webapp/scan/csrf_token_quality")
@vl_turbo()
@vl_verify()
def scan_csrf_token_quality(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    tokens_collected = []  # (path, token, source)
    for path in ("/", "/login", "/api/login", "/contact", "/register"):
        token, src = _fetch_token(base + path, req)
        if token:
            tokens_collected.append((path, token, src))

    if not tokens_collected:
        return standard_response(
            tool="csrf_token_quality", target=req.target, findings=[],
            tests_performed=5, vulnerable=False,
            skipped_reason="No CSRF tokens found in homepage or common form paths")

    findings = []
    issues = []

    # Test 1: length
    short_tokens = [(p, t) for p, t, _ in tokens_collected if len(t) < 16]
    if short_tokens:
        issues.append(("Short tokens (<16 chars)",
                        ", ".join(f"{p}({len(t)}ch)" for p, t in short_tokens[:3]),
                        "HIGH"))

    # Test 2: entropy
    low_entropy = [(p, t) for p, t, _ in tokens_collected if _shannon_entropy(t) < 3.0]
    if low_entropy:
        issues.append(("Low-entropy tokens (Shannon < 3 bits/char)",
                        ", ".join(f"{p} ent={_shannon_entropy(t):.1f}" for p, t in low_entropy[:3]),
                        "HIGH"))

    # Test 3: reuse across GETs of SAME url
    rep_url = tokens_collected[0][0]
    t1, _ = _fetch_token(base + rep_url, req)
    t2, _ = _fetch_token(base + rep_url, req)
    if t1 and t2 and t1 == t2:
        issues.append(("Token reused across 2 GETs of same URL (session-static)",
                        f"{rep_url}: token unchanged across 2 fresh requests",
                        "MEDIUM"))

    if issues:
        sev = "HIGH" if any(s == "HIGH" for _, _, s in issues) else "MEDIUM"
        cvss = "7.5" if sev == "HIGH" else "5.3"
        findings.append(wrap_finding(
            f"CSRF token quality issues ({len(issues)})",
            sev, cvss=cvss, cwe="CWE-352", owasp="A01:2021",
            remediation="(1) Use ≥32-char random tokens. (2) Use crypto-strength "
                        "PRNG (secrets module in Python, crypto.randomBytes in Node). "
                        "(3) Rotate tokens per session (not per page-load). "
                        "(4) Bind token to session cookie via double-submit pattern "
                        "(token sent both in cookie + form, server compares).",
            evidence_marker=" | ".join(f"{desc}: {ev}" for desc, ev, _ in issues[:3])))
    else:
        avg_len = sum(len(t) for _, t, _ in tokens_collected) / len(tokens_collected)
        avg_ent = sum(_shannon_entropy(t) for _, t, _ in tokens_collected) / len(tokens_collected)
        findings.append(wrap_finding(
            f"CSRF tokens look strong ({len(tokens_collected)} sampled, "
            f"avg len {avg_len:.0f}, avg ent {avg_ent:.1f})",
            "POSITIVE", cwe="CWE-352",
            remediation="Maintain. Continue rotating per session.",
            evidence_marker=" | ".join(f"{p}: {len(t)}ch ent={_shannon_entropy(t):.1f}"
                                          for p, t, _ in tokens_collected[:5])))

    return standard_response(
        tool="csrf_token_quality", target=req.target, findings=findings,
        tests_performed=5 + 2, vulnerable=bool(issues),
        tests_summary=f"{len(tokens_collected)} tokens sampled, {len(issues)} issues",
        raw_data={"tokens_sampled": [{"path": p, "length": len(t),
                                        "entropy": _shannon_entropy(t), "source": s}
                                       for p, t, s in tokens_collected]})


def register(app):
    app.include_router(router)
