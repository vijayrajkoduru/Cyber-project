"""XXE — multi-variant XML external entity injection.

Payload source: tools/_payloads/xxe.py (XXE_PAYLOADS, 18 entries across
classic / parameter-ent / xinclude / svg / soap / docx / utf16 / json-xml /
blind-oob / dos). Each entry carries its own matcher regex; we skip
blind-oob and dos entries (no inline reflection / not safe for prod).

Each payload is tested across multiple Content-Types so parsers that only
honor a specific MIME still get exercised.
"""
import re
import time
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding)
from tools._payloads.xxe import XXE_PAYLOADS
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify
# AI-curated extras: more file targets, parameter-entity, XInclude, SVG, SOAP, UTF-16.
_AI_EXTRA_XXE = load_json("xxe_extra_payloads", fallback=[])
_MERGED_XXE = list(XXE_PAYLOADS) + [p for p in _AI_EXTRA_XXE if isinstance(p, dict) and "body" in p and "matcher" in p]

router = APIRouter()

_CTS = ["application/xml", "text/xml", "application/x-xml",
        "application/soap+xml", "image/svg+xml"]


def _testable_payloads():
    """Drop blind-oob (needs OOB infra) and dos (unsafe for live targets)."""
    return [p for p in _MERGED_XXE if p.get("category") not in ("blind-oob", "dos")]


_PAYLOAD_SET = _testable_payloads()


def _pick_cts_for(category):
    """SVG variant only needs image/svg+xml; SOAP needs soap envelope CT;
    everything else tries the generic XML CTs."""
    if category == "svg":      return ["image/svg+xml", "application/xml"]
    if category == "soap":     return ["application/soap+xml", "text/xml"]
    if category == "json-xml": return ["application/xml", "application/json"]
    return ["application/xml", "text/xml"]


@router.post("/api/webapp/scan/xxe")
@vl_turbo()
@vl_verify()
def scan_xxe(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    unreachable = precheck_target(url, req)
    if unreachable:
        return vuln_response(tool="xxe", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    findings, tests, confirmed = [], 0, []
    # VL-TURBO wall-clock cap: 36 payloads × 2 CTs × 10s × 3 retries = way over 240s.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 45.0
    _bailed = False

    for entry in _PAYLOAD_SET:
        if _bailed: break
        variant = entry.get("name", entry.get("category", "xxe"))
        body = entry["body"]
        matcher = entry["matcher"]
        category = entry.get("category", "classic")
        cts = _pick_cts_for(category)
        for ct in cts:
            if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
                _bailed = True; break
            tests += 1
            r = safe_request("POST", url,
                headers={"Content-Type": ct, "User-Agent": "VulnusLab/1.0"},
                data=body, req=req, timeout=8, retries=0, allow_redirects=False)
            if r is None: continue
            try:
                # Guard: an always-true matcher (".+"/".*") fires on any
                # response -> skip it (defense-in-depth against placeholder
                # matchers re-entering the payload set).
                if matcher and re.fullmatch(r"[()\s]*\.[+*?]*[()\s]*", matcher.strip()):
                    continue
                if re.search(matcher, (r.text or "")[:8000], re.IGNORECASE):
                    sev = str(entry.get("severity", "CRITICAL")).upper()
                    cvss = str(entry.get("cvss", "9.1"))
                    findings.append(wrap_finding(
                        f"XXE — {variant} ({category}) via Content-Type: {ct}",
                        sev, cvss=cvss, cwe="CWE-611", owasp="A05:2021",
                        remediation=("Disable XML external entities. Python: defusedxml. "
                                     "Java: setFeature('http://apache.org/xml/features/disallow-doctype-decl', true). "
                                     "PHP: libxml_disable_entity_loader(true). "
                                     ".NET: XmlResolver = null."),
                        evidence_marker=f"POST with {ct} and {variant} XXE returned body matching {matcher!r}"))
                    confirmed.append({"variant": variant, "category": category,
                                       "content_type": ct})
                    return vuln_response(tool="xxe", target=req.target,
                        findings=findings, tested=tests,
                        what_checked="XML external entity injection across multiple content-types",
                        tests_summary=(f"XXE: confirmed on first hit — {tests} payload×content-type "
                                       f"combos tested from {len(_PAYLOAD_SET)}-entry library "
                                       f"(XXE_PAYLOADS, 10 categories)"),
                        raw_data={"xxe": {"confirmed": confirmed,
                                           "library_size": len(_MERGED_XXE), "ai_extras_loaded": len(_AI_EXTRA_XXE)}})
            except re.error:
                continue

    summary = (f"XXE: tested {tests} payload×content-type combos from "
               f"{len(_PAYLOAD_SET)}-entry library in {time.time() - _wallclock_start:.1f}s "
               f"— classic, parameter-entity, XInclude, SVG, SOAP, Office-XML, UTF-16, JSON→XML")
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return vuln_response(tool="xxe", target=req.target, findings=findings,
        tested=max(tests, 1),
        what_checked="XML external entity injection across multiple content-types",
        severity_when_clean="POSITIVE",
        tests_summary=summary,
        raw_data={"xxe": {"confirmed": confirmed,
                           "library_size": len(_MERGED_XXE), "ai_extras_loaded": len(_AI_EXTRA_XXE),
                           "wallclock_bailed": _bailed}})


def register(app):
    app.include_router(router)
