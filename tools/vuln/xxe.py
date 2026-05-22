"""XXE — multi-variant XML external entity injection.

Payload source: tools/_payloads/xxe.py (XXE_PAYLOADS, 18 entries across
classic / parameter-ent / xinclude / svg / soap / docx / utf16 / json-xml /
blind-oob / dos). Each entry carries its own matcher regex; we skip
blind-oob and dos entries (no inline reflection / not safe for prod).

Each payload is tested across multiple Content-Types so parsers that only
honor a specific MIME still get exercised.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._payloads.xxe import XXE_PAYLOADS

router = APIRouter()

_CTS = ["application/xml", "text/xml", "application/x-xml",
        "application/soap+xml", "image/svg+xml"]


def _testable_payloads():
    """Drop blind-oob (needs OOB infra) and dos (unsafe for live targets)."""
    return [p for p in XXE_PAYLOADS if p.get("category") not in ("blind-oob", "dos")]


_PAYLOAD_SET = _testable_payloads()


def _pick_cts_for(category):
    """SVG variant only needs image/svg+xml; SOAP needs soap envelope CT;
    everything else tries the generic XML CTs."""
    if category == "svg":      return ["image/svg+xml", "application/xml"]
    if category == "soap":     return ["application/soap+xml", "text/xml"]
    if category == "json-xml": return ["application/xml", "application/json"]
    return ["application/xml", "text/xml"]


@router.post("/api/scan/xxe")
async def scan_xxe(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings, tests, confirmed = [], 0, []

    for entry in _PAYLOAD_SET:
        variant = entry.get("name", entry.get("category", "xxe"))
        body = entry["body"]
        matcher = entry["matcher"]
        category = entry.get("category", "classic")
        cts = _pick_cts_for(category)
        for ct in cts:
            tests += 1
            r = safe_request("POST", url,
                headers={"Content-Type": ct, "User-Agent": "VulnusLab/1.0"},
                data=body, req=req, timeout=10, allow_redirects=False)
            if r is None: continue
            try:
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
                    return standard_response(tool="xxe", target=req.target,
                        findings=findings, tests_performed=tests,
                        tests_summary=(f"XXE: confirmed on first hit — {tests} payload×content-type "
                                       f"combos tested from {len(_PAYLOAD_SET)}-entry library "
                                       f"(XXE_PAYLOADS, 10 categories)"),
                        raw_data={"xxe": {"confirmed": confirmed,
                                           "library_size": len(XXE_PAYLOADS)}})
            except re.error:
                continue

    return standard_response(tool="xxe", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=(f"XXE: tested {tests} payload×content-type combos from "
                       f"{len(_PAYLOAD_SET)}-entry library (XXE_PAYLOADS, 10 categories) "
                       f"— classic, parameter-entity, XInclude, SVG, SOAP, Office-XML, UTF-16, JSON→XML"),
        raw_data={"xxe": {"confirmed": confirmed,
                           "library_size": len(XXE_PAYLOADS)}})


def register(app):
    app.include_router(router)
