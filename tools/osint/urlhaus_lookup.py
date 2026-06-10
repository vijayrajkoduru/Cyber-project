"""URLhaus malware-URL reputation lookup — playbook §4 #54.

abuse.ch URLhaus API: queries a URL/host against the global blocklist of
known-malicious URLs. Free, no key required for low-volume use. POST API.

Real probe. Zero false positives — only reports if URLhaus has a confirmed
entry.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_post, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip()
    if not target:
        return standard_response(
            tool="urlhaus_lookup", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty target")

    # URLhaus accepts both host and full URL queries
    is_url = target.startswith(("http://", "https://"))
    endpoint = "url" if is_url else "host"
    field = "url" if is_url else "host"
    host = target if not is_url else target.split("//", 1)[1].split("/", 1)[0]

    r = safe_post(
        f"https://urlhaus-api.abuse.ch/v1/{endpoint}/",
        req=req, timeout=8,
        data={field: target if is_url else host},
        headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="urlhaus_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"URLhaus unreachable (status={r.status_code if r else 'no-conn'})")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="urlhaus_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON URLhaus response")

    status = data.get("query_status", "")
    if status == "no_results":
        return standard_response(
            tool="urlhaus_lookup", target=req.target,
            findings=[wrap_finding(
                f"URLhaus has NO malicious entries for {target}",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Not on the abuse.ch malware blocklist as of this scan. "
                            "Re-scan periodically as new URLs are added daily.",
                evidence_marker="URLhaus query_status=no_results (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Clean per URLhaus")
    if status != "ok":
        return standard_response(
            tool="urlhaus_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"URLhaus status={status}")

    urls = data.get("urls", []) if endpoint == "host" else [data]
    threats = [(u.get("url"), u.get("threat"), u.get("date_added"),
                 u.get("url_status"))
                for u in urls if u]
    active = [t for t in threats if t[3] == "online"]

    findings = [wrap_finding(
        f"URLhaus FLAGGED — {len(threats)} malicious URL(s) "
        f"({len(active)} currently active) for {target}",
        severity="CRITICAL", cvss="9.0", cwe="CWE-829",
        owasp="A06:2021",
        remediation="This host has hosted malware per abuse.ch. If this is YOUR "
                    "host: server is compromised — isolate, investigate, rebuild. "
                    "If this is a THIRD-PARTY: block at firewall + email gateway.",
        evidence_marker=" | ".join(
            f"{t[0]} ({t[1]}, added {t[2]}, status {t[3]})"
            for t in threats[:5]
        ) + (' ...' if len(threats) > 5 else '') + " (CONFIRMED via URLhaus)")]

    return standard_response(
        tool="urlhaus_lookup", target=req.target, findings=findings,
        tests_performed=1, vulnerable=True,
        tests_summary=f"URLhaus: {len(threats)} malicious URLs",
        raw_data={"threats": [list(t) for t in threats[:20]],
                   "total": len(threats), "active": len(active)})


@router.post("/api/osint/urlhaus_lookup")
@vl_verify()
async def scan_urlhaus_lookup(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="urlhaus_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
