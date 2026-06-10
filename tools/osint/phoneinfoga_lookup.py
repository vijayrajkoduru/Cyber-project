"""phoneinfoga_lookup — phone number OSINT (libphonenumber + numverify advisory)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    raw = (req.target or "").strip()
    # Basic format check
    phone = re.sub(r"[^\d+]", "", raw)
    if not phone or len(phone) < 7:
        return standard_response(
            tool="phoneinfoga_lookup", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be a phone number")

    findings = [wrap_finding(
        f"Phone OSINT for {phone}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="For active phone-OSINT (carrier, line type, location), "
                    "use NumVerify (250 free/mo, $19.99/mo paid), Twilio "
                    "Lookup ($0.005/lookup), or PhoneInfoga CLI (open-source, "
                    "scrapes free sources). Pass auth_bearer = NumVerify API key "
                    "to enable real lookup in next session.",
        evidence_marker=f"phone={phone} | how-to: "
                          f"https://numverify.com/api/{phone[:6]}…")]

    key = (req.auth_bearer or "").strip()
    if key:
        r = safe_get(f"http://apilayer.net/api/validate?access_key={key}&number={phone}",
                      req=req, timeout=6,
                      headers={"User-Agent": "VulnusLab-OSINT/1.0"})
        if r is not None and r.status_code == 200:
            try:
                data = r.json()
                if data.get("valid"):
                    findings = [wrap_finding(
                        f"NumVerify: {phone} → {data.get('country_name','?')} "
                        f"({data.get('carrier','?')}, {data.get('line_type','?')})",
                        severity="POSITIVE", cwe="CWE-200",
                        remediation="Public number metadata.",
                        evidence_marker=f"country={data.get('country_code','?')}"
                                          f" carrier={data.get('carrier','?')} "
                                          f"line_type={data.get('line_type','?')}")]
            except Exception:
                pass

    return standard_response(
        tool="phoneinfoga_lookup", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"phone={phone}",
        raw_data={"phone": phone})


@router.post("/api/osint/phoneinfoga_lookup")
@vl_verify()
async def scan_phoneinfoga_lookup(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(tool="phoneinfoga_lookup", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
