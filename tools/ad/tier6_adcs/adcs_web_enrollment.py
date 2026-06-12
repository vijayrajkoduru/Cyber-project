"""adcs_web_enrollment - AD CS Web Enrollment / ESC8 surface probe (playbook §6 #77).

Safe HTTP probe for the AD CS Web Enrollment role (CertSrv). Checks the standard
enrollment paths on both HTTP and HTTPS and inspects the WWW-Authenticate header.
An ESC8 relay surface exists when /certsrv answers with an NTLM/Negotiate
challenge over CLEARTEXT HTTP — that is the endpoint ntlmrelayx relays coerced
machine authentication to in order to mint a DC certificate.

ZERO-FP: the graded ESC8 finding fires ONLY when such a challenge is actually
observed on the live target. VA-not-PT: we never coerce, never relay, never
request a certificate. Detection only.

Customer input: ScanRequest.target = CA / web-enrollment host IP or hostname.
No creds needed.
"""
from __future__ import annotations
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ad_adcs_web_enrollment_findings import AD_ADCS_WEB_ENROLLMENT_FINDING_RULES

router = APIRouter()
_PATHS = ["/certsrv/", "/certsrv/certfnsh.asp", "/certsrv/certrqxt.asp"]
_TIMEOUT = 8.0


def _is_ntlm_challenge(headers) -> bool:
    """True if WWW-Authenticate advertises NTLM or Negotiate (the relay target)."""
    val = ""
    try:
        val = (headers.get("www-authenticate") or "").lower()
    except Exception:
        return False
    return "ntlm" in val or "negotiate" in val


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["ad_adcs_web_enrollment_total"] = 0
        ctx.source("no-target")
        return
    try:
        import httpx
    except ImportError:
        ctx.state["ad_adcs_web_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    # Strip any scheme the user may have included.
    host = target.split("://", 1)[-1].split("/", 1)[0]

    probed = []
    http_surface = []   # cleartext-HTTP NTLM endpoints (ESC8 relay target)
    https_present = []  # HTTPS enrollment endpoints (advisory only)

    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT,
                                     follow_redirects=False) as client:
            for scheme, port in (("http", 80), ("https", 443)):
                for path in _PATHS:
                    url = f"{scheme}://{host}:{port}{path}"
                    try:
                        r = await client.get(url)
                    except Exception:
                        continue
                    probed.append({"url": url, "status": r.status_code})
                    # certsrv answers 401 with an NTLM/Negotiate challenge.
                    is_certsrv = (r.status_code in (200, 401, 403)
                                  and ("certsrv" in url.lower()))
                    if not is_certsrv:
                        continue
                    ntlm = _is_ntlm_challenge(r.headers)
                    if scheme == "http" and ntlm:
                        http_surface.append({"url": url, "auth": "NTLM/Negotiate",
                                             "status": r.status_code})
                    elif scheme == "https":
                        https_present.append({"url": url,
                                              "auth": "NTLM/Negotiate" if ntlm else "other",
                                              "status": r.status_code})
    except Exception as e:
        ctx.state["ad_adcs_web_error"] = f"probe failed: {str(e)[:120]}"
        ctx.source(f"probe error: {str(e)[:80]}")
        return

    ctx.state["ad_adcs_web_endpoints"] = probed
    ctx.state["ad_adcs_esc8_surface"] = http_surface
    ctx.state["ad_adcs_https_endpoints"] = https_present
    # total = number of graded (ESC8 cleartext) surfaces actually detected.
    ctx.state["ad_adcs_web_enrollment_total"] = len(http_surface)
    ctx.source(f"probed {len(probed)} certsrv paths; "
               f"{len(http_surface)} HTTP-NTLM surface, {len(https_present)} HTTPS")


INTEL_FIELDS = [("Endpoints probed", "ad_adcs_web_endpoints"),
                ("ESC8 HTTP-NTLM surface", "ad_adcs_esc8_surface"),
                ("HTTPS enrollment endpoints", "ad_adcs_https_endpoints")]


@router.post("/api/ad/adcs_web_enrollment")
async def ad_adcs_web_enrollment(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="adcs_web_enrollment",
        gather_func=gather, finding_rules=AD_ADCS_WEB_ENROLLMENT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
