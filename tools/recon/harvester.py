"""recon_harvester — OSINT email + host harvesting (defensive).

Tries theHarvester binary first; falls back to pure-Python DNS-based
host enumeration. ALWAYS returns a valid response — never raises an
uncaught exception to the wrapper.
"""
import asyncio, subprocess, re, shutil
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host

router = APIRouter()


async def recon_harvester_impl(req: ScanRequest):
    domain = recon_host(req.target)
    emails, hosts = [], []
    binary_attempted, binary_succeeded = False, False
    binary_error = None

    # Method 1: theHarvester binary (if present)
    if shutil.which("theHarvester"):
        binary_attempted = True
        try:
            proc = await asyncio.create_subprocess_exec(
                "theHarvester", "-d", domain, "-b", "duckduckgo,bing,crtsh", "-l", "50",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=4*1024*1024,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
                output = (stdout or b"").decode("utf-8", errors="ignore")
                for m in re.finditer(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", output):
                    e = m.group(0).lower()
                    if e not in emails and domain.lower() in e:
                        emails.append(e)
                for m in re.finditer(rf"\b([a-zA-Z0-9-]+\.{re.escape(domain)})\b", output):
                    h = m.group(0).lower()
                    if h not in hosts and h != domain.lower():
                        hosts.append(h)
                binary_succeeded = True
            except asyncio.TimeoutError:
                try: proc.kill()
                except: pass
                binary_error = "theHarvester subprocess timed out after 45s"
        except Exception as e:
            binary_error = f"{type(e).__name__}: {str(e)[:100]}"

    # Method 2: crt.sh fallback (always run — augments binary results)
    try:
        import requests
        r = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=10)
        if r.status_code == 200:
            try:
                certs = r.json()
                for c in certs[:200]:
                    nv = c.get("name_value", "")
                    for line in nv.split("\n"):
                        line = line.strip().lower()
                        if domain.lower() in line and "*" not in line and line not in hosts:
                            hosts.append(line)
            except Exception:
                pass
    except Exception:
        pass

    skipped_reason = None
    if not emails and not hosts:
        if binary_attempted and not binary_succeeded:
            skipped_reason = f"theHarvester failed: {binary_error or 'no output'}; crt.sh also empty"
        elif not binary_attempted:
            skipped_reason = "theHarvester binary not installed; crt.sh returned no hosts"
        else:
            skipped_reason = "No emails or hosts discovered for this domain"

    return {
        "ok": True,
        "vulnerable": False,
        "emails": sorted(set(emails))[:50],
        "hosts": sorted(set(hosts))[:100],
        "binary_attempted": binary_attempted,
        "binary_succeeded": binary_succeeded,
        "binary_error": binary_error,
        "skipped_reason": skipped_reason,
        "engine": "theHarvester (if installed) + crt.sh fallback, both with strict timeouts",
    }


# VLERR-WRAP-V1
@router.post("/api/recon/harvester")
async def recon_harvester(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await recon_harvester_impl(req)
    except Exception as _e:
        return {"ok": False,
                "skipped_reason": f"harvester scanner failed: {type(_e).__name__}: {str(_e)[:200]}",
                "error": f"{type(_e).__name__}: {str(_e)[:300]}"}


def register(app):
    app.include_router(router)
