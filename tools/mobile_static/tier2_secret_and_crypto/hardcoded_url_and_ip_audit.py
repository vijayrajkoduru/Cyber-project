"""hardcoded_url_and_ip_audit — find cleartext URLs + internal IPs in decompiled tree."""
import ipaddress
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.hardcoded_url_and_ip_audit_findings import HARDCODED_URL_AND_IP_AUDIT_FINDING_RULES

router = APIRouter()

URL_RE = re.compile(r'https?://[A-Za-z0-9._\-/:?=&%~#@!,;\'\(\)\*\+\$]+')
IP_RE  = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

SCAN_EXTS = (".java", ".kt", ".smali", ".xml", ".json", ".properties")
NOISE_HOSTS = {
    "example.com", "schemas.android.com", "schemas.openxmlformats.org",
    "www.w3.org", "xmlns.jcp.org", "java.sun.com", "play.google.com",
    "developer.android.com", "fonts.gstatic.com",
}


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["hardcoded_url_and_ip_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["hardcoded_url_and_ip_audit_error"] = str(e)
        return

    cleartext_urls = set()
    internal_ips = set()
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in SCAN_EXTS:
            continue
        if files_scanned >= 4000:
            break
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_scanned += 1
        for url in URL_RE.findall(text):
            if url.startswith("http://"):
                host = url.split("/")[2].split(":")[0].lower()
                if host not in NOISE_HOSTS and not host.endswith(".local"):
                    cleartext_urls.add(url[:200])
        for ip in IP_RE.findall(text):
            if _is_internal(ip):
                internal_ips.add(ip)
        if len(cleartext_urls) + len(internal_ips) >= 300:
            break

    ctx.state["cleartext_urls"] = sorted(cleartext_urls)[:50]
    ctx.state["internal_ips"] = sorted(internal_ips)[:50]
    ctx.state["hardcoded_url_and_ip_audit_total"] = len(cleartext_urls) + len(internal_ips)
    ctx.source(f"regex-url-scan ({files_scanned} files)")


INTEL_FIELDS = [
    ("Cleartext URLs", "cleartext_urls"),
    ("Internal IPs", "internal_ips"),
]


@router.post("/api/mobile_static/hardcoded_url_and_ip_audit")
async def mobile_static_hardcoded_url_and_ip_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="hardcoded_url_and_ip_audit",
        gather_func=gather,
        finding_rules=HARDCODED_URL_AND_IP_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
