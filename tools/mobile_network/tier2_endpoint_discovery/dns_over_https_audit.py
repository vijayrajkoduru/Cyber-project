"""dns_over_https_audit - DoH / DoT presence detection.
Sensitive apps (banking, secure messaging) should resolve via DoH/DoT to
prevent DNS-level traffic analysis + spoofing. Detection of:
DnsOverHttps (okhttp), Cloudflare 1.1.1.1, dns.google, Quad9 references,
NWParameters.requireDNSSEC on iOS."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.dns_over_https_audit_findings import DNS_OVER_HTTPS_AUDIT_FINDING_RULES

router = APIRouter()
DOH_LIB_RE = re.compile(r'DnsOverHttps|dns-over-https|doh|DOH')
DOH_RESOLVER_RE = re.compile(r'cloudflare-dns|1\.1\.1\.1|dns\.google|8\.8\.8\.8|dns\.quad9\.net|9\.9\.9\.9')
IOS_DOH_RE = re.compile(r'NWPathMonitor|requireDNSSEC|DoHConfig|NEDNSOverHTTPSSettings')
NETWORK_USE_RE = re.compile(r'OkHttpClient|HttpURLConnection|URLSession|getaddrinfo')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["dns_over_https_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["dns_over_https_audit_error"] = str(e); return
    doh_evidence = []
    network_clients = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h", ".xml", ".plist"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if DOH_LIB_RE.search(txt) or DOH_RESOLVER_RE.search(txt) or IOS_DOH_RE.search(txt):
            if len(doh_evidence) < 20:
                doh_evidence.append(p.name)
        if NETWORK_USE_RE.search(txt) and len(network_clients) < 20:
            network_clients.append(p.name)
    findings_total = 0
    if network_clients and not doh_evidence:
        findings_total += 1
    ctx.state["doh_evidence_files"] = doh_evidence
    ctx.state["network_client_files"] = network_clients
    ctx.state["files_scanned"] = files_scanned
    ctx.state["dns_over_https_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("DoH/DoT evidence", "doh_evidence_files"),
                ("Network client files", "network_client_files")]


@router.post("/api/mobile_network/dns_over_https_audit")
async def mobile_network_dns_over_https_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="dns_over_https_audit",
        gather_func=gather, finding_rules=DNS_OVER_HTTPS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
