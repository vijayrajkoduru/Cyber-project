"""SSH version + protocol audit (banner-based CVE hints). VL-FORGE Vuln tier1 - §1 #6."""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import tcp_probe

router = APIRouter()


async def gather(ctx):
    host = str(ctx.host)
    op, data = await asyncio.to_thread(tcp_probe, host, 22, b"", 128, 5)
    if not op:
        ctx.state["tested"] = 0
        return
    ctx.source("tcp-22")
    ctx.state["tested"] = 1
    banner = data.decode("utf-8", "ignore").strip()
    ctx.state["ssh_banner"] = banner
    m = re.search(r"SSH-(\d+\.\d+)-(.+)", banner)
    if m:
        ctx.state["ssh_proto"] = m.group(1)
        ctx.state["ssh_software"] = m.group(2)[:60]
    vm = re.search(r"OpenSSH[_-](\d+)\.(\d+)", banner)
    if vm:
        ctx.state["openssh_major"] = int(vm.group(1))
        ctx.state["openssh_minor"] = int(vm.group(2))


def _r_v1(s):
    if s.get("ssh_proto") not in ("1.0", "1.5", "1.99"):
        return None
    return {"name": "SSH protocol 1.x supported (insecure)", "severity": "CRITICAL", "cvss": 9.0, "cwe": "CWE-327",
            "evidence": f"Banner: {s.get('ssh_banner')}", "remediation": "Disable SSHv1 — Protocol 2 only."}


def _r_old(s):
    maj = s.get("openssh_major")
    if maj is None:
        return None
    minr = s.get("openssh_minor", 0)
    if maj < 7 or (maj == 7 and minr < 7):
        return {"name": f"Outdated OpenSSH {maj}.{minr} (known CVEs)", "severity": "HIGH", "cvss": 7.5,
                "cwe": "CWE-1395", "evidence": f"Banner: {s.get('ssh_banner')}",
                "remediation": "Upgrade OpenSSH; <7.7 has user-enum CVE-2018-15473 among others."}
    return None


def _r_banner(s):
    if not s.get("ssh_banner") or s.get("ssh_proto") in ("1.0", "1.5", "1.99"):
        return None
    maj = s.get("openssh_major")
    if maj is not None and (maj < 7 or (maj == 7 and s.get("openssh_minor", 0) < 7)):
        return None
    return {"name": f"SSH service exposed: {s.get('ssh_software') or s.get('ssh_banner')}", "severity": "INFO",
            "cwe": "CWE-200", "evidence": f"Banner: {s.get('ssh_banner')}",
            "remediation": "Restrict SSH to VPN/bastion; key-only auth; fail2ban."}


FINDING_RULES = [_r_v1, _r_old, _r_banner]
INTEL_FIELDS = [("SSH banner", "ssh_banner")]


@router.post("/api/vuln/ssh_audit")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="ssh_audit",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
