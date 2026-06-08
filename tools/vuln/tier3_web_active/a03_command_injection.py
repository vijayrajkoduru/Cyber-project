"""A03 Command Injection - passive sleep-free output detection. Self-contained.
Strategy: inject a benign payload like ';id;' in common params, look for uid=/gid=/groups= output."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, CMD_PATTERNS

router = APIRouter()

PROBE_PARAMS = ["cmd", "exec", "ip", "host", "ping", "query", "system", "do"]
PAYLOAD = ";id"


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base or base.get("status", 0) >= 500:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_params"] = len(PROBE_PARAMS)
    hits = []
    for p in PROBE_PARAMS:
        url = f"{base_url}?{p}={PAYLOAD}"
        r = await http_get_async(url, timeout=8)
        if not r:
            continue
        body = r.get("body", "")
        for pattern in CMD_PATTERNS:
            if re.search(pattern, body):
                hits.append({"param": p, "evidence": pattern, "status": r.get("status")})
                break
    ctx.state["cmd_hits"] = hits


def _r_cmd(s):
    hits = s.get("cmd_hits") or []
    if not hits:
        return None
    return {"name": f"Command injection output observed via {len(hits)} parameter(s)", "severity": "CRITICAL", "cvss": 9.8,
            "cwe": "CWE-78",
            "evidence": f"OS command output (uid/gid) reflected in: {', '.join(h['param'] for h in hits)}",
            "remediation": "Never pass user input to shell. Use language-native APIs; if shell needed, use exec arrays with shell=False."}


FINDING_RULES = [_r_cmd]
INTEL_FIELDS = [("Parameters probed", "probed_params"), ("Cmd output hits", "cmd_hits")]


@router.post("/api/vuln/a03_command_injection")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a03_command_injection",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
