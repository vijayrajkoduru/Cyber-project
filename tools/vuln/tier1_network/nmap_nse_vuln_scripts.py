"""Real nmap NSE vuln-script scan (curated fast scripts) - primary Kali engine. VL-FORGE Vuln §1 #2/#4/#5/#8."""
import asyncio, re, shutil
import xml.etree.ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify
router = APIRouter()
_PORTS = "21,22,23,25,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017"
_SCRIPTS = ("ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-ccs-injection,smb-vuln-ms17-010,smb-vuln-ms08-067,"
            "smb-vuln-cve-2017-7494,rdp-vuln-ms12-020,http-shellshock,http-vuln-cve2017-5638,ftp-vsftpd-backdoor,ftp-proftpd-backdoor")
# The exact set of NSE vuln-script ids we run. Only a "VULNERABLE" verdict from
# one of THESE ids is graded - a stray 'VULNERABLE' word from any other script
# output is ignored.
_KNOWN_VULN_IDS = frozenset(_SCRIPTS.split(","))
# nmap's vulns library prints a structured verdict line. The ONLY state that is
# a confirmed positive is exactly "VULNERABLE". We must NOT fire on
# "NOT VULNERABLE", "LIKELY VULNERABLE", or "VULNERABLE (DoS)" maybe-states,
# nor on the literate "State: " label appearing without that exact verdict.
_VERDICT = re.compile(r"\bState:\s*VULNERABLE\b", re.I)
_NEGATED = re.compile(r"\bState:\s*(?:NOT\s+VULNERABLE|LIKELY\s+VULNERABLE|UNKNOWN)\b", re.I)
_T = 50; _MAX = 30
async def _run(host):
    if not shutil.which("nmap"):
        return None, "nmap binary not present in container"
    cmd = ["nmap","-Pn","-T4","--open","-p",_PORTS,"--script",_SCRIPTS,"--script-timeout","25s","--host-timeout","45s","-oX","-",host]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except Exception as e:
        return None, f"nmap spawn failed: {e}"
    partial = False
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=_T)
    except asyncio.TimeoutError:
        partial = True
        try: proc.kill()
        except Exception: pass
        try: out, _ = await asyncio.wait_for(proc.communicate(), timeout=4)
        except Exception: out = b""
    return {"xml": (out or b"").decode("utf-8","replace"), "partial": partial}, None
def _parse(xml):
    vulns, ports = [], []
    try: root = ET.fromstring(xml)
    except Exception: return vulns, ports
    for host in root.iter("host"):
        for port in host.iter("port"):
            pid = port.get("portid",""); st = port.find("state")
            if st is not None and st.get("state") == "open":
                svc = port.find("service"); ports.append(f"{pid}/{svc.get('name','?') if svc is not None else '?'}")
            for scr in port.iter("script"):
                o = scr.get("output") or ""
                sid = scr.get("id", "")
                # ZERO-FP: grade ONLY when (a) the script is one of OUR known
                # vuln-script ids, and (b) its structured "State: VULNERABLE"
                # verdict line is present, and (c) it is not a NOT/LIKELY/
                # UNKNOWN state. The bare word 'VULNERABLE' appearing anywhere
                # in output (e.g. in a reference URL, a "not vulnerable"
                # sentence, or a maybe-state) is NOT a confirmed verdict and
                # must not produce a HIGH finding.
                if sid in _KNOWN_VULN_IDS and _VERDICT.search(o) and not _NEGATED.search(o):
                    vulns.append({"port": pid, "id": sid, "output": " ".join(o.split())[:300]})
    return vulns, ports
async def gather(ctx):
    res, err = await _run(str(ctx.host))
    if err:
        ctx.state["skipped_reason"] = err; return
    if not res["partial"] and not res["xml"].strip():
        ctx.state["skipped_reason"] = "nmap produced no output (host unreachable or scan blocked)"; return
    vulns, ports = _parse(res["xml"])
    ctx.source("nmap"); ctx.state["tested"] = 1; ctx.state["partial"] = res["partial"]
    ctx.state["open_ports"] = ports; ctx.state["vulns"] = vulns[:_MAX]
def _mk(i):
    def rule(s):
        v = s.get("vulns") or []
        if i >= len(v): return None
        x = v[i]
        return {"name": f"nmap NSE confirmed vulnerability: {x['id']} (port {x['port']})", "severity": "HIGH", "cvss": 8.1, "cwe": "CWE-1395",
                "evidence": f"nmap '{x['id']}' reported VULNERABLE on port {x['port']}: {x['output']}",
                "remediation": "Patch the affected service immediately - confirmed exploitable by the NSE check."}
    return rule
def _r_clean(s):
    if (s.get("tested") or 0) < 1 or (s.get("vulns") or []): return None
    op = s.get("open_ports") or []; note = " (partial - hit time cap)" if s.get("partial") else ""
    return {"name": "No NSE-detectable network vulnerabilities found", "severity": "POSITIVE",
            "evidence": f"nmap NSE vuln scripts on {len(op)} open port(s) [{', '.join(op) or 'none'}] found nothing exploitable{note}."}
FINDING_RULES = [_mk(i) for i in range(_MAX)] + [_r_clean]; INTEL_FIELDS = [("Open ports","open_ports")]
@router.post("/api/vuln/nmap_nse_vuln_scripts")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="nmap_nse_vuln_scripts", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
