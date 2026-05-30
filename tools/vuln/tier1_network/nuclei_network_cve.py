"""Real nuclei scan (cve/network/exposure templates) - primary Kali engine. VL-FORGE Vuln §1 #3 + §2."""
import asyncio, json, shutil
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import run_scanner
router = APIRouter()
_TAGS = "cve,network,exposure,default-login,misconfiguration"; _SEV = "critical,high,medium"; _T = 50; _MAX = 40
_SEV_MAP = {"critical":("CRITICAL",9.5),"high":("HIGH",8.1),"medium":("MEDIUM",5.5),"low":("LOW",3.1),"info":("INFO",0.0)}
async def _run(target):
    if not shutil.which("nuclei"):
        return None, "nuclei binary not present in container"
    cmd = ["nuclei","-u",target,"-jsonl","-silent","-duc","-no-interactsh","-timeout","5","-retries","1","-rate-limit","150","-c","25","-severity",_SEV,"-tags",_TAGS]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except Exception as e:
        return None, f"nuclei spawn failed: {e}"
    partial = False
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=_T)
    except asyncio.TimeoutError:
        partial = True
        try: proc.kill()
        except Exception: pass
        try: out, err = await asyncio.wait_for(proc.communicate(), timeout=4)
        except Exception: out, err = b"", b""
    rows = []
    for ln in (out or b"").decode("utf-8","replace").splitlines():
        ln = ln.strip()
        if ln.startswith("{"):
            try: rows.append(json.loads(ln))
            except Exception: pass
    if not rows and not partial and proc.returncode not in (0, None):
        snip = " ".join((err or b"").decode("utf-8","replace").split())[:160]
        if "no templates" in snip.lower() or "could not find" in snip.lower():
            return None, "nuclei templates not installed (run: nuclei -update-templates)"
        return None, f"nuclei exit {proc.returncode}: {snip or 'no output'}"
    return {"rows": rows, "partial": partial}, None
async def gather(ctx):
    target = web_url(str(ctx.host)).rstrip("/")
    res, err = await _run(target)
    if err:
        ctx.state["skipped_reason"] = err; return
    ctx.source("nuclei"); ctx.state["tested"] = 1; ctx.state["partial"] = res["partial"]
    findings, info_n = [], 0
    for r in res["rows"]:
        info = r.get("info", {}) or {}; sev = (info.get("severity") or "info").lower()
        if sev not in ("critical","high","medium","low"):
            info_n += 1; continue
        cls = info.get("classification", {}) or {}; cves = [c.upper() for c in (cls.get("cve-id") or [])]
        findings.append({"id": r.get("template-id",""), "name": info.get("name") or r.get("template-id","finding"),
                         "severity": sev, "matched": r.get("matched-at") or r.get("host", target),
                         "cve": cves, "cvss": cls.get("cvss-score"),
                         "ref": (info.get("reference") or [None])[0] if info.get("reference") else None})
    ctx.state["info_count"] = info_n; ctx.state["nuclei_findings"] = findings[:_MAX]
def _mk(i):
    def rule(s):
        items = s.get("nuclei_findings") or []
        if i >= len(items): return None
        f = items[i]; sev, base = _SEV_MAP.get(f["severity"], ("INFO", 0.0)); cves = ", ".join(f["cve"]) if f["cve"] else ""
        return {"name": f["name"] + (f" [{cves}]" if cves else ""), "severity": sev,
                "cvss": float(f["cvss"]) if f.get("cvss") else base, "cve": cves or "N/A",
                "cwe": "CWE-1395" if cves else "CWE-16",
                "evidence": f"nuclei template '{f['id']}' matched at {f['matched']}." + (f" CVE: {cves}." if cves else ""),
                "remediation": f.get("ref") or "Patch/reconfigure the affected component per the matched template advisory."}
    return rule
def _r_clean(s):
    if (s.get("tested") or 0) < 1 or (s.get("nuclei_findings") or []): return None
    note = " (partial - hit time cap)" if s.get("partial") else ""
    return {"name": "nuclei found no critical/high/medium vulnerabilities", "severity": "POSITIVE",
            "evidence": f"nuclei (cve/network/exposure/default-login) matched nothing actionable{note}; {s.get('info_count',0)} info templates noted."}
FINDING_RULES = [_mk(i) for i in range(_MAX)] + [_r_clean]; INTEL_FIELDS = []
@router.post("/api/vuln/nuclei_network_cve")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="nuclei_network_cve", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
