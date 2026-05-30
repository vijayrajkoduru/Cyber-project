"""Exposed dependency manifest -> OSV.dev vulnerability lookup. VL-FORGE Vuln tier7 §7 #105."""
import asyncio, json, re, ssl, urllib.request
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import run_scanner
from tools.vuln._vuln_common import http_get
router = APIRouter()
_CTX = ssl._create_unverified_context()
_MANIFESTS = ["/package-lock.json", "/package.json", "/composer.lock", "/requirements.txt", "/Gemfile.lock"]
def _osv(pkgs):
    queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for n, v, e in pkgs if v]
    if not queries: return {}
    try:
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch",
            data=json.dumps({"queries": queries}).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "VulnusLab-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=15, context=_CTX) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return {}
    out = {}
    for q, res in zip(queries, data.get("results", [])):
        ids = [v.get("id", "") for v in (res.get("vulns") or [])][:5]
        if ids: out[q["package"]["name"]] = ids
    return out
def _pkglock(txt):
    out = []
    try: d = json.loads(txt)
    except Exception: return out
    for path, meta in (d.get("packages") or {}).items():
        if path.startswith("node_modules/") and meta.get("version"):
            out.append((path.split("node_modules/")[-1], meta["version"], "npm"))
    if not out:
        for name, meta in (d.get("dependencies") or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out.append((name, meta["version"], "npm"))
    return out
def _pkgjson(txt):
    out = []
    try: d = json.loads(txt)
    except Exception: return out
    for sect in ("dependencies", "devDependencies"):
        for name, ver in (d.get(sect) or {}).items():
            v = re.sub(r"[\^~>=<\s]", "", str(ver))
            if re.match(r"^\d+\.\d+", v): out.append((name, v, "npm"))
    return out
def _req(txt):
    return [(m.group(1), m.group(2), "PyPI") for line in txt.splitlines()
            for m in [re.match(r"^([A-Za-z0-9._-]+)==([0-9][^\s;#]*)", line.strip())] if m]
def _composer(txt):
    out = []
    try: d = json.loads(txt)
    except Exception: return out
    for p in (d.get("packages") or []):
        if p.get("name") and p.get("version"): out.append((p["name"], p["version"].lstrip("v"), "Packagist"))
    return out
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/"); exposed = []; pkgs = []
    for path in _MANIFESTS:
        r = await asyncio.to_thread(http_get, base + path)
        if not r or int(r.get("status") or 0) != 200: continue
        body = r.get("body", "") or ""
        if "text/html" in (r.get("headers", {}).get("content-type", "") or "").lower(): continue
        exposed.append(path)
        if path.endswith("package-lock.json"): pkgs += _pkglock(body)
        elif path.endswith("package.json"): pkgs += _pkgjson(body)
        elif path.endswith("composer.lock"): pkgs += _composer(body)
        elif path.endswith("requirements.txt"): pkgs += _req(body)
    ctx.source("http"); ctx.state["probed"] = 1; ctx.state["exposed"] = exposed
    seen = set(); uniq = []
    for t in pkgs:
        if t not in seen: seen.add(t); uniq.append(t)
    ctx.state["pkg_count"] = len(uniq)
    if uniq:
        vmap = await asyncio.to_thread(_osv, uniq[:100])
        ctx.state["vuln_pkgs"] = [{"name": n, "ids": ids} for n, ids in vmap.items()][:10]
def _mk(i):
    def rule(s):
        v = s.get("vuln_pkgs") or []
        if i >= len(v): return None
        x = v[i]
        return {"name": f"Vulnerable dependency: {x['name']} ({len(x['ids'])} advisory)", "severity": "MEDIUM", "cvss": 6.5, "cwe": "CWE-1395",
                "evidence": f"OSV.dev: {x['name']} -> {', '.join(x['ids'])}. From exposed manifest {', '.join(s.get('exposed') or [])}.",
                "remediation": "Upgrade the dependency to a fixed version; remove the lockfile/manifest from the web root."}
    return rule
def _r_exposed(s):
    ex = s.get("exposed") or []
    if not ex or (s.get("vuln_pkgs") or []): return None
    return {"name": f"Dependency manifest exposed in web root: {', '.join(ex)}", "severity": "LOW", "cwe": "CWE-200",
            "evidence": f"Reachable: {', '.join(ex)} ({s.get('pkg_count',0)} pkgs); no OSV-known-vulnerable deps, but the manifest aids targeted attacks.",
            "remediation": "Remove dependency manifests/lockfiles from the public web root."}
def _r_clean(s):
    if not s.get("probed") or (s.get("exposed") or []): return None
    return {"name": "No dependency manifests exposed", "severity": "POSITIVE", "evidence": "No package-lock.json / composer.lock / requirements.txt / Gemfile.lock reachable in the web root."}
FINDING_RULES = [_mk(i) for i in range(10)] + [_r_exposed, _r_clean]; INTEL_FIELDS = [("Exposed manifests", "exposed")]
@router.post("/api/vuln/osv_scanner")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="osv_scanner", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
