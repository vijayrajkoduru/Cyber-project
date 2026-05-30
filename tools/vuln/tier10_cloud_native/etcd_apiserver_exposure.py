"""Cloud-native control-plane exposure (docker daemon / etcd / kube-apiserver / kubelet). VL-FORGE Vuln tier10 §10 #157."""
import asyncio, socket, ssl, urllib.error, urllib.request
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
router = APIRouter()
_CTX = ssl._create_unverified_context()
def _open(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False
def _fetch(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnusLab-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            return r.status, r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""
async def gather(ctx):
    host = str(ctx.host); findings = []; ports = []
    if await asyncio.to_thread(_open, host, 2375):
        ports.append("2375/docker")
        st, b = await asyncio.to_thread(_fetch, f"http://{host}:2375/version")
        if st == 200 and ("ApiVersion" in b or "Docker" in b):
            findings.append({"sev":"CRITICAL","cvss":9.8,"name":"Docker daemon API exposed unauthenticated (port 2375)",
                "ev":f"GET :2375/version -> {b[:120]}","rem":"Never expose the Docker TCP API; bind to localhost, require mTLS (2376)."})
    if await asyncio.to_thread(_open, host, 2379):
        ports.append("2379/etcd")
        st, b = await asyncio.to_thread(_fetch, f"http://{host}:2379/version")
        if st == 200 and "etcdserver" in b:
            findings.append({"sev":"HIGH","cvss":8.1,"name":"etcd client API exposed (port 2379)",
                "ev":f"GET :2379/version -> {b[:120]}","rem":"Firewall etcd to control-plane nodes; enable client-cert auth + encryption."})
    if await asyncio.to_thread(_open, host, 6443):
        ports.append("6443/kube-apiserver")
        st, b = await asyncio.to_thread(_fetch, f"https://{host}:6443/version")
        if st == 200 and "gitVersion" in b:
            findings.append({"sev":"HIGH","cvss":8.2,"name":"Kubernetes API server allows anonymous /version (port 6443)",
                "ev":f"Anonymous GET :6443/version -> {b[:120]}","rem":"Disable anonymous-auth on kube-apiserver; restrict 6443 to a private network."})
        elif st in (401, 403):
            findings.append({"sev":"MEDIUM","cvss":5.3,"name":"Kubernetes API server internet-reachable (port 6443)",
                "ev":f"GET :6443/version -> HTTP {st} (auth required, but control plane is publicly exposed).","rem":"Restrict kube-apiserver to a bastion/VPN; do not expose 6443 publicly."})
    if await asyncio.to_thread(_open, host, 10250):
        ports.append("10250/kubelet")
        st, b = await asyncio.to_thread(_fetch, f"https://{host}:10250/pods")
        if st == 200 and ("PodList" in b or '"items"' in b):
            findings.append({"sev":"CRITICAL","cvss":9.8,"name":"Kubelet API anonymous access (port 10250)",
                "ev":"Anonymous GET :10250/pods returned a pod list.","rem":"Set --anonymous-auth=false + --authorization-mode=Webhook on kubelet; firewall 10250."})
    ctx.source("tcp"); ctx.state["probed"] = 1; ctx.state["open_ports"] = ports; ctx.state["cp_findings"] = findings[:8]
def _mk(i):
    def rule(s):
        f = s.get("cp_findings") or []
        if i >= len(f): return None
        x = f[i]
        return {"name": x["name"], "severity": x["sev"], "cvss": x["cvss"], "cwe": "CWE-284", "evidence": x["ev"], "remediation": x["rem"]}
    return rule
def _r_clean(s):
    if not s.get("probed") or (s.get("cp_findings") or []): return None
    return {"name": "No exposed cloud-native control-plane services", "severity": "POSITIVE",
            "evidence": f"Probed docker(2375)/etcd(2379)/kube-apiserver(6443)/kubelet(10250); open: {', '.join(s.get('open_ports') or []) or 'none'}; none unauthenticated."}
FINDING_RULES = [_mk(i) for i in range(8)] + [_r_clean]; INTEL_FIELDS = [("Control-plane ports", "open_ports")]
@router.post("/api/vuln/etcd_apiserver_exposure")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="etcd_apiserver_exposure", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
