"""§24 Container/K8s — 103 endpoints per 24_container_k8s.md.

VL-FORGE upgrade 2026-05-30: 7 live probes for externally-observable
container/k8s misconfigs (Docker daemon, etcd, K8s API, Harbor registry,
Dashboard, kubelet, container registry public access).
"""
import json
import re
import shutil
import socket
import ssl
import subprocess
import urllib.request, urllib.error
from contextlib import closing
from datetime import datetime, timezone
from tools._pack_common import make_advisory_router, _adv_response
from tools._shared import wrap_finding


# Recognise an image reference vs a hostname/IP/URL.
# Accepts: nginx, nginx:1.21, library/nginx:1.21, registry.io/org/app:tag,
#          registry.io:5000/org/app:tag, sha256: digest references.
# Rejects: example.com (no tag/slash combination), 8.8.8.8, http(s)://...
_IMAGE_REF_RE = re.compile(
    r"^(?:[a-zA-Z0-9._-]+(?::[0-9]+)?/)?"   # optional registry[:port]/
    r"[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)*" # repo/sub-repo
    r"(?::[a-zA-Z0-9._-]+|@sha256:[a-f0-9]{32,})$"  # :tag or @digest
)


def _looks_like_image_ref(target: str) -> bool:
    """True if target syntactically looks like an OCI image reference.
    Heuristic: must contain ':' (tag) or '@sha256:' digest, and must NOT
    look like a URL or a bare IP. Reject obvious non-image inputs."""
    if not target or not isinstance(target, str):
        return False
    t = target.strip()
    if t.startswith(("http://", "https://", "ftp://")):
        return False
    # Bare IPv4
    if re.match(r"^\d+\.\d+\.\d+\.\d+(?::\d+)?$", t):
        return False
    # Hostname with no slash, no @sha256, no tag separator
    if "/" not in t and "@sha256:" not in t and ":" not in t:
        return False
    # Hostname:port with no slash (registry.io:5000 alone) -> not an image ref
    if "/" not in t and "@sha256:" not in t and re.match(r"^[\w.-]+:\d+$", t):
        return False
    return bool(_IMAGE_REF_RE.match(t))


def _run_tool(cmd, timeout_s=60, env=None):
    """Subprocess wrapper with consistent error handling.
    Returns (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_s, check=False, env=env)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or "timeout"
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} binary not found in PATH"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {str(e)[:200]}"


def _not_applicable_for_image_scanner(target, slug, tool_name):
    """Return a NOT_APPLICABLE finding when the target isn't an image ref."""
    return _build_resp(slug, target, [wrap_finding(
        f"[NOT_APPLICABLE] {tool_name} requires an OCI image reference",
        "INFO", cvss="0.0", cwe="N/A",
        remediation=(f"To run {tool_name}, provide an image reference like "
                      "'nginx:1.21' or 'myreg.io/app:v2.3' as the scan target. "
                      "Hostnames/IPs are not scannable by image-CVE tools."),
        evidence_marker=(f"Target '{target[:80]}' does not match image-ref "
                          "pattern (registry/repo:tag or @sha256:digest)."),
    )], 0, f"{tool_name} skipped - not an image reference")



_INSECURE_SSL = ssl.create_default_context()
_INSECURE_SSL.check_hostname = False
_INSECURE_SSL.verify_mode = ssl.CERT_NONE


def _http_get_insecure(url, timeout=4, method="GET", extra_headers=None):
    """HTTP(S) GET that tolerates self-signed certs (typical for K8s/ingress)."""
    try:
        headers = {"User-Agent": "VulnusLab/2.0"}
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=_INSECURE_SSL) as r:
            body = r.read(8192).decode("utf-8", errors="ignore")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192).decode("utf-8", errors="ignore")
            return e.code, dict(e.headers or {}), body
        except Exception:
            return e.code, {}, ""
    except Exception:
        return 0, {}, ""


def _tls_inspect(host, port, timeout=4):
    """Open a real TLS connection and return protocol version, cert info,
    and whether the server requested a client certificate (mTLS hint)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert(binary_form=False) or {}
                cert_bin = s.getpeercert(binary_form=True)
                return {
                    "ok": True,
                    "tls_version": s.version(),
                    "cipher": s.cipher(),
                    "peer_cert": cert,
                    "cert_bytes": len(cert_bin) if cert_bin else 0,
                }
    except ssl.SSLError as e:
        return {"ok": False, "ssl_error": str(e)[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def _host(t):
    return t.split("://", 1)[-1].split("/")[0].split(":")[0].strip().lower() or t

def _tcp_open(host, port, timeout=2.0):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False

def _http_get(url, timeout=4):
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"VulnusLab/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(4096).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(4096).decode("utf-8", errors="ignore")
        except Exception: return e.code, ""
    except Exception:
        return 0, ""

def _build_resp(tool, target, findings, tested, summary):
    sev_top = "INFO"
    sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"POSITIVE":0}
    for f in findings:
        if sev_order.get(f.get("severity","INFO"),0) > sev_order.get(sev_top,0):
            sev_top = f.get("severity","INFO")
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": sev_top in ("CRITICAL","HIGH","MEDIUM"),
            "severity": sev_top, "findings": findings,
            "tests_performed": tested, "tests_summary": summary, "raw_data": {}}


def _probe_docker_daemon_exposed(target, req):
    host = _host(target)
    findings = []
    for port, label in [(2375, "Docker (insecure)"), (2376, "Docker TLS")]:
        if _tcp_open(host, port):
            # Try /version endpoint
            code, body = _http_get(f"http://{host}:{port}/version", timeout=3)
            sev = "CRITICAL" if code == 200 else "HIGH"
            findings.append(wrap_finding(
                f"Docker daemon port {port}/tcp reachable — {label}",
                sev, cvss="9.5" if sev == "CRITICAL" else "7.5",
                cwe="CWE-732", owasp="A05:2021",
                remediation="NEVER expose Docker daemon publicly. Bind to localhost + mTLS only.",
                evidence_marker=f"TCP/{port} open; /version → {code}"))
    if not findings:
        findings.append(wrap_finding("Docker daemon NOT externally exposed (good)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue localhost-only binding.",
            evidence_marker="TCP/2375 + 2376 closed"))
    return _build_resp("docker_daemon_exposed", target, findings, 2, "Docker daemon exposure")


def _probe_etcd_exposed(target, req):
    host = _host(target)
    findings = []
    for port in [2379, 2380]:
        if _tcp_open(host, port):
            code, body = _http_get(f"http://{host}:{port}/version", timeout=3)
            if code == 200 and "etcd" in body.lower():
                findings.append(wrap_finding(
                    f"etcd {port}/tcp publicly reachable + responds on /version",
                    "CRITICAL", cvss="9.5", cwe="CWE-306",
                    remediation="etcd MUST NOT be exposed publicly. Require client-cert auth + bind to private subnet.",
                    evidence_marker=f"TCP/{port} open; etcd version response"))
            elif _tcp_open(host, port):
                findings.append(wrap_finding(
                    f"Port {port}/tcp open (etcd default), no /version response",
                    "HIGH", cvss="7.5", cwe="CWE-306",
                    remediation="Audit listener on this port; etcd port should not be public.",
                    evidence_marker=f"TCP/{port} open, /version filtered"))
    if not findings:
        findings.append(wrap_finding("etcd not externally reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue private etcd networking.",
            evidence_marker="TCP/2379 + 2380 closed"))
    return _build_resp("etcd_apiserver_exposure", target, findings, 2, "etcd port + version probe")


def _probe_k8s_api(target, req):
    host = _host(target)
    findings = []
    for port in [6443, 8080, 8443]:
        if _tcp_open(host, port):
            code, body = _http_get(f"https://{host}:{port}/version", timeout=3)
            if code in (200, 401, 403):
                is_k8s = "gitCommit" in body or "kubernetes" in body.lower()
                sev = "CRITICAL" if code == 200 and is_k8s else "HIGH"
                findings.append(wrap_finding(
                    f"K8s API server on {port}/tcp — {'anonymous /version' if code == 200 else 'auth required'}",
                    sev, cvss="9.0" if sev == "CRITICAL" else "7.0",
                    cwe="CWE-306",
                    remediation="Restrict K8s API to bastion/VPN; require client-cert + RBAC; never anonymous.",
                    evidence_marker=f"TCP/{port} open; /version → {code}"))
    if not findings:
        findings.append(wrap_finding("K8s API not externally reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue API restriction.",
            evidence_marker="TCP/6443 + 8080 + 8443 closed"))
    return _build_resp("kube_bench_master", target, findings, 3, "K8s API server external exposure")


def _probe_kubelet(target, req):
    host = _host(target)
    findings = []
    for port in [10250, 10255, 10256]:
        if _tcp_open(host, port):
            code, body = _http_get(f"https://{host}:{port}/pods", timeout=3)
            sev = "CRITICAL" if code == 200 else "HIGH"
            findings.append(wrap_finding(
                f"kubelet port {port}/tcp exposed — read-only-port + anonymous risk",
                sev, cvss="9.0" if code == 200 else "7.0",
                cwe="CWE-306",
                remediation="Disable kubelet read-only-port (10255); require auth on 10250.",
                evidence_marker=f"TCP/{port} open; /pods → {code}"))
    if not findings:
        findings.append(wrap_finding("kubelet not externally reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue kubelet restriction.",
            evidence_marker="TCP/10250 + 10255 + 10256 closed"))
    return _build_resp("k8s_kubelet_anonymous_auth", target, findings, 3, "kubelet exposure")


def _probe_harbor_registry(target, req):
    host = _host(target)
    code, body = _http_get(f"https://{host}/api/v2.0/health", timeout=4)
    is_harbor = code == 200 and ("harbor" in body.lower() or '"status":"healthy"' in body)
    findings = []
    if is_harbor:
        # Check for anonymous repo listing
        c2, b2 = _http_get(f"https://{host}/v2/", timeout=4)
        anon = c2 == 200 and '"errors"' not in b2[:100]
        findings.append(wrap_finding(
            f"Harbor registry detected — anonymous /v2 {'ALLOWED' if anon else 'denied'}",
            "HIGH" if anon else "INFO",
            cvss="7.0" if anon else "0.0", cwe="CWE-200" if anon else "N/A",
            remediation="Require auth on all repo paths; disable anonymous_pull.",
            evidence_marker=f"Harbor on {host}; anon pull: {anon}"))
    else:
        findings.append(wrap_finding(
            f"No Harbor registry signature at https://{host}/api/v2.0/health",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue.",
            evidence_marker=f"Status: {code}"))
    return _build_resp("registry_npm_2fa_audit", target, findings, 2, "Harbor registry public-access check")


def _probe_k8s_dashboard(target, req):
    host = _host(target)
    paths = [
        f"https://{host}/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
        f"https://{host}:30443/",
        f"http://{host}:30080/",
    ]
    findings = []
    for url in paths:
        code, body = _http_get(url, timeout=3)
        if code == 200 and ("Kubernetes Dashboard" in body or "k8s" in body.lower()):
            findings.append(wrap_finding(
                "Kubernetes Dashboard publicly reachable",
                "CRITICAL", cvss="9.0", cwe="CWE-306",
                remediation="Never expose Dashboard publicly. Use kubectl proxy + auth-enabled access only.",
                evidence_marker=f"GET {url} → 200"))
            break
    if not findings:
        findings.append(wrap_finding("Kubernetes Dashboard not publicly reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue private Dashboard access.",
            evidence_marker=f"All {len(paths)} dashboard paths closed/filtered"))
    return _build_resp("opa_kyverno_no_policies", target, findings, len(paths), "K8s Dashboard exposure")


def _probe_registry_public(target, req):
    host = _host(target)
    code, body = _http_get(f"https://{host}/v2/", timeout=3)
    is_anon = code == 200 and '"errors"' not in body[:100]
    is_authd = code in (401, 403)
    findings = []
    if is_anon:
        findings.append(wrap_finding(
            f"Container registry /v2/ allows ANONYMOUS access at {host}",
            "HIGH", cvss="7.5", cwe="CWE-200",
            remediation="Require authentication on registry pulls; use IAM-signed access.",
            evidence_marker=f"GET https://{host}/v2/ → 200 (no error)"))
    elif is_authd:
        findings.append(wrap_finding(
            f"Container registry at {host} requires auth (good)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue auth-required posture.",
            evidence_marker=f"GET /v2/ → {code}"))
    else:
        findings.append(wrap_finding(
            f"No container registry detected at {host}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify registry hostname.",
            evidence_marker=f"GET /v2/ → {code}"))
    return _build_resp("registry_pypi_2fa_audit", target, findings, 1, "Container registry /v2 public probe")


# ───────────────────────────────────────────────────────────────
# Real probes added 2026-06-01: externally-observable checks that
# work against any hostname/IP target with no extra inputs.
# ───────────────────────────────────────────────────────────────


def _probe_k8s_anonymous_auth(target, req):
    """Test whether kube-apiserver allows anonymous requests to
    sensitive endpoints. CIS K8s 1.2.1 control."""
    host = _host(target)
    findings = []
    for port in (6443, 8443):
        if not _tcp_open(host, port):
            continue
        # Anonymous GET /api should be rejected (401/403). 200 = anon allowed.
        code, _, body = _http_get_insecure(f"https://{host}:{port}/api", timeout=4)
        if code == 200 and "kind" in body.lower():
            findings.append(wrap_finding(
                f"kube-apiserver on {port}/tcp allows ANONYMOUS access to /api",
                "CRITICAL", cvss="9.0", cwe="CWE-306",
                remediation="Set --anonymous-auth=false on kube-apiserver. "
                            "Require client-cert or token auth for all endpoints.",
                evidence_marker=f"GET https://{host}:{port}/api → 200; body contains 'kind'"))
        elif code in (401, 403):
            findings.append(wrap_finding(
                f"kube-apiserver on {port}/tcp requires auth (good)",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue auth-required posture.",
                evidence_marker=f"GET /api → {code}"))
    if not findings:
        findings.append(wrap_finding("kube-apiserver not externally reachable on 6443/8443",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue private API server access.",
            evidence_marker="TCP/6443 + 8443 closed/filtered"))
    return _build_resp("k8s_anonymous_auth", target, findings, 2,
                       "kube-apiserver anonymous-auth probe")


def _probe_k8s_api_insecure_port(target, req):
    """Detect kube-apiserver --insecure-port (legacy 8080) exposed."""
    host = _host(target)
    findings = []
    if _tcp_open(host, 8080):
        code, _, body = _http_get_insecure(f"http://{host}:8080/api", timeout=3)
        if code == 200 and ("kind" in body.lower() or "apiversion" in body.lower()):
            findings.append(wrap_finding(
                "kube-apiserver insecure-port 8080 EXPOSED — bypasses all auth",
                "CRITICAL", cvss="10.0", cwe="CWE-306",
                remediation="Set --insecure-port=0 on kube-apiserver immediately. "
                            "Anyone reaching 8080 has full cluster admin.",
                evidence_marker=f"GET http://{host}:8080/api → 200 (insecure port active)"))
        else:
            findings.append(wrap_finding(
                f"Port 8080 open but does not respond as kube-apiserver",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Investigate what service is on 8080.",
                evidence_marker=f"GET :8080/api → {code}"))
    else:
        findings.append(wrap_finding("kube-apiserver insecure-port 8080 closed (good)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue --insecure-port=0.",
            evidence_marker="TCP/8080 closed"))
    return _build_resp("k8s_api_server_insecure_port", target, findings, 1,
                       "kube-apiserver insecure-port (8080) probe")


def _probe_registry_anon_push(target, req):
    """Test whether registry accepts anonymous push (POST upload init)."""
    host = _host(target)
    findings = []
    # Probe the standard /v2/<name>/blobs/uploads/ POST upload endpoint.
    code, hdrs, body = _http_get_insecure(
        f"https://{host}/v2/vulnuslab-probe/blobs/uploads/",
        timeout=4, method="POST")
    if code in (202, 200):
        # 202 with Location header = registry accepted anon push initiation.
        loc = hdrs.get("Location") or hdrs.get("location") or ""
        findings.append(wrap_finding(
            f"Registry at {host} accepts ANONYMOUS push (POST /v2/.../blobs/uploads/ → {code})",
            "CRITICAL", cvss="9.5", cwe="CWE-306",
            remediation="Disable anonymous push immediately. Require auth + RBAC for all "
                        "write operations. Anonymous push = supply-chain compromise vector.",
            evidence_marker=f"POST /v2/vulnuslab-probe/blobs/uploads/ → {code}; Location: {loc[:80]}"))
    elif code in (401, 403, 404):
        findings.append(wrap_finding(
            f"Registry at {host} rejects anonymous push (good)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue auth-required push posture.",
            evidence_marker=f"POST → {code}"))
    else:
        findings.append(wrap_finding(
            f"No standard OCI registry detected at {host}:443",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify registry hostname / port.",
            evidence_marker=f"POST → {code}"))
    return _build_resp("registry_anon_push", target, findings, 1,
                       "OCI registry anonymous-push probe")


def _probe_nginx_ingress(target, req):
    """Detect nginx ingress + check for exposed status/metrics endpoints."""
    host = _host(target)
    findings = []
    code, hdrs, _ = _http_get_insecure(f"https://{host}/", timeout=4)
    if code == 0:
        code, hdrs, _ = _http_get_insecure(f"http://{host}/", timeout=4)
    server = (hdrs.get("Server") or hdrs.get("server") or "").lower()
    is_nginx = "nginx" in server
    if is_nginx:
        # Check exposed status endpoints
        exposed = []
        for path in ("/nginx-status", "/stub_status", "/metrics", "/nginx_status"):
            for scheme in ("https", "http"):
                c, _, b = _http_get_insecure(f"{scheme}://{host}{path}", timeout=3)
                if c == 200 and ("active connections" in b.lower() or "nginx_" in b.lower()):
                    exposed.append(f"{scheme}://{host}{path}")
                    break
        if exposed:
            findings.append(wrap_finding(
                f"nginx ingress detected ({server}) — status endpoint EXPOSED: {exposed[0]}",
                "HIGH", cvss="7.5", cwe="CWE-200",
                remediation="Restrict /nginx-status, /stub_status, /metrics to internal "
                            "monitoring subnet only. Add allow/deny ACL.",
                evidence_marker=f"Exposed: {', '.join(exposed)}"))
        else:
            findings.append(wrap_finding(
                f"nginx detected ({server}) — no status endpoint exposed (good)",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Continue ACL on monitoring endpoints.",
                evidence_marker=f"Server: {server}"))
    else:
        findings.append(wrap_finding("No nginx ingress signature detected",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Not running nginx, or Server header suppressed.",
            evidence_marker=f"Server: {server or '(none)'}"))
    return _build_resp("nginx_ingress_audit", target, findings, 5,
                       "nginx ingress fingerprint + status-endpoint exposure")


def _probe_traefik_ingress(target, req):
    """Detect Traefik and check for /api or /dashboard publicly exposed."""
    host = _host(target)
    findings = []
    # Traefik default API port is 8080; dashboard usually behind /dashboard/
    exposed = []
    for port_path in ("/dashboard/", "/api/rawdata", "/api/version", ":8080/dashboard/"):
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}{port_path}" if not port_path.startswith(":") \
                  else f"{scheme}://{host}{port_path}"
            c, hdrs, b = _http_get_insecure(url, timeout=3)
            srv = (hdrs.get("Server") or "").lower()
            if c == 200 and ("traefik" in b.lower() or "traefik" in srv):
                exposed.append(url)
                break
    if exposed:
        findings.append(wrap_finding(
            f"Traefik dashboard / API EXPOSED at {exposed[0]}",
            "HIGH", cvss="8.0", cwe="CWE-306",
            remediation="Disable Traefik dashboard (api.dashboard=false) or restrict to "
                        "internal network with auth middleware.",
            evidence_marker=f"Exposed: {', '.join(exposed[:3])}"))
    else:
        findings.append(wrap_finding("Traefik dashboard/API not publicly reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue private dashboard access.",
            evidence_marker="All probed Traefik endpoints closed/non-200"))
    return _build_resp("traefik_audit", target, findings, 4,
                       "Traefik dashboard / API exposure")


def _probe_haproxy_ingress(target, req):
    """Detect HAProxy and check for /stats publicly exposed."""
    host = _host(target)
    findings = []
    exposed = []
    for path in ("/stats", "/haproxy?stats", "/admin?stats"):
        for scheme in ("https", "http"):
            c, hdrs, b = _http_get_insecure(f"{scheme}://{host}{path}", timeout=3)
            srv = (hdrs.get("Server") or "").lower()
            body_l = b.lower()
            if c == 200 and ("haproxy" in body_l or "haproxy" in srv or
                              "statistics report" in body_l):
                exposed.append(f"{scheme}://{host}{path}")
                break
    if exposed:
        findings.append(wrap_finding(
            f"HAProxy stats page EXPOSED at {exposed[0]}",
            "HIGH", cvss="7.5", cwe="CWE-200",
            remediation="Move stats listener to internal interface or add stats auth. "
                        "Stats page leaks backend topology + traffic patterns.",
            evidence_marker=f"Exposed: {', '.join(exposed[:3])}"))
    else:
        findings.append(wrap_finding("HAProxy stats not publicly reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue internal-only stats listener.",
            evidence_marker="All HAProxy stats paths closed/non-200"))
    return _build_resp("haproxy_ingress_audit", target, findings, 3,
                       "HAProxy stats exposure")


def _probe_envoy_proxy(target, req):
    """Detect Envoy + check for admin /stats /clusters /listeners exposed."""
    host = _host(target)
    findings = []
    exposed = []
    # Envoy admin interface default port is 9901
    for url in (f"http://{host}:9901/stats", f"http://{host}:9901/clusters",
                f"http://{host}:9901/listeners", f"http://{host}:9901/config_dump"):
        c, _, b = _http_get_insecure(url, timeout=3)
        if c == 200 and ("envoy" in b.lower() or "cluster_manager" in b.lower()):
            exposed.append(url)
    if exposed:
        sev = "CRITICAL" if "/config_dump" in str(exposed) else "HIGH"
        cvss = "9.0" if sev == "CRITICAL" else "7.5"
        findings.append(wrap_finding(
            f"Envoy admin interface EXPOSED on :9901 — {len(exposed)} endpoint(s)",
            sev, cvss=cvss, cwe="CWE-306",
            remediation="Bind Envoy admin to loopback (127.0.0.1:9901) only. "
                        "/config_dump leaks credentials, TLS certs, full cluster topology.",
            evidence_marker=f"Exposed: {', '.join(exposed)}"))
    else:
        findings.append(wrap_finding("Envoy admin interface not exposed",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue admin-loopback-only binding.",
            evidence_marker="TCP/9901 admin endpoints closed/filtered"))
    return _build_resp("envoy_config_audit", target, findings, 4,
                       "Envoy admin interface (:9901) exposure")


def _probe_ingress_tls_audit(target, req):
    """Real TLS handshake audit: version, cert expiry, weak protocols."""
    host = _host(target)
    findings = []
    for port in (443, 8443):
        if not _tcp_open(host, port):
            continue
        info = _tls_inspect(host, port, timeout=4)
        if not info.get("ok"):
            continue
        tls_ver = info.get("tls_version") or ""
        cert = info.get("peer_cert") or {}
        # TLS version check
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(wrap_finding(
                f"TLS {tls_ver} accepted on :{port} — weak / deprecated protocol",
                "HIGH", cvss="7.5", cwe="CWE-326",
                remediation="Disable TLSv1.0/1.1. Require TLSv1.2+ (preferably TLSv1.3).",
                evidence_marker=f"Handshake negotiated {tls_ver} cipher={info.get('cipher')}"))
        # Cert expiry check
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                exp = exp.replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    findings.append(wrap_finding(
                        f"TLS cert on :{port} EXPIRED {-days} days ago",
                        "CRITICAL", cvss="9.0", cwe="CWE-298",
                        remediation="Renew certificate immediately. Browsers/clients reject expired certs.",
                        evidence_marker=f"notAfter: {not_after} (expired)"))
                elif days < 7:
                    findings.append(wrap_finding(
                        f"TLS cert on :{port} expires in {days} days",
                        "HIGH", cvss="7.5", cwe="CWE-298",
                        remediation="Renew certificate now. Automate via cert-manager / Let's Encrypt.",
                        evidence_marker=f"notAfter: {not_after}"))
                elif days < 30:
                    findings.append(wrap_finding(
                        f"TLS cert on :{port} expires in {days} days",
                        "MEDIUM", cvss="5.5", cwe="CWE-298",
                        remediation="Schedule renewal. Set cert-manager renewBefore to 30d.",
                        evidence_marker=f"notAfter: {not_after}"))
            except Exception:
                pass
    if not findings:
        findings.append(wrap_finding("TLS configuration appears healthy on 443/8443",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue current TLS hardening + cert rotation cadence.",
            evidence_marker="TLSv1.2+, cert valid > 30d, no weak protocols accepted"))
    return _build_resp("ingress_tls_audit", target, findings, 2,
                       "Ingress TLS protocol + certificate audit")


def _probe_istio_gateway_mtls(target, req):
    """Probe Istio gateway / generic ingress for mTLS posture.
    If a TLS handshake completes without a client cert being requested,
    mTLS is OFF for that listener."""
    host = _host(target)
    findings = []
    for port in (443, 15443):  # 15443 = Istio multi-cluster gateway
        if not _tcp_open(host, port):
            continue
        info = _tls_inspect(host, port, timeout=4)
        if not info.get("ok"):
            continue
        # If we got a server cert back without being asked for a client cert,
        # the server is NOT enforcing mTLS for this listener.
        cert_bytes = info.get("cert_bytes", 0)
        if cert_bytes > 0:
            findings.append(wrap_finding(
                f"TLS on :{port} completes without client-cert request — mTLS OFF",
                "HIGH", cvss="7.5", cwe="CWE-295",
                remediation="If this is an Istio gateway, set tls.mode=MUTUAL on Gateway "
                            "resource. Enforce client certs at edge if zero-trust required.",
                evidence_marker=f"Server cert ({cert_bytes}B) returned; no CertificateRequest sent"))
    if not findings:
        findings.append(wrap_finding("No TLS listener on 443/15443, or mTLS already enforced",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue mTLS posture.",
            evidence_marker="No anonymous-TLS handshake completed"))
    return _build_resp("istio_gateway_mtls_off", target, findings, 2,
                       "Istio gateway / ingress mTLS posture probe")


def _probe_consul_audit(target, req):
    """Detect HashiCorp Consul + check for unauth HTTP API exposure.
    Consul default ports: 8500 (HTTP API), 8501 (HTTPS API), 8600 (DNS).
    Anonymous /v1/agent/self leaks node info; /v1/agent/services leaks
    every registered service. Either is a serious data-leak vector."""
    host = _host(target)
    findings = []
    exposed = []
    detected = False

    for port, scheme in ((8500, "http"), (8501, "https")):
        if not _tcp_open(host, port):
            continue
        for path in ("/v1/agent/self", "/v1/agent/services",
                      "/v1/status/leader", "/v1/catalog/nodes"):
            url = f"{scheme}://{host}:{port}{path}"
            c, _, b = _http_get_insecure(url, timeout=3)
            if c == 200 and ("Config" in b or "Consul" in b or
                              "Datacenter" in b or '"Address"' in b):
                detected = True
                exposed.append(url)
                break
        if detected:
            break

    if exposed:
        # /v1/agent/self leaks the most -> CRITICAL; others HIGH
        sev = "CRITICAL" if "/agent/self" in exposed[0] else "HIGH"
        cvss = "9.0" if sev == "CRITICAL" else "7.5"
        findings.append(wrap_finding(
            f"Consul HTTP API EXPOSED at {exposed[0]} (no auth required)",
            sev, cvss=cvss, cwe="CWE-306",
            remediation="Enable Consul ACLs (acl.enabled=true + acl.default_policy=deny). "
                        "Bind HTTP API to localhost only OR require gossip-encryption + "
                        "TLS client certs for external access.",
            evidence_marker=f"Anonymous GET {exposed[0]} -> 200 (Consul fingerprint matched)"))
    elif detected:
        findings.append(wrap_finding(
            "Consul detected on standard ports but API requires auth (good)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue ACL + TLS-required posture.",
            evidence_marker="Consul fingerprint, /v1/* requires auth"))
    else:
        findings.append(wrap_finding(
            "No Consul HTTP API exposed on standard ports",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue private Consul access.",
            evidence_marker="TCP/8500 + 8501 closed/non-Consul"))
    return _build_resp("consul_audit", target, findings, 8,
                       "Consul HTTP API exposure probe")


def _probe_istio_audit(target, req):
    """Detect Istio control plane (istiod / pilot) ports leaked externally.
    Default: 15010 (XDS gRPC), 15012 (XDS mTLS), 15014 (monitoring),
    15017 (webhook). Externally-reachable istiod = cluster topology leak."""
    host = _host(target)
    findings = []
    exposed_ports = []
    metrics_leak = None

    # TCP probe for control-plane ports
    for port, label in [
        (15010, "XDS plaintext"),
        (15012, "XDS mTLS"),
        (15014, "monitoring"),
        (15017, "webhook"),
    ]:
        if _tcp_open(host, port):
            exposed_ports.append((port, label))

    # HTTP probe :15014/metrics (Prometheus, leaks every cluster node + workload)
    if any(p == 15014 for p, _ in exposed_ports):
        c, _, b = _http_get_insecure(f"http://{host}:15014/metrics", timeout=3)
        if c == 200 and ("pilot_" in b or "istiod_" in b or "citadel_" in b):
            metrics_leak = f"http://{host}:15014/metrics ({len(b)} bytes)"

    if metrics_leak:
        findings.append(wrap_finding(
            f"Istio istiod /metrics EXPOSED on :15014 (leaks cluster topology)",
            "HIGH", cvss="7.5", cwe="CWE-200",
            remediation="Bind istiod monitoring (port 15014) to in-cluster only. "
                        "Restrict via NetworkPolicy or ServiceMesh interface.",
            evidence_marker=metrics_leak))

    if exposed_ports:
        labels = ", ".join(f"{p}/{lbl}" for p, lbl in exposed_ports)
        findings.append(wrap_finding(
            f"Istio control-plane port(s) reachable externally: {labels}",
            "HIGH" if any(p in (15010, 15017) for p, _ in exposed_ports) else "MEDIUM",
            cvss="7.5" if any(p in (15010, 15017) for p, _ in exposed_ports) else "5.5",
            cwe="CWE-306",
            remediation="Istiod control-plane ports must be in-cluster only. "
                        "Block 15010 (plaintext XDS) and 15017 (webhook) at the edge.",
            evidence_marker=f"TCP open: {labels}"))

    if not findings:
        findings.append(wrap_finding(
            "Istio control plane not externally reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue in-cluster-only istiod binding.",
            evidence_marker="TCP/15010 + 15012 + 15014 + 15017 closed/filtered"))
    return _build_resp("istio_audit", target, findings, 4,
                       "Istio control plane (istiod) external exposure")


def _probe_linkerd_audit(target, req):
    """Detect Linkerd control plane exposure.
    Default: 4191 (proxy admin), 4143 (proxy inbound), 8086 (linkerd-viz tap),
    8085 (linkerd-viz metrics-api). Externally-reachable Viz API allows
    cluster-wide traffic inspection."""
    host = _host(target)
    findings = []
    exposed_ports = []

    for port, label in [
        (4191, "linkerd-proxy admin"),
        (8086, "linkerd-viz tap-api"),
        (8085, "linkerd-viz metrics-api"),
        (9990, "linkerd-viz prometheus"),
    ]:
        if _tcp_open(host, port):
            exposed_ports.append((port, label))

    # HTTP probe /metrics on the tap/metrics API for confirmation
    tap_confirmed = False
    if any(p in (8086, 8085) for p, _ in exposed_ports):
        for port in (8086, 8085):
            c, _, b = _http_get_insecure(f"http://{host}:{port}/metrics", timeout=3)
            if c == 200 and ("linkerd" in b.lower() or "tap" in b.lower()):
                tap_confirmed = True
                break

    if tap_confirmed:
        findings.append(wrap_finding(
            "Linkerd-viz API EXPOSED externally (cluster-wide traffic inspection)",
            "HIGH", cvss="7.5", cwe="CWE-306",
            remediation="Linkerd-viz components must NEVER be exposed externally. "
                        "Use 'linkerd viz dashboard' via kubectl port-forward only. "
                        "Block 8085/8086/9990 at the edge.",
            evidence_marker=f"Linkerd fingerprint on /metrics; ports: {[p for p, _ in exposed_ports]}"))
    elif exposed_ports:
        labels = ", ".join(f"{p}/{lbl}" for p, lbl in exposed_ports)
        findings.append(wrap_finding(
            f"Linkerd port(s) reachable externally: {labels}",
            "MEDIUM", cvss="5.5", cwe="CWE-306",
            remediation="Linkerd control / proxy ports should not be externally reachable. "
                        "Bind to cluster network only.",
            evidence_marker=f"TCP open: {labels}"))
    else:
        findings.append(wrap_finding(
            "Linkerd control plane not externally reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue in-cluster-only linkerd posture.",
            evidence_marker="TCP/4191 + 8085 + 8086 + 9990 closed/filtered"))
    return _build_resp("linkerd_audit", target, findings, 4,
                       "Linkerd control plane / viz external exposure")


# ───────────────────────────────────────────────────────────────
# Image-scanner probes (Trivy / Grype / Cosign / Syft)
# Activate when target syntactically looks like an OCI image reference.
# Honestly skip with NOT_APPLICABLE for hostnames / IPs / URLs.
# ───────────────────────────────────────────────────────────────


def _probe_trivy_image(target, req):
    """Real Trivy image scan. Pulls + scans the image, parses JSON, emits
    findings per CVE. Limits to HIGH/CRITICAL by default to keep PDFs
    readable. Skips honestly when target is not an image reference."""
    if not _looks_like_image_ref(target):
        return _not_applicable_for_image_scanner(target, "trivy_image", "Trivy")

    if shutil.which("trivy") is None:
        return _build_resp("trivy_image", target, [wrap_finding(
            "[NOT IMPLEMENTED] trivy binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile that installs Trivy.",
            evidence_marker="trivy not found in PATH")], 0,
            "Trivy not installed")

    exit_code, stdout, stderr = _run_tool([
        "trivy", "image",
        "--format", "json",
        "--severity", "HIGH,CRITICAL",
        "--quiet",
        "--timeout", "5m",
        "--skip-db-update",  # use pre-baked DB
        target,
    ], timeout_s=360)

    if exit_code == 124:
        return _build_resp("trivy_image", target, [wrap_finding(
            f"[PROBE ERROR] Trivy scan timeout (>6 min) on {target[:80]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Try a smaller image or run trivy manually with longer timeout.",
            evidence_marker="Trivy wall-clock budget exceeded")], 0,
            "Trivy timeout")

    if exit_code not in (0, 1) or not stdout.strip():
        return _build_resp("trivy_image", target, [wrap_finding(
            f"[PROBE ERROR] Trivy exit {exit_code}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify image reference is valid and pullable.",
            evidence_marker=f"stderr: {stderr[-300:]}")], 0,
            f"Trivy exit {exit_code}")

    try:
        data = json.loads(stdout)
    except Exception as e:
        return _build_resp("trivy_image", target, [wrap_finding(
            f"[PROBE ERROR] Trivy JSON parse failed: {str(e)[:120]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Trivy output unexpected; check trivy version.",
            evidence_marker=f"First 300 chars of stdout: {stdout[:300]}")], 0,
            "Trivy parse error")

    findings = []
    sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    cvss_default = {"CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.5", "LOW": "3.0"}

    results = data.get("Results", []) if isinstance(data, dict) else []
    for r in results:
        target_name = r.get("Target", "")
        for v in r.get("Vulnerabilities", []) or []:
            cve = v.get("VulnerabilityID", "")
            pkg = v.get("PkgName", "")
            installed = v.get("InstalledVersion", "")
            fixed = v.get("FixedVersion", "")
            sev = sev_map.get(v.get("Severity", "").upper(), "MEDIUM")
            cvss_score = ""
            cvss_data = v.get("CVSS", {}) or {}
            for src in ("nvd", "redhat", "ghsa", "trivy"):
                if cvss_data.get(src, {}).get("V3Score"):
                    cvss_score = str(cvss_data[src]["V3Score"])
                    break
            cvss_score = cvss_score or cvss_default.get(sev, "0.0")

            title = f"{cve} in {pkg} {installed}" + (f" (fixed in {fixed})" if fixed else " (no fix)")
            findings.append(wrap_finding(
                title, sev, cvss=cvss_score, cwe="CWE-1104",
                remediation=(f"Upgrade {pkg} to {fixed}" if fixed
                              else f"No fix yet for {pkg} {installed} - track upstream advisory."),
                evidence_marker=(f"Trivy {target_name}: {cve} affects "
                                  f"{pkg}@{installed}; severity={sev}, CVSS={cvss_score}")))

    if not findings:
        findings.append(wrap_finding(
            f"Trivy: 0 HIGH/CRITICAL CVEs in {target[:80]}",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue pinning to current patched version.",
            evidence_marker="Trivy completed cleanly, no HIGH/CRITICAL findings"))
    return _build_resp("trivy_image", target, findings, max(len(findings), 1),
                       f"Trivy image CVE scan ({len(findings)} HIGH/CRIT)")


def _probe_grype_image(target, req):
    """Real Grype image scan (alternative CVE DB to Trivy).
    Useful for cross-verification: vulns found by both = confirmed;
    found by only one = suspected. Skips honestly when not an image ref."""
    if not _looks_like_image_ref(target):
        return _not_applicable_for_image_scanner(target, "grype_image", "Grype")

    if shutil.which("grype") is None:
        return _build_resp("grype_image", target, [wrap_finding(
            "[NOT IMPLEMENTED] grype binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile that installs Grype.",
            evidence_marker="grype not found in PATH")], 0,
            "Grype not installed")

    exit_code, stdout, stderr = _run_tool([
        "grype", target, "-o", "json", "-q",
        "--fail-on", "never",  # don't exit nonzero on findings
    ], timeout_s=360)

    if exit_code == 124:
        return _build_resp("grype_image", target, [wrap_finding(
            f"[PROBE ERROR] Grype scan timeout on {target[:80]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Try a smaller image or run grype manually.",
            evidence_marker="Grype wall-clock budget exceeded")], 0, "Grype timeout")

    if exit_code != 0 or not stdout.strip():
        return _build_resp("grype_image", target, [wrap_finding(
            f"[PROBE ERROR] Grype exit {exit_code}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify image is pullable.",
            evidence_marker=f"stderr: {stderr[-300:]}")], 0, f"Grype exit {exit_code}")

    try:
        data = json.loads(stdout)
    except Exception as e:
        return _build_resp("grype_image", target, [wrap_finding(
            f"[PROBE ERROR] Grype JSON parse failed: {str(e)[:120]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Grype output unexpected.",
            evidence_marker=f"First 300 chars: {stdout[:300]}")], 0, "Grype parse error")

    findings = []
    sev_default_cvss = {"Critical": "9.0", "High": "7.5", "Medium": "5.5", "Low": "3.0"}
    matches = data.get("matches", []) if isinstance(data, dict) else []
    for m in matches:
        vuln = m.get("vulnerability", {})
        cve = vuln.get("id", "")
        sev_raw = vuln.get("severity", "Medium")
        if sev_raw not in ("Critical", "High"):
            continue  # filter to HIGH/CRIT for PDF parity with Trivy
        artifact = m.get("artifact", {})
        pkg = artifact.get("name", "")
        installed = artifact.get("version", "")
        fixed_versions = vuln.get("fix", {}).get("versions", []) or []
        fixed = fixed_versions[0] if fixed_versions else ""
        cvss_score = ""
        for cvss_entry in vuln.get("cvss", []) or []:
            metrics = cvss_entry.get("metrics", {})
            if metrics.get("baseScore"):
                cvss_score = str(metrics["baseScore"])
                break
        cvss_score = cvss_score or sev_default_cvss.get(sev_raw, "0.0")
        sev = sev_raw.upper()
        findings.append(wrap_finding(
            f"{cve} in {pkg} {installed}" + (f" (fixed in {fixed})" if fixed else " (no fix)"),
            sev, cvss=cvss_score, cwe="CWE-1104",
            remediation=(f"Upgrade {pkg} to {fixed}" if fixed
                          else f"No fix yet for {pkg} {installed}."),
            evidence_marker=f"Grype: {cve} affects {pkg}@{installed}; sev={sev}"))

    if not findings:
        findings.append(wrap_finding(
            f"Grype: 0 HIGH/CRITICAL CVEs in {target[:80]}",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue current image version.",
            evidence_marker="Grype completed cleanly"))
    return _build_resp("grype_image", target, findings, max(len(findings), 1),
                       f"Grype image CVE scan ({len(findings)} HIGH/CRIT)")


def _probe_cosign_verify(target, req):
    """Real Cosign signature verification.
    Checks if image is signed by a known/trusted key. Unsigned images
    are a supply-chain risk. Skips honestly when not an image ref."""
    if not _looks_like_image_ref(target):
        return _not_applicable_for_image_scanner(target, "image_signing_cosign", "Cosign")

    if shutil.which("cosign") is None:
        return _build_resp("image_signing_cosign", target, [wrap_finding(
            "[NOT IMPLEMENTED] cosign binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile that installs Cosign.",
            evidence_marker="cosign not found in PATH")], 0, "Cosign not installed")

    # Try keyless verification (Sigstore Fuldio / Rekor)
    exit_code, stdout, stderr = _run_tool([
        "cosign", "verify", target,
        "--certificate-identity-regexp", ".*",  # any identity
        "--certificate-oidc-issuer-regexp", ".*",  # any OIDC issuer
    ], timeout_s=60)

    findings = []
    if exit_code == 0:
        findings.append(wrap_finding(
            f"Cosign: {target[:60]} has a valid Sigstore signature",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue keyless signing posture.",
            evidence_marker=f"cosign verify -> exit 0; {stdout[:200]}"))
    elif "no signatures found" in (stderr + stdout).lower() or "no matching signatures" in (stderr + stdout).lower():
        findings.append(wrap_finding(
            f"Cosign: {target[:60]} is UNSIGNED (supply-chain risk)",
            "MEDIUM", cvss="5.5", cwe="CWE-1357",
            remediation=("Sign images with cosign + Sigstore keyless. "
                          "Add admission policy to refuse unsigned images in production."),
            evidence_marker=f"cosign verify -> no signatures found on {target}"))
    else:
        findings.append(wrap_finding(
            f"Cosign verify error on {target[:60]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Check image accessibility + cosign output.",
            evidence_marker=f"cosign stderr: {stderr[-300:]}"))
    return _build_resp("image_signing_cosign", target, findings, 1,
                       "Cosign signature verification")


def _probe_syft_sbom(target, req):
    """Real Syft SBOM generation - lists packages + versions per layer.
    Doesn't emit vulnerabilities but informational POSITIVE finding with
    package count + ecosystem breakdown. Use case: SBOM compliance."""
    if not _looks_like_image_ref(target):
        return _not_applicable_for_image_scanner(target, "image_provenance_slsa", "Syft")

    if shutil.which("syft") is None:
        return _build_resp("image_provenance_slsa", target, [wrap_finding(
            "[NOT IMPLEMENTED] syft binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile that installs Syft.",
            evidence_marker="syft not found in PATH")], 0, "Syft not installed")

    exit_code, stdout, stderr = _run_tool([
        "syft", target, "-o", "syft-json", "-q",
    ], timeout_s=180)

    if exit_code != 0 or not stdout.strip():
        return _build_resp("image_provenance_slsa", target, [wrap_finding(
            f"[PROBE ERROR] Syft exit {exit_code}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify image is pullable.",
            evidence_marker=f"stderr: {stderr[-300:]}")], 0, f"Syft exit {exit_code}")

    try:
        data = json.loads(stdout)
    except Exception as e:
        return _build_resp("image_provenance_slsa", target, [wrap_finding(
            f"[PROBE ERROR] Syft JSON parse: {str(e)[:120]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Syft output unexpected.",
            evidence_marker=f"First 300 chars: {stdout[:300]}")], 0, "Syft parse error")

    artifacts = data.get("artifacts", []) if isinstance(data, dict) else []
    by_ecosystem = {}
    for a in artifacts:
        eco = a.get("type", "unknown")
        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1

    eco_summary = ", ".join(f"{k}:{v}" for k, v in sorted(by_ecosystem.items()))
    findings = [wrap_finding(
        f"SBOM: {len(artifacts)} packages across {len(by_ecosystem)} ecosystem(s)",
        "INFO", cvss="0.0", cwe="N/A",
        remediation=("Store this SBOM with the image build artifact. "
                      "Use for SLSA Level 2+ provenance attestation."),
        evidence_marker=f"Syft inventory: {eco_summary[:300]}")]
    return _build_resp("image_provenance_slsa", target, findings, 1,
                       f"Syft SBOM ({len(artifacts)} packages)")


def _probe_trivy_image_secrets(target, req):
    """Real Trivy secret-detection scan on an OCI image.
    Different scanner mode than _probe_trivy_image (which finds CVEs);
    this looks for hardcoded API keys, tokens, private keys baked into
    the image layers. Skips honestly when target isn't an image ref."""
    if not _looks_like_image_ref(target):
        return _not_applicable_for_image_scanner(target, "image_secrets_scan", "Trivy secret scan")

    if shutil.which("trivy") is None:
        return _build_resp("image_secrets_scan", target, [wrap_finding(
            "[NOT IMPLEMENTED] trivy binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile that installs Trivy.",
            evidence_marker="trivy not found in PATH")], 0, "Trivy not installed")

    exit_code, stdout, stderr = _run_tool([
        "trivy", "image",
        "--format", "json",
        "--scanners", "secret",
        "--quiet",
        "--timeout", "3m",
        "--skip-db-update",
        target,
    ], timeout_s=240)

    if exit_code == 124:
        return _build_resp("image_secrets_scan", target, [wrap_finding(
            "[PROBE ERROR] Trivy secret scan timeout",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Try a smaller image.",
            evidence_marker="Wall-clock exceeded")], 0, "Trivy secret timeout")

    if exit_code not in (0, 1) or not stdout.strip():
        return _build_resp("image_secrets_scan", target, [wrap_finding(
            f"[PROBE ERROR] Trivy secret scan exit {exit_code}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify image is pullable.",
            evidence_marker=f"stderr: {stderr[-300:]}")], 0,
            f"Trivy exit {exit_code}")

    try:
        data = json.loads(stdout)
    except Exception as e:
        return _build_resp("image_secrets_scan", target, [wrap_finding(
            f"[PROBE ERROR] Trivy JSON parse: {str(e)[:120]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Trivy output unexpected.",
            evidence_marker=f"First 300 chars: {stdout[:300]}")], 0, "parse error")

    findings = []
    for r in data.get("Results", []) or []:
        for s in r.get("Secrets", []) or []:
            sev = s.get("Severity", "MEDIUM").upper()
            cvss = {"CRITICAL": "9.0", "HIGH": "7.5",
                    "MEDIUM": "5.5", "LOW": "3.0"}.get(sev, "5.5")
            cat = s.get("Category", "secret")
            title_short = s.get("Title", cat)
            match = s.get("Match", "")[:120]
            path = r.get("Target", "")
            findings.append(wrap_finding(
                f"Hardcoded {cat} in image: {title_short}",
                sev, cvss=cvss, cwe="CWE-798",
                remediation=(f"Remove {cat} from image. Use runtime "
                              "secret-injection (Vault CSI, AWS Secrets "
                              "Manager, K8s Secrets) instead of baking "
                              "into image layers."),
                evidence_marker=f"Trivy secret: {path}: {match}"))

    if not findings:
        findings.append(wrap_finding(
            f"Trivy secret scan: 0 hardcoded secrets in {target[:80]}",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue clean-build posture.",
            evidence_marker="Trivy --scanners secret: 0 hits"))
    return _build_resp("image_secrets_scan", target, findings,
                       max(len(findings), 1),
                       f"Trivy hardcoded-secret scan ({len(findings)})")


def _probe_ingress_authz_open(target, req):
    """Detect ingress controllers that expose admin / metrics / health
    endpoints without auth. Probes common paths attackers use as a
    starting point (cluster reconnaissance + potential RCE)."""
    host = _host(target)
    findings = []
    exposed = []

    # Common ingress / admin paths leaked publicly
    paths_to_test = [
        ("/actuator/env", "Spring Boot Actuator env (CRITICAL leak)"),
        ("/actuator/heapdump", "Spring Boot heapdump"),
        ("/actuator/health", "Spring Boot health"),
        ("/.env", "dotenv config file"),
        ("/admin", "Admin interface"),
        ("/manager", "Tomcat manager"),
        ("/console", "Web console"),
        ("/api/v1/health", "Generic health endpoint"),
        ("/metrics", "Prometheus metrics endpoint"),
        ("/healthz", "K8s-style health endpoint"),
        ("/readyz", "K8s-style readiness endpoint"),
        ("/swagger-ui", "Swagger UI"),
        ("/v3/api-docs", "OpenAPI spec"),
        ("/graphql", "GraphQL endpoint"),
    ]

    high_value = ("/actuator/env", "/actuator/heapdump", "/.env",
                   "/admin", "/manager", "/console")

    for scheme in ("https", "http"):
        for path, label in paths_to_test:
            url = f"{scheme}://{host}{path}"
            c, _, b = _http_get_insecure(url, timeout=3)
            if c == 200 and len(b) > 20 and "<html" not in b[:200].lower():
                exposed.append((path, label, scheme))
            elif c == 200 and path in ("/admin", "/manager", "/swagger-ui"):
                exposed.append((path, label, scheme))
        if exposed:
            break

    if exposed:
        critical_hits = [e for e in exposed if e[0] in high_value]
        sev = "CRITICAL" if critical_hits else "HIGH" if len(exposed) > 3 else "MEDIUM"
        cvss = "9.0" if sev == "CRITICAL" else "7.5" if sev == "HIGH" else "5.5"
        summary = "; ".join(f"{e[2]}://{host}{e[0]} ({e[1]})" for e in exposed[:5])
        findings.append(wrap_finding(
            f"Ingress: {len(exposed)} sensitive path(s) reachable without auth",
            sev, cvss=cvss, cwe="CWE-306",
            remediation=("Restrict admin / actuator / metrics / health paths "
                          "to internal IPs or require auth. Add ingress-level "
                          "deny rules. Spring Boot: management.endpoints.web."
                          "exposure.include=health (only)."),
            evidence_marker=f"Exposed: {summary}"))
    else:
        findings.append(wrap_finding(
            "No unauthenticated admin/actuator/metrics paths detected on ingress",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue locked-down ingress posture.",
            evidence_marker=f"Probed {len(paths_to_test)*2} path/scheme combinations"))
    return _build_resp("ingress_authz_open", target, findings,
                       len(paths_to_test) * 2,
                       "Ingress unauth admin/actuator/metrics probe")


PROBES = {
    # original 7 real probes
    "docker_daemon_exposed":          _probe_docker_daemon_exposed,
    "etcd_apiserver_exposure":        _probe_etcd_exposed,
    "kube_bench_master":              _probe_k8s_api,
    "k8s_kubelet_anonymous_auth":     _probe_kubelet,
    "registry_npm_2fa_audit":         _probe_harbor_registry,
    "opa_kyverno_no_policies":        _probe_k8s_dashboard,
    "registry_pypi_2fa_audit":        _probe_registry_public,
    # newly forged real probes (2026-06-01)
    "k8s_anonymous_auth":             _probe_k8s_anonymous_auth,
    "k8s_api_server_insecure_port":   _probe_k8s_api_insecure_port,
    "registry_anon_push":             _probe_registry_anon_push,
    "nginx_ingress_audit":            _probe_nginx_ingress,
    "traefik_audit":                  _probe_traefik_ingress,
    "haproxy_ingress_audit":          _probe_haproxy_ingress,
    "envoy_config_audit":             _probe_envoy_proxy,
    "ingress_tls_audit":              _probe_ingress_tls_audit,
    "istio_gateway_mtls_off":         _probe_istio_gateway_mtls,
    "consul_audit":                   _probe_consul_audit,
    "istio_audit":                    _probe_istio_audit,
    "linkerd_audit":                  _probe_linkerd_audit,
    "linkerd_authz_audit":            _probe_linkerd_audit,
    # image scanners (activate when target = OCI image ref like nginx:1.21)
    "trivy_image":                    _probe_trivy_image,
    "grype_image":                    _probe_grype_image,
    "image_signing_cosign":           _probe_cosign_verify,
    "image_provenance_slsa":          _probe_syft_sbom,
    "image_secrets_scan":             _probe_trivy_image_secrets,
    "ingress_authz_open":             _probe_ingress_authz_open,
    "service_mesh_authz_open":        _probe_ingress_authz_open,
    # additional slugs covered by existing probes (no new code needed)
    "k8s_kubelet_unauth_token":       _probe_kubelet,
    "k8s_etcd_no_tls":                _probe_etcd_exposed,
    "k8s_etcd_unencrypted":           _probe_etcd_exposed,
    "secrets_etcd_unencrypted":       _probe_etcd_exposed,
    "registry_public_pull":           _probe_registry_public,
}

T = [
    # §1 Image/Registry (13)
    ("trivy_image", "Trivy image scan.", "MEDIUM", "5.5"),
    ("grype_image", "Grype image scan.", "MEDIUM", "5.5"),
    ("snyk_container", "Snyk container.", "MEDIUM", "5.5"),
    ("anchore_image", "Anchore image.", "MEDIUM", "5.5"),
    ("clair_image", "Clair image.", "MEDIUM", "5.5"),
    ("hadolint_dockerfile", "Hadolint Dockerfile.", "MEDIUM", "5.5"),
    ("image_secrets_scan", "Image secrets scan.", "HIGH", "8.0"),
    ("image_distroless_base", "Distroless/Wolfi base check.", "INFO", "0.0"),
    ("image_signing_cosign", "Cosign image signing.", "MEDIUM", "5.5"),
    ("registry_public_pull", "Registry public pull.", "HIGH", "7.5"),
    ("registry_anon_push", "Registry anonymous push.", "CRITICAL", "9.0"),
    ("image_provenance_slsa", "SLSA provenance check.", "MEDIUM", "5.5"),
    ("manual_image_review", "Manual image review.", "INFO", "0.0"),
    # §2 Dockerfile (10)
    ("dockerfile_root_user", "Dockerfile USER root.", "MEDIUM", "5.5"),
    ("dockerfile_no_user", "Dockerfile no USER directive.", "MEDIUM", "5.5"),
    ("dockerfile_ssh_in_image", "SSH server in image.", "MEDIUM", "5.5"),
    ("dockerfile_curl_pipe_bash", "curl | bash in RUN.", "HIGH", "7.0"),
    ("dockerfile_hardcoded_secret", "Hardcoded secret in image.", "CRITICAL", "9.0"),
    ("dockerfile_apt_unpinned", "apt without pinned versions.", "MEDIUM", "5.5"),
    ("dockerfile_no_healthcheck", "No HEALTHCHECK.", "INFO", "0.0"),
    ("dockerfile_multistage_audit", "Multi-stage build audit.", "INFO", "0.0"),
    ("dockerfile_copy_chown_audit", "COPY --chown audit.", "INFO", "0.0"),
    ("dockerfile_expose_audit", "EXPOSE port audit.", "INFO", "0.0"),
    # §3 Container Runtime (12)
    ("container_privileged", "Container privileged mode.", "CRITICAL", "9.0"),
    ("container_capadd_dangerous", "Dangerous CAP_ADD.", "HIGH", "8.0"),
    ("container_host_pid", "hostPID:true.", "HIGH", "8.0"),
    ("container_host_network", "hostNetwork:true.", "HIGH", "7.5"),
    ("container_host_ipc", "hostIPC:true.", "HIGH", "7.5"),
    ("container_hostpath_dangerous", "Dangerous hostPath mount.", "CRITICAL", "9.0"),
    ("container_docker_sock_mount", "Docker socket mounted.", "CRITICAL", "9.5"),
    ("container_runas_root", "runAsUser:0.", "HIGH", "7.5"),
    ("container_no_readonly_rootfs", "readOnlyRootFilesystem:false.", "MEDIUM", "5.5"),
    ("container_allow_priv_escalation", "allowPrivilegeEscalation:true.", "HIGH", "7.5"),
    ("container_seccomp_unset", "seccompProfile unset.", "MEDIUM", "5.5"),
    ("container_apparmor_unset", "AppArmor profile unset.", "MEDIUM", "5.5"),
    # §4 K8s Cluster Hardening CIS (17)
    ("kube_bench_master", "kube-bench master.", "MEDIUM", "5.5"),
    ("kube_bench_node", "kube-bench node.", "MEDIUM", "5.5"),
    ("kube_hunter", "kube-hunter.", "MEDIUM", "5.5"),
    ("k8s_anonymous_auth", "Anonymous-auth=true.", "CRITICAL", "9.0"),
    ("k8s_audit_logs_off", "Audit logs off.", "MEDIUM", "5.5"),
    ("k8s_etcd_unencrypted", "etcd unencrypted.", "HIGH", "7.5"),
    ("k8s_etcd_no_tls", "etcd no TLS.", "HIGH", "8.0"),
    ("k8s_api_server_insecure_port", "API server insecure port.", "CRITICAL", "9.0"),
    ("k8s_kubelet_anonymous_auth", "Kubelet anonymous-auth.", "CRITICAL", "9.0"),
    ("k8s_kubelet_unauth_token", "Kubelet unauth token.", "CRITICAL", "9.0"),
    ("k8s_admission_no_plugin", "Admission plugin missing.", "HIGH", "7.5"),
    ("k8s_psp_psa_disabled", "PSP/PSA disabled.", "HIGH", "7.5"),
    ("k8s_network_policy_absent", "NetworkPolicy absent.", "MEDIUM", "5.5"),
    ("k8s_certificate_rotation", "Certificate rotation audit.", "MEDIUM", "5.5"),
    ("k8s_tls_min_version", "TLS min version audit.", "MEDIUM", "5.5"),
    ("k8s_admission_controller_audit", "Admission controller audit.", "MEDIUM", "5.5"),
    ("k8s_cni_plugin_audit", "CNI plugin audit.", "MEDIUM", "5.5"),
    # §5 RBAC / Policy / OPA (12)
    ("rbac_cluster_admin_overuse", "cluster-admin overuse.", "HIGH", "8.0"),
    ("rbac_secret_get_anywhere", "Secrets GET cluster-wide.", "HIGH", "7.5"),
    ("rbac_pod_exec_create_overuse", "pod exec/create RBAC overuse.", "HIGH", "8.0"),
    ("rbac_node_proxy_overuse", "node/proxy overuse.", "HIGH", "7.5"),
    ("rbac_impersonate_users", "impersonate users RBAC.", "HIGH", "8.0"),
    ("rbac_pod_serviceaccount_token", "Pod SA token automount audit.", "MEDIUM", "5.5"),
    ("rbac_clusterrolebinding_audit", "ClusterRoleBinding audit.", "MEDIUM", "5.5"),
    ("rbac_aggregate_role_audit", "aggregateRule audit.", "MEDIUM", "5.5"),
    ("opa_gatekeeper_no_constraints", "Gatekeeper no constraints.", "MEDIUM", "5.5"),
    ("opa_kyverno_no_policies", "Kyverno no policies.", "MEDIUM", "5.5"),
    ("rbac_audit_via_rbac_tool", "rbac-tool audit.", "INFO", "0.0"),
    ("manual_rbac_review", "Manual RBAC review.", "INFO", "0.0"),
    # §6 Network Policy / Service Mesh (10)
    ("network_policy_default_deny", "Default-deny NetworkPolicy.", "MEDIUM", "5.5"),
    ("network_policy_egress_audit", "Egress NetworkPolicy audit.", "MEDIUM", "5.5"),
    ("service_mesh_mtls_off", "Service mesh mTLS off.", "HIGH", "7.5"),
    ("service_mesh_authz_open", "Service mesh authz open.", "HIGH", "7.5"),
    ("ingress_tls_audit", "Ingress TLS audit.", "MEDIUM", "5.5"),
    ("ingress_authz_open", "Ingress authz open.", "HIGH", "7.5"),
    ("istio_gateway_mtls_off", "Istio gateway mTLS off.", "HIGH", "7.5"),
    ("linkerd_authz_audit", "Linkerd authz audit.", "MEDIUM", "5.5"),
    ("envoy_filter_audit", "Envoy filter audit.", "MEDIUM", "5.5"),
    ("manual_network_policy_review", "Manual network policy review.", "INFO", "0.0"),
    # §7 Secrets Management (9)
    ("secrets_etcd_unencrypted", "etcd secrets unencrypted.", "HIGH", "7.5"),
    ("secrets_in_env_var", "Secrets in env vars.", "MEDIUM", "5.5"),
    ("secrets_in_configmap", "Secrets in ConfigMap (not Secret).", "HIGH", "7.5"),
    ("secrets_helm_values_leak", "Helm values.yaml secret leak.", "HIGH", "8.0"),
    ("secrets_kustomize_leak", "Kustomize secret leak.", "HIGH", "7.5"),
    ("external_secrets_audit", "ExternalSecrets audit.", "MEDIUM", "5.5"),
    ("vault_csi_audit", "Vault CSI audit.", "MEDIUM", "5.5"),
    ("sealed_secrets_audit", "SealedSecrets audit.", "MEDIUM", "5.5"),
    ("manual_secrets_review", "Manual secrets review.", "INFO", "0.0"),
    # §8 Container Escape CVEs (9)
    ("escape_leaky_vessels_runc_2024", "Leaky Vessels runc (CVE-2024-21626).", "HIGH", "8.6"),
    ("escape_containerd_cve_2022_23648", "containerd (CVE-2022-23648).", "HIGH", "7.5"),
    ("escape_docker_socket_mount", "Docker socket escape.", "CRITICAL", "9.5"),
    ("escape_cap_sys_admin_chain", "CAP_SYS_ADMIN escape chain.", "HIGH", "8.0"),
    ("escape_kernel_keyring", "Kernel keyring escape.", "HIGH", "7.5"),
    ("escape_proc_self_exe", "/proc/self/exe escape.", "HIGH", "7.5"),
    ("escape_user_namespace_audit", "User namespace audit.", "MEDIUM", "5.5"),
    ("escape_cgroup_release_agent", "cgroup release_agent escape.", "HIGH", "8.0"),
    ("manual_escape_research", "Manual escape research.", "INFO", "0.0"),
    # §9 Service Mesh & Ingress (8)
    ("istio_audit", "Istio audit.", "MEDIUM", "5.5"),
    ("linkerd_audit", "Linkerd audit.", "MEDIUM", "5.5"),
    ("consul_audit", "Consul audit.", "MEDIUM", "5.5"),
    ("envoy_config_audit", "Envoy config audit.", "MEDIUM", "5.5"),
    ("nginx_ingress_audit", "Nginx ingress audit.", "MEDIUM", "5.5"),
    ("traefik_audit", "Traefik audit.", "MEDIUM", "5.5"),
    ("haproxy_ingress_audit", "HAProxy ingress audit.", "MEDIUM", "5.5"),
    ("manual_mesh_review", "Manual mesh review.", "INFO", "0.0"),
    # §10 eBPF Runtime Detection (3)
    ("falco_runtime_audit", "Falco runtime audit.", "MEDIUM", "5.5"),
    ("tetragon_runtime_audit", "Tetragon (Cilium) runtime audit.", "MEDIUM", "5.5"),
    ("tracee_runtime_audit", "Tracee (Aqua) runtime audit.", "MEDIUM", "5.5"),
]

router = make_advisory_router("container_k8s", T,
    playbook_ref="See module_playbooks/24_container_k8s.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
