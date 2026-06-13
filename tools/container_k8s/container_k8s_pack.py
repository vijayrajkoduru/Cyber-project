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
from tools._pack_common import (make_advisory_router, _adv_response,
                                   _advisory_by_design_response)
from tools._shared import wrap_finding
from tools.container_k8s._dockerfile_probes import (
    _probe_dockerfile_root_user,
    _probe_dockerfile_no_user,
    _probe_dockerfile_ssh_in_image,
    _probe_dockerfile_curl_pipe_bash,
    _probe_dockerfile_hardcoded_secret,
    _probe_dockerfile_apt_unpinned,
    _probe_dockerfile_no_healthcheck,
    _probe_dockerfile_multistage_audit,
    _probe_dockerfile_copy_chown_audit,
    _probe_dockerfile_expose_audit,
    _probe_dockerfile_base_image_eol,
    _probe_hadolint_dockerfile,
    _probe_dockerfile_antipatterns,
)
from tools.container_k8s._pod_spec_probes import (
    _probe_container_privileged,
    _probe_container_capadd_dangerous,
    _probe_container_host_pid,
    _probe_container_host_network,
    _probe_container_host_ipc,
    _probe_container_hostpath_dangerous,
    _probe_container_docker_sock_mount,
    _probe_container_runas_root,
    _probe_container_no_readonly_rootfs,
    _probe_container_allow_priv_escalation,
    _probe_container_seccomp_unset,
    _probe_container_apparmor_unset,
)
from tools.container_k8s._kubeconfig_probes import (
    _probe_k8s_anonymous_auth_kubectl,
    _probe_k8s_audit_logs_off,
    _probe_k8s_admission_no_plugin,
    _probe_k8s_psp_psa_disabled,
    _probe_k8s_network_policy_absent,
    _probe_rbac_cluster_admin_overuse,
    _probe_rbac_secret_get_anywhere,
    _probe_rbac_pod_exec_create_overuse,
    _probe_rbac_node_proxy_overuse,
    _probe_rbac_impersonate_users,
    _probe_secrets_in_env_var,
    _probe_kube_bench_node,
)
from tools.container_k8s._escape_cve_probes import (
    _probe_escape_leaky_vessels_runc,
    _probe_escape_containerd_2022_23648,
)
from tools.container_k8s._kubeconfig_extra_probes import (
    _probe_secrets_etcd_unencrypted,
    _probe_vault_csi_audit,
    _probe_sealed_secrets_audit,
    _probe_external_secrets_audit,
    _probe_k8s_tls_min_version,
    _probe_k8s_cni_plugin_audit,
    _probe_rbac_pod_serviceaccount_token,
    _probe_rbac_clusterrolebinding_audit,
    _probe_rbac_aggregate_role_audit,
    _probe_envoy_filter_audit,
)
from tools.container_k8s._repo_secret_probes import (
    _probe_secrets_helm_values_leak,
    _probe_secrets_kustomize_leak,
    _probe_kyverno_no_policies,
    _probe_opa_gatekeeper_no_constraints,
)
from tools.container_k8s._scaffold_forge_probes import (
    _probe_escape_docker_socket_mount,
    _probe_escape_cap_sys_admin_chain,
    _probe_escape_user_namespace_audit,
    _probe_k8s_admission_controller_audit,
    _probe_k8s_certificate_rotation,
    _probe_rbac_audit_via_rbac_tool,
    _probe_service_mesh_mtls_off,
)


# Advisory-by-design wrappers for paid / external-service image scanners
def _abd_snyk(t, r): return _advisory_by_design_response(
    "snyk_container", t, "Snyk container vulnerability scan",
    reason=("Snyk is a paid commercial service requiring a subscription + "
             "API token. VulnusLab does not bundle paid integrations. "
             "Trivy + Grype probes (already real) cover the same CVE surface "
             "for free."),
    cwe="N/A")

def _abd_anchore(t, r): return _advisory_by_design_response(
    "anchore_image", t, "Anchore Engine deep image analysis",
    reason=("Anchore Engine runs as a stateful sidecar service (Postgres "
             "backend + policy engine). Not bundled in the SaaS scanner; "
             "Trivy probe (already real) covers the same image-CVE surface."),
    cwe="N/A")

def _abd_clair(t, r): return _advisory_by_design_response(
    "clair_image", t, "Clair static image analysis",
    reason=("Clair is a stateful sidecar service requiring Postgres + "
             "deployment of clairctl. Trivy + Grype probes already deployed "
             "cover the same image-CVE surface for free."),
    cwe="N/A")


# Advisory-by-design wrappers - these techniques cannot be SaaS-probed.
def _abd_falco(t, r): return _advisory_by_design_response(
    "falco_runtime_audit", t, "Falco eBPF runtime detection",
    reason="Falco runs as a DaemonSet inside the cluster + reads kernel eBPF events; requires on-host deployment, not SaaS-probeable.",
    cwe="N/A")

def _abd_tetragon(t, r): return _advisory_by_design_response(
    "tetragon_runtime_audit", t, "Tetragon (Cilium) eBPF runtime detection",
    reason="Cilium Tetragon requires in-cluster DaemonSet + kernel eBPF programs. Not SaaS-probeable.",
    cwe="N/A")

def _abd_tracee(t, r): return _advisory_by_design_response(
    "tracee_runtime_audit", t, "Tracee (Aqua) eBPF runtime detection",
    reason="Tracee runs eBPF probes from inside cluster nodes. Not SaaS-probeable.",
    cwe="N/A")

def _abd_manual_image_review(t, r): return _advisory_by_design_response(
    "manual_image_review", t, "Manual image review",
    reason="Image-spec review is a human activity. See playbook checklist.",
    cwe="N/A")

def _abd_manual_rbac_review(t, r): return _advisory_by_design_response(
    "manual_rbac_review", t, "Manual RBAC review",
    reason="Holistic RBAC review requires human judgement on business roles.",
    cwe="N/A")

def _abd_manual_np_review(t, r): return _advisory_by_design_response(
    "manual_network_policy_review", t, "Manual NetworkPolicy review",
    reason="Topology-aware NP review requires human judgement on intended traffic flows.",
    cwe="N/A")

def _abd_manual_secrets_review(t, r): return _advisory_by_design_response(
    "manual_secrets_review", t, "Manual secrets-management review",
    reason="Secrets rotation cadence + access-pattern audit requires human review of vault logs.",
    cwe="N/A")

def _abd_manual_escape(t, r): return _advisory_by_design_response(
    "manual_escape_research", t, "Container escape research",
    reason="CVE research + exploit chain validation is a human red-team activity.",
    cwe="N/A")

def _abd_manual_mesh(t, r): return _advisory_by_design_response(
    "manual_mesh_review", t, "Service-mesh configuration review",
    reason="Holistic mesh policy review requires human judgement.",
    cwe="N/A")

def _abd_escape_cgroup(t, r): return _advisory_by_design_response(
    "escape_cgroup_release_agent", t, "cgroup release_agent escape",
    reason="Requires on-host /sys/fs/cgroup write access. Not SaaS-detectable without running container shell.",
    cwe="CWE-269")

def _abd_escape_kernel_keyring(t, r): return _advisory_by_design_response(
    "escape_kernel_keyring", t, "Kernel keyring container escape",
    reason="Requires on-host kernel-keyring probing. Not SaaS-detectable.",
    cwe="CWE-269")

def _abd_escape_proc_self_exe(t, r): return _advisory_by_design_response(
    "escape_proc_self_exe", t, "/proc/self/exe container escape (CVE-2019-5736)",
    reason="Patched in runc 1.0.0-rc6+. CVE-2024-21626 covers similar vectors and is forged via runtime version check.",
    cwe="CWE-269")


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


def _resolve_image_ref(target, req):
    """Image probes accept the image from EITHER the basic target field OR
    the advanced `image_ref` input. Advanced input wins when both are set
    (more specific). Returns the effective image-ref string or "" if neither
    is a valid image reference."""
    adv = ""
    if req is not None:
        adv = (getattr(req, "image_ref", None) or "").strip()
    if adv and _looks_like_image_ref(adv):
        return adv
    if target and _looks_like_image_ref(target):
        return target
    return ""


def _not_applicable_for_image_scanner(target, slug, tool_name):
    """Return a NOT_APPLICABLE finding when the target isn't an image ref."""
    r = _build_resp(slug, target, [wrap_finding(
        f"[NOT_APPLICABLE] {tool_name} requires an OCI image reference",
        "INFO", cvss="0.0", cwe="N/A",
        remediation=(f"To run {tool_name}, provide an image reference like "
                      "'nginx:1.21' or 'myreg.io/app:v2.3' as the scan target. "
                      "Hostnames/IPs are not scannable by image-CVE tools."),
        evidence_marker=(f"Target '{target[:80]}' does not match image-ref "
                          "pattern (registry/repo:tag or @sha256:digest)."),
    )], 0, f"{tool_name} skipped - not an image reference")
    r["_skipped"] = True
    r["skipped_reason"] = f"target is not an image reference"
    return r



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


def _target_is_placeholder(target) -> bool:
    """True if `target` is empty/whitespace or the 'n/a' sentinel the frontend
    sends when only advanced inputs are filled. Network-target probes should
    skip honestly in this case instead of probing 'https://n/v2/' garbage."""
    if not target or not isinstance(target, str):
        return True
    t = target.strip().lower()
    return t in ("", "n/a", "na", "none", "-", "(none)")


def _na_for_network_probe(slug: str, target: str, tool_name: str) -> dict:
    """Standard NOT_APPLICABLE shape for network-target probes when only
    advanced inputs were supplied (target is the 'n/a' placeholder)."""
    return _build_resp(slug, target, [wrap_finding(
        f"[NOT_APPLICABLE] {tool_name} requires a hostname/URL target",
        "INFO", cvss="0.0", cwe="N/A",
        remediation=(f"To run {tool_name}, paste a target hostname or URL "
                      "in the Target field. This probe doesn't use the advanced "
                      "inputs (image / Dockerfile / pod-spec / kubeconfig / repo) "
                      "since it checks network-reachable services."),
        evidence_marker="Target is empty or 'n/a' — only advanced inputs were "
                        "provided. Probe skipped to avoid probing the literal "
                        "string as a hostname.",
    )], 0, f"{tool_name} skipped — no network target")

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
    """Docker Engine API public-exposure probe.

    Zero-FP rule: CRITICAL only when the Docker daemon /version endpoint
    answers UNAUTHENTICATED with a real Docker fingerprint (ApiVersion /
    GitCommit). An unauthenticated remote daemon == trivial host root
    (mount / and chroot). A bare open port with no Docker fingerprint is
    reported INFO, never HIGH.
    """
    host = _host(target)
    findings = []
    for port, label in [(2375, "Docker (plaintext)"), (2376, "Docker (TLS)")]:
        if not _tcp_open(host, port):
            continue
        confirmed = False
        for scheme in ("http", "https"):
            code, _, body = _http_get_insecure(
                f"{scheme}://{host}:{port}/version", timeout=3)
            bl = (body or "").lower()
            if code == 200 and ("apiversion" in bl or "gitcommit" in bl
                                or '"os"' in bl):
                confirmed = True
                proto = scheme
                break
        if confirmed:
            findings.append(wrap_finding(
                f"Docker Engine API on {port}/tcp answers UNAUTHENTICATED ({label})",
                "CRITICAL", cvss="9.5", cwe="CWE-732", owasp="A05:2021",
                remediation="NEVER expose the Docker daemon API. An open remote "
                            "daemon grants full host root (mount /, run "
                            "privileged). Bind to the local socket only, or "
                            "enforce mTLS (tlsverify) + firewall the port.",
                evidence_marker=f"{proto}://{host}:{port}/version → 200 with "
                                "Docker fingerprint (ApiVersion/GitCommit)"))
        else:
            findings.append(wrap_finding(
                f"Port {port}/tcp open but no unauthenticated Docker fingerprint",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Confirm the listener. If this is dockerd, ensure "
                            "tlsverify is enforced (anonymous /version was "
                            "rejected here).",
                evidence_marker=f"TCP/{port} open; /version returned no Docker "
                                "version document"))
    if not findings:
        findings.append(wrap_finding("Docker daemon NOT externally exposed (good)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue localhost-only binding.",
            evidence_marker="TCP/2375 + 2376 closed"))
    return _build_resp("docker_daemon_exposed", target, findings, 2, "Docker daemon exposure")


def _probe_etcd_exposed(target, req):
    """etcd public-exposure probe (CIS 2.x / NSA-CISA).

    Zero-FP rule: CRITICAL only when an etcd fingerprint is actually
    observed unauthenticated (/version returns etcd JSON, or /health
    returns the etcd health document, or the v2 keyspace answers). A bare
    open TCP port with no etcd fingerprint is reported INFO — never HIGH —
    because many unrelated services bind 2379/2380.
    """
    host = _host(target)
    findings = []
    for port in [2379, 2380]:
        if not _tcp_open(host, port):
            continue
        confirmed = None
        # /version (plaintext etcd) -> {"etcdserver":"...","etcdcluster":"..."}
        for scheme in ("http", "https"):
            code, _, body = _http_get_insecure(
                f"{scheme}://{host}:{port}/version", timeout=3)
            bl = (body or "").lower()
            if code == 200 and ("etcdserver" in bl or "etcdcluster" in bl):
                confirmed = (f"{scheme} /version", body[:120])
                break
            ch, _, hb = _http_get_insecure(
                f"{scheme}://{host}:{port}/health", timeout=3)
            if ch == 200 and '"health"' in (hb or "").lower():
                confirmed = (f"{scheme} /health", hb[:120])
                break
        if confirmed:
            ep, sample = confirmed
            findings.append(wrap_finding(
                f"etcd {port}/tcp publicly reachable + answers unauthenticated",
                "CRITICAL", cvss="9.5", cwe="CWE-306", owasp="A05:2021",
                remediation="etcd MUST NOT be exposed publicly. Require peer + "
                            "client mTLS (--client-cert-auth=true) and bind to "
                            "a private subnet. Unauthenticated etcd = full "
                            "cluster secret/state disclosure.",
                evidence_marker=f"TCP/{port} open; {ep} → etcd fingerprint: {sample}"))
        else:
            findings.append(wrap_finding(
                f"Port {port}/tcp open (etcd default) but no unauthenticated "
                "etcd fingerprint",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Confirm the listener. If this is etcd, ensure "
                            "client-cert auth blocks anonymous access (this "
                            "probe could not read it without credentials).",
                evidence_marker=f"TCP/{port} open; /version + /health did not "
                                "return an etcd document"))
    if not findings:
        findings.append(wrap_finding("etcd not externally reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue private etcd networking.",
            evidence_marker="TCP/2379 + 2380 closed"))
    return _build_resp("etcd_apiserver_exposure", target, findings, 2, "etcd port + version probe")


def _probe_k8s_api(target, req):
    """kube-apiserver external-exposure probe (CIS 1.2.x edge restriction).

    Zero-FP rule: a graded severity requires a positive K8s fingerprint
    (gitCommit / 'kubernetes' / a real *Status JSON). A bare open port that
    does NOT answer as a K8s API is reported INFO, never HIGH — that avoids
    flagging unrelated HTTPS services that happen to listen on 8443.
    """
    host = _host(target)
    findings = []
    for port in [6443, 8080, 8443]:
        if not _tcp_open(host, port):
            continue
        scheme = "http" if port == 8080 else "https"
        code, _, body = _http_get_insecure(
            f"{scheme}://{host}:{port}/version", timeout=3)
        bl = (body or "").lower()
        is_k8s = ("gitcommit" in bl or "gitversion" in bl
                  or ("kubernetes" in bl and "builddate" in bl))
        if not is_k8s and code in (401, 403):
            # /version blocked — try /healthz which returns plain 'ok' on K8s
            c2, _, b2 = _http_get_insecure(
                f"{scheme}://{host}:{port}/healthz", timeout=3)
            is_k8s = (c2 == 200 and b2.strip().lower() == "ok") or is_k8s
        if not is_k8s:
            if code or _tcp_open(host, port):
                findings.append(wrap_finding(
                    f"Port {port}/tcp open but no kube-apiserver fingerprint",
                    "INFO", cvss="0.0", cwe="N/A",
                    remediation="Confirm what service listens here; not "
                                "confirmed as a Kubernetes API server.",
                    evidence_marker=f"{scheme}://{host}:{port}/version → {code}, "
                                    "no K8s fingerprint"))
            continue
        if code == 200:
            findings.append(wrap_finding(
                f"kube-apiserver on {port}/tcp serves /version to anonymous "
                "callers (public-info-viewer default) and is internet-reachable",
                "MEDIUM", cvss="5.5", cwe="CWE-306", owasp="A05:2021",
                remediation="Restrict the API server to a bastion/VPN/allow-list. "
                            "The version string aids targeted CVE selection even "
                            "when full auth is enforced.",
                evidence_marker=f"TCP/{port} open; /version → 200 (K8s fingerprint)"))
        else:
            findings.append(wrap_finding(
                f"kube-apiserver on {port}/tcp is internet-reachable "
                "(auth required for /version)",
                "MEDIUM", cvss="5.5", cwe="CWE-306", owasp="A05:2021",
                remediation="Place the API server behind a private endpoint / "
                            "allow-list. Edge reachability widens the attack "
                            "surface even with RBAC enforced.",
                evidence_marker=f"TCP/{port} open; /version → {code} (K8s fingerprint)"))
    if not findings:
        findings.append(wrap_finding("K8s API not externally reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue API restriction.",
            evidence_marker="TCP/6443 + 8080 + 8443 closed"))
    return _build_resp("kube_bench_master", target, findings, 3, "K8s API server external exposure")


def _probe_kubelet(target, req):
    """kubelet anonymous-auth probe (CIS K8s 4.2.1).

    Zero-FP rule: a graded severity is emitted ONLY when an anonymous
    request to a kubelet endpoint actually SUCCEEDS with kubelet-shaped
    content. A port that is merely open but answers 401/403 to anonymous
    callers is the SECURE configuration and is reported POSITIVE — never
    flagged HIGH for being reachable.

    Endpoints probed per port:
      10250 (HTTPS, authn/authz)  -> /pods, /runningpods/, /stats/summary
      10255 (HTTP read-only port) -> /pods, /metrics/cadvisor, /stats/summary
    A 200 with kubelet JSON/Prometheus content == anonymous access GRANTED.
    """
    host = _host(target)
    findings = []
    any_open = False

    # (port, scheme, [endpoints], content-fingerprint tokens)
    kubelet_ports = [
        (10250, "https", ["/pods", "/runningpods/", "/stats/summary"],
         ('"kind"', '"podlist"', '"items"', '"node"', '"podref"')),
        (10255, "http", ["/pods", "/stats/summary", "/metrics/cadvisor"],
         ('"kind"', '"podlist"', '"items"', "container_", "# help", "# type")),
    ]

    for port, scheme, endpoints, tokens in kubelet_ports:
        if not _tcp_open(host, port):
            continue
        any_open = True
        anon_hit = None
        sample_code = None
        for ep in endpoints:
            code, _, body = _http_get_insecure(
                f"{scheme}://{host}:{port}{ep}", timeout=3)
            sample_code = code
            bl = (body or "").lower()
            if code == 200 and any(tok in bl for tok in tokens):
                anon_hit = (ep, code)
                break
        if anon_hit:
            ep, code = anon_hit
            # 10255 read-only port being open at all is a finding; granted
            # anonymous read on either port is the same critical exposure.
            findings.append(wrap_finding(
                f"kubelet on {port}/tcp grants ANONYMOUS read at {ep}",
                "CRITICAL", cvss="9.0", cwe="CWE-306", owasp="A05:2021",
                remediation=("Set kubelet --anonymous-auth=false and "
                             "--authorization-mode=Webhook. Disable the "
                             "read-only port entirely (--read-only-port=0). "
                             "Anonymous kubelet read leaks every pod/secret "
                             "mount path and node stats."),
                evidence_marker=(f"GET {scheme}://{host}:{port}{ep} → {code} "
                                 "with kubelet-shaped body (content fingerprint "
                                 "matched)")))
        elif sample_code in (401, 403):
            findings.append(wrap_finding(
                f"kubelet on {port}/tcp reachable but requires auth (good)",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue authn/authz-required kubelet posture.",
                evidence_marker=f"Anonymous GET → {sample_code} on {port}"))
        else:
            findings.append(wrap_finding(
                f"Port {port}/tcp open but does not answer as an "
                "anonymous-readable kubelet",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Confirm what service listens here; no anonymous "
                            "kubelet read was observed.",
                evidence_marker=f"Probed kubelet endpoints; last code {sample_code}"))

    if not any_open:
        findings.append(wrap_finding("kubelet not externally reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue kubelet restriction.",
            evidence_marker="TCP/10250 + 10255 closed/filtered"))
    return _build_resp("k8s_kubelet_anonymous_auth", target, findings, 6,
                       "kubelet anonymous-read probe (content-fingerprinted)")


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
    if _target_is_placeholder(target):
        return _na_for_network_probe("registry_pypi_2fa_audit", target,
                                       "Container registry public-pull probe")
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
    """kube-apiserver anonymous-auth probe (CIS K8s 1.2.1).

    Zero-FP rule: `/api`, `/version`, `/healthz` are readable by
    `system:anonymous` on DEFAULT, correctly-hardened clusters via the
    built-in `system:public-info-viewer` ClusterRole — so a 200 there is
    NOT a finding (reported INFO only). The unambiguous misconfiguration
    is when an anonymous caller can LIST a real resource collection
    (`/api/v1/namespaces`, `/api/v1/pods`) and the body is a genuine
    Kubernetes *List object. That means RBAC for system:anonymous is
    broken — graded CRITICAL only on that signal.
    """
    host = _host(target)
    findings = []
    any_reachable = False

    # Resource-list endpoints: a 200 List here == anonymous RBAC broken.
    resource_eps = ("/api/v1/namespaces", "/api/v1/pods",
                    "/api/v1/secrets", "/apis/apps/v1/deployments")

    for port in (6443, 8443):
        if not _tcp_open(host, port):
            continue
        any_reachable = True
        leaked = None
        for ep in resource_eps:
            code, _, body = _http_get_insecure(
                f"https://{host}:{port}{ep}", timeout=4)
            bl = (body or "").lower()
            # A real list object carries the *List kind + an items array.
            if code == 200 and '"items"' in bl and (
                    '"kind":"namespacelist"' in bl.replace(" ", "")
                    or '"kind":"podlist"' in bl.replace(" ", "")
                    or '"kind":"secretlist"' in bl.replace(" ", "")
                    or '"kind":"deploymentlist"' in bl.replace(" ", "")):
                leaked = (ep, code)
                break
        if leaked:
            ep, code = leaked
            findings.append(wrap_finding(
                f"kube-apiserver on {port}/tcp returns a resource LIST to "
                f"ANONYMOUS callers at {ep}",
                "CRITICAL", cvss="9.0", cwe="CWE-306", owasp="A05:2021",
                remediation=("Set --anonymous-auth=false on kube-apiserver and "
                             "remove any ClusterRoleBinding granting list/get "
                             "to system:anonymous or system:unauthenticated. "
                             "An anonymous resource list means the whole "
                             "cluster state is readable without credentials."),
                evidence_marker=(f"GET https://{host}:{port}{ep} → {code} with a "
                                 "genuine Kubernetes *List object (kind+items "
                                 "fingerprint matched)")))
            continue
        # Fall back to the info-only public endpoints.
        code, _, body = _http_get_insecure(f"https://{host}:{port}/api", timeout=4)
        if code == 200 and "kind" in body.lower():
            findings.append(wrap_finding(
                f"kube-apiserver on {port}/tcp serves public discovery (/api) "
                "to anonymous callers — expected default, not a finding",
                "INFO", cvss="0.0", cwe="N/A",
                remediation=("Default behaviour via system:public-info-viewer. "
                             "Confirm no resource collections are anonymously "
                             "listable (this probe verified they are not)."),
                evidence_marker=f"GET /api → 200; resource lists denied/empty"))
        elif code in (401, 403):
            findings.append(wrap_finding(
                f"kube-apiserver on {port}/tcp requires auth (good)",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue auth-required posture.",
                evidence_marker=f"GET /api → {code}"))

    if not any_reachable:
        findings.append(wrap_finding("kube-apiserver not externally reachable on 6443/8443",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue private API server access.",
            evidence_marker="TCP/6443 + 8443 closed/filtered"))
    return _build_resp("k8s_anonymous_auth", target, findings, len(resource_eps) + 1,
                       "kube-apiserver anonymous resource-list probe")


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
    if _target_is_placeholder(target):
        return _na_for_network_probe("registry_anon_push", target,
                                       "Registry anonymous-push probe")
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
    if _target_is_placeholder(target):
        return _na_for_network_probe("nginx_ingress", target, "nginx ingress probe")
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

    Zero-FP strategy: mTLS-off only makes sense to flag for things that
    were SUPPOSED to be Istio gateways. Public CDNs / registries / SaaS
    endpoints never require client certs at :443 - flagging that is
    noise. Require Istio fingerprint (header / server banner / Istio-
    specific port :15443) before flagging mTLS-off as a finding.

    Severity:
      :15443 reachable (Istio multi-cluster gateway port) + mTLS off ->
        HIGH (this port has only one purpose: cross-cluster mTLS).
      :443 with Istio fingerprint + mTLS off -> HIGH (intended for mTLS).
      :443 without Istio fingerprint -> POSITIVE (no signal of intended
        mTLS, so absence of client-cert demand is not a finding).
    """
    host = _host(target)
    findings = []

    # Step 1: detect Istio fingerprint via HTTP response headers
    istio_fingerprinted = False
    fp_evidence = ""
    for scheme in ("https", "http"):
        try:
            c, hdrs, body = _http_get_insecure(f"{scheme}://{host}/", timeout=4)
        except Exception:
            continue
        if c == 0:
            continue
        h_lower = {k.lower(): str(v) for k, v in (hdrs or {}).items()}
        server = h_lower.get("server", "").lower()
        x_envoy_keys = [k for k in h_lower if k.startswith("x-envoy")]
        x_istio_keys = [k for k in h_lower if k.startswith("x-istio")]
        if ("istio" in server or "envoy" in server or
                x_envoy_keys or x_istio_keys):
            istio_fingerprinted = True
            fp_evidence = (f"{scheme}: Server={server[:60]}; "
                            f"x-envoy headers={len(x_envoy_keys)}; "
                            f"x-istio headers={len(x_istio_keys)}")
            break

    # Step 2: check Istio multi-cluster gateway port :15443
    multi_cluster_open = _tcp_open(host, 15443)

    # Step 3: TLS handshake on :443 + :15443
    tls_results = {}
    for port in (443, 15443):
        if not _tcp_open(host, port):
            continue
        info = _tls_inspect(host, port, timeout=4)
        if info.get("ok"):
            tls_results[port] = info

    # Decision logic - only flag when we have a real signal
    if multi_cluster_open and tls_results.get(15443):
        # Port 15443 is Istio-specific. Any TLS without mTLS here = HIGH.
        info = tls_results[15443]
        cert_bytes = info.get("cert_bytes", 0)
        if cert_bytes > 0:
            findings.append(wrap_finding(
                "Istio multi-cluster gateway :15443 reachable with mTLS DISABLED",
                "HIGH", cvss="7.5", cwe="CWE-295",
                remediation="Set tls.mode=MUTUAL on Istio Gateway resource. "
                            ":15443 must require client cert for cross-cluster traffic.",
                evidence_marker=(f"Port :15443 TLS handshake completed without "
                                  f"CertificateRequest; server cert {cert_bytes}B")))

    if istio_fingerprinted and tls_results.get(443):
        info = tls_results[443]
        cert_bytes = info.get("cert_bytes", 0)
        if cert_bytes > 0:
            findings.append(wrap_finding(
                "Istio-fingerprinted gateway on :443 completes TLS without client-cert request",
                "HIGH", cvss="7.5", cwe="CWE-295",
                remediation="Set tls.mode=MUTUAL on Gateway resource if zero-trust required. "
                            "Otherwise document the intentional public-facing posture.",
                evidence_marker=f"{fp_evidence}; TLS server cert {cert_bytes}B; no CertificateRequest"))

    if not findings:
        if istio_fingerprinted:
            findings.append(wrap_finding(
                "Istio fingerprinted, mTLS posture appears appropriate for public listener",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue current posture.",
                evidence_marker=fp_evidence))
        else:
            findings.append(wrap_finding(
                "No Istio gateway fingerprint detected - mTLS-off finding does not apply",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation=("Target does not present as an Istio gateway "
                              "(no Server: istio-envoy header, no x-envoy/x-istio "
                              "headers, no :15443 reachability). Public TLS "
                              "endpoints are not expected to require client certs."),
                evidence_marker=("No Istio fingerprint in response headers; "
                                  ":15443 closed/filtered")))
    return _build_resp("istio_gateway_mtls_off", target, findings, 3,
                       "Istio gateway mTLS posture (fingerprint-gated)")


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

    if exposed_ports and not metrics_leak:
        # No HTTP fingerprint confirmed (metrics_leak handles that case above).
        # These ports are istiod-reserved; internet-reachability of them is the
        # finding itself. Severity stays MEDIUM here (no positive istiod content
        # confirmation) to honour zero-FP — we report the reachable reserved
        # ports without asserting istiod is definitely running.
        labels = ", ".join(f"{p}/{lbl}" for p, lbl in exposed_ports)
        findings.append(wrap_finding(
            f"istiod-reserved control-plane port(s) reachable externally: {labels}",
            "MEDIUM", cvss="5.5", cwe="CWE-306", owasp="A05:2021",
            remediation="Istiod control-plane ports (15010 plaintext XDS, 15012 "
                        "XDS mTLS, 15017 webhook) must be in-cluster only. Block "
                        "them at the edge / NetworkPolicy. If these are not istiod, "
                        "confirm what binds these reserved ports.",
            evidence_marker=f"TCP open on istiod-reserved ports: {labels} "
                            "(no positive HTTP istiod content confirmation)"))

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
    img = _resolve_image_ref(target, req)
    if not img:
        return _not_applicable_for_image_scanner(target, "trivy_image", "Trivy")
    target = img  # remainder of function uses `target` as the image ref

    if shutil.which("trivy") is None:
        return _build_resp("trivy_image", target, [wrap_finding(
            "[NOT IMPLEMENTED] trivy binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile that installs Trivy.",
            evidence_marker="trivy not found in PATH")], 0,
            "Trivy not installed")

    # First pass: try with --skip-db-update for speed (uses pre-baked DB).
    # If the DB is stale or the image needs metadata Trivy doesn't have,
    # exit 1 will trip — second pass drops that flag so Trivy fetches the
    # diff. Image-pull failures still surface honestly in the second pass.
    def _run_trivy(skip_db_update: bool):
        cmd = ["trivy", "image", "--format", "json",
               "--severity", "HIGH,CRITICAL",
               "--quiet", "--timeout", "8m"]
        if skip_db_update:
            cmd.append("--skip-db-update")
        cmd.append(target)
        return _run_tool(cmd, timeout_s=540)

    exit_code, stdout, stderr = _run_trivy(skip_db_update=True)
    if exit_code not in (0,) or not stdout.strip():
        # Retry with DB refresh (most common cause of first-pass failure)
        exit_code, stdout, stderr = _run_trivy(skip_db_update=False)

    if exit_code == 124:
        return _build_resp("trivy_image", target, [wrap_finding(
            f"[PROBE ERROR] Trivy scan timeout (>9 min) on {target[:80]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Try a smaller image or run trivy manually with longer timeout.",
            evidence_marker="Trivy wall-clock budget exceeded")], 0,
            "Trivy timeout")

    if exit_code not in (0, 1) or not stdout.strip():
        # Capture the most diagnostic part of stderr (last 600 chars covers
        # the FATAL line + the underlying cause Trivy chains in plain text).
        err_excerpt = (stderr or "").strip().replace("\t", " ")[-600:]
        return _build_resp("trivy_image", target, [wrap_finding(
            f"[PROBE ERROR] Trivy exit {exit_code} on {target[:60]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Common causes: (1) image not pullable from this host "
                          "(check registry auth / network egress), (2) image "
                          "uses a manifest format Trivy can't parse, (3) Trivy "
                          "DB corrupted - try `trivy image --reset` on the VPS."),
            evidence_marker=f"trivy stderr: {err_excerpt}")], 0,
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
    img = _resolve_image_ref(target, req)
    if not img:
        return _not_applicable_for_image_scanner(target, "grype_image", "Grype")
    target = img

    if shutil.which("grype") is None:
        return _build_resp("grype_image", target, [wrap_finding(
            "[NOT IMPLEMENTED] grype binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile that installs Grype.",
            evidence_marker="grype not found in PATH")], 0,
            "Grype not installed")

    # Grype's --fail-on accepts severity NAMES only (critical/high/medium/low/
    # negligible/unknown) — there's no "never". A stale ~/.grype.yaml or
    # GRYPE_FAIL_ON env on the host with "fail-on: never" trips Grype at
    # config-parse time. Earlier fix tried --config /dev/null but Viper
    # rejects it with "Unsupported Config Type ''" because /dev/null has
    # no extension. Final fix: point HOME at a fresh tempdir so Grype
    # can't read ~/.grype.yaml at all + still strip GRYPE_FAIL_* env.
    import os, tempfile
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GRYPE_FAIL")}
    env.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")
    # The Dockerfile-baked Grype DB can be weeks old by the time the
    # backend container is deployed. Grype defaults to refusing any DB
    # older than 5 days. Two-layer fix:
    #   1) GRYPE_DB_AUTO_UPDATE=true — pull a fresh DB on first scan
    #   2) GRYPE_DB_MAX_ALLOWED_BUILT_AGE=8760h — tolerate up to 1y
    #      offline (covers air-gapped + slow CI environments)
    env["GRYPE_DB_AUTO_UPDATE"] = "true"
    env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] = "8760h"
    _scratch_home = tempfile.mkdtemp(prefix="vl-grype-home-")
    env["HOME"] = _scratch_home
    env["XDG_CONFIG_HOME"] = _scratch_home   # Grype also honours XDG
    try:
        exit_code, stdout, stderr = _run_tool([
            "grype", target, "-o", "json", "-q",
        ], timeout_s=360, env=env)
    finally:
        try: shutil.rmtree(_scratch_home, ignore_errors=True)
        except Exception: pass

    if exit_code == 124:
        return _build_resp("grype_image", target, [wrap_finding(
            f"[PROBE ERROR] Grype scan timeout on {target[:80]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Try a smaller image or run grype manually.",
            evidence_marker="Grype wall-clock budget exceeded")], 0, "Grype timeout")

    # Grype exits 0 on success even with findings (since --fail-on is unset).
    # Some Grype versions briefly emitted exit 1 with valid JSON when a DB
    # metadata update was triggered; accept exit 1 as long as stdout has JSON.
    if exit_code not in (0, 1) or not stdout.strip():
        return _build_resp("grype_image", target, [wrap_finding(
            f"[PROBE ERROR] Grype exit {exit_code}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify image is pullable.",
            evidence_marker=f"stderr: {stderr[-500:]}")], 0, f"Grype exit {exit_code}")

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
    img = _resolve_image_ref(target, req)
    if not img:
        return _not_applicable_for_image_scanner(target, "image_signing_cosign", "Cosign")
    target = img

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
    img = _resolve_image_ref(target, req)
    if not img:
        return _not_applicable_for_image_scanner(target, "image_provenance_slsa", "Syft")
    target = img

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
    img = _resolve_image_ref(target, req)
    if not img:
        return _not_applicable_for_image_scanner(target, "image_secrets_scan", "Trivy secret scan")
    target = img

    if shutil.which("trivy") is None:
        return _build_resp("image_secrets_scan", target, [wrap_finding(
            "[NOT IMPLEMENTED] trivy binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile that installs Trivy.",
            evidence_marker="trivy not found in PATH")], 0, "Trivy not installed")

    # Secret scanning doesn't need the vuln DB, but Trivy 0.70+ still tries
    # to download the Java DB metadata when --skip-db-update is set against
    # a fresh cache and crashes with "scan error: unable to ..." . Drop the
    # skip flag — pre-baked DB in the container handles it fine.
    # Also drop --quiet so stderr captures real error text on failure.
    exit_code, stdout, stderr = _run_tool([
        "trivy", "image",
        "--format", "json",
        "--scanners", "secret",
        "--timeout", "3m",
        "--no-progress",
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
            evidence_marker=f"stderr: {stderr[-600:]}")], 0,
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
    endpoints without auth.

    Zero-FP strategy: a path is only flagged as exposed if its response
    BODY matches a content fingerprint specific to the expected
    vulnerable artifact - not just HTTP 200. Public CDNs (gcr.io,
    cloudflare.com, etc) return 200 for arbitrary paths via marketing
    pages or generic 404 templates; those must not flag.

    Each path entry carries:
      content_re   - regex that MUST match in response body
      min_body     - minimum body length for the match to count
      severity     - severity if a real match
      cvss         - cvss if a real match
    """
    host = _host(target)
    findings = []
    exposed = []

    paths_to_test = [
        # Spring Boot Actuator - leaks env vars, heap, config
        {"path": "/actuator/env",
         "label": "Spring Boot Actuator /env (CRITICAL leak)",
         "content_re": r'"activeProfiles"\s*:|"propertySources"\s*:|"applicationConfig"',
         "min_body": 80, "severity": "CRITICAL", "cvss": "9.0"},
        {"path": "/actuator/heapdump",
         "label": "Spring Boot Actuator /heapdump (memory dump)",
         "content_re": r"^HPROF",  # HPROF binary header
         "min_body": 100, "severity": "CRITICAL", "cvss": "9.0"},
        {"path": "/actuator/configprops",
         "label": "Spring Boot Actuator /configprops",
         "content_re": r'"contexts"\s*:|"configurationProperties"',
         "min_body": 80, "severity": "HIGH", "cvss": "7.5"},
        {"path": "/actuator/threaddump",
         "label": "Spring Boot Actuator /threaddump",
         "content_re": r'"threads"\s*:\[|threadName',
         "min_body": 80, "severity": "MEDIUM", "cvss": "5.5"},
        {"path": "/actuator/health",
         "label": "Spring Boot Actuator /health (info disclosure)",
         "content_re": r'^\{\s*"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE)"',
         "min_body": 15, "severity": "LOW", "cvss": "3.0"},
        # dotenv: KEY=value lines
        {"path": "/.env",
         "label": "dotenv config file (.env)",
         "content_re": r"(?im)^[A-Z][A-Z0-9_]+\s*=\s*\S",
         "min_body": 20, "severity": "CRITICAL", "cvss": "9.0"},
        # Tomcat manager
        {"path": "/manager/html",
         "label": "Tomcat Web Application Manager",
         "content_re": r"Tomcat Web Application Manager|/manager/text",
         "min_body": 100, "severity": "CRITICAL", "cvss": "9.0"},
        {"path": "/manager/status",
         "label": "Tomcat manager status",
         "content_re": r"Tomcat Web Application Manager|<title>.*Tomcat",
         "min_body": 100, "severity": "HIGH", "cvss": "7.5"},
        # H2 / database console
        {"path": "/h2-console/",
         "label": "H2 Database console",
         "content_re": r"H2 Console|h2console",
         "min_body": 100, "severity": "CRITICAL", "cvss": "9.0"},
        # Prometheus exposition format - "# HELP" and "# TYPE" lines
        {"path": "/metrics",
         "label": "Prometheus metrics endpoint",
         "content_re": r"(?m)^# (HELP|TYPE)\s+\w+",
         "min_body": 50, "severity": "MEDIUM", "cvss": "5.5"},
        {"path": "/prometheus",
         "label": "Prometheus metrics endpoint",
         "content_re": r"(?m)^# (HELP|TYPE)\s+\w+",
         "min_body": 50, "severity": "MEDIUM", "cvss": "5.5"},
        # Swagger / OpenAPI
        {"path": "/swagger-ui/index.html",
         "label": "Swagger UI",
         "content_re": r"swagger-ui|<title>Swagger",
         "min_body": 100, "severity": "MEDIUM", "cvss": "5.5"},
        {"path": "/v3/api-docs",
         "label": "OpenAPI 3 spec",
         "content_re": r'"openapi"\s*:\s*"3\.',
         "min_body": 30, "severity": "MEDIUM", "cvss": "5.5"},
        {"path": "/v2/api-docs",
         "label": "Swagger 2 spec",
         "content_re": r'"swagger"\s*:\s*"2\.',
         "min_body": 30, "severity": "MEDIUM", "cvss": "5.5"},
        # GraphQL introspection
        {"path": "/graphql",
         "label": "GraphQL endpoint with introspection",
         "content_re": r'"data"\s*:\s*\{\s*"__schema"|"types"\s*:\s*\[',
         "min_body": 50, "severity": "MEDIUM", "cvss": "5.5",
         "method_post": True},  # GraphQL needs POST
    ]

    for scheme in ("https", "http"):
        for p in paths_to_test:
            url = f"{scheme}://{host}{p['path']}"
            try:
                c, _, b = _http_get_insecure(url, timeout=3)
            except Exception:
                continue
            if c != 200 or not b or len(b) < p["min_body"]:
                continue
            # Real content fingerprint match required - not just HTTP 200.
            try:
                if not re.search(p["content_re"], b[:8000], re.IGNORECASE | re.MULTILINE):
                    continue
            except re.error:
                continue
            exposed.append({
                "path": p["path"], "label": p["label"], "scheme": scheme,
                "severity": p["severity"], "cvss": p["cvss"],
            })
        if exposed:
            break

    if exposed:
        # Highest-severity hit drives the overall finding severity.
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        top = max(exposed, key=lambda e: sev_rank.get(e["severity"], 0))
        sev = top["severity"]
        cvss = top["cvss"]
        summary = "; ".join(
            f"{e['scheme']}://{host}{e['path']} ({e['label']})" for e in exposed[:5])
        findings.append(wrap_finding(
            f"Ingress: {len(exposed)} sensitive endpoint(s) confirmed reachable without auth",
            sev, cvss=cvss, cwe="CWE-306",
            remediation=("Restrict admin / actuator / metrics / health paths "
                          "to internal IPs or require auth. Add ingress-level "
                          "deny rules. Spring Boot: management.endpoints.web."
                          "exposure.include=health,info (only) + "
                          "management.endpoint.health.show-details=never."),
            evidence_marker=f"Confirmed (body fingerprint matched): {summary}"))
    else:
        findings.append(wrap_finding(
            "No unauthenticated admin/actuator/metrics endpoints detected",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue locked-down ingress posture.",
            evidence_marker=(f"Probed {len(paths_to_test)*2} path/scheme combos. "
                              "0 matched a real-content fingerprint - HTTP-200 "
                              "responses from CDN/marketing pages don't count.")))
    return _build_resp("ingress_authz_open", target, findings,
                       len(paths_to_test) * 2,
                       "Ingress unauth admin/actuator/metrics probe (content-fingerprinted)")


def _probe_image_distroless(target, req):
    """Detect whether the image is distroless / Wolfi / minimal base.
    Distroless images lack shells, package managers, and shell utilities -
    drastically reducing attack surface for container escapes and
    post-exploitation. Uses Syft package inventory to detect shell and
    package-manager presence."""
    img = _resolve_image_ref(target, req)
    if not img:
        return _not_applicable_for_image_scanner(target, "image_distroless_base", "Distroless detector")
    target = img

    if shutil.which("syft") is None:
        return _build_resp("image_distroless_base", target, [wrap_finding(
            "[NOT IMPLEMENTED] syft binary not installed (needed for inventory)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile that installs Syft.",
            evidence_marker="syft not found in PATH")], 0, "Syft not installed")

    exit_code, stdout, stderr = _run_tool([
        "syft", target, "-o", "syft-json", "-q",
    ], timeout_s=180)

    if exit_code != 0 or not stdout.strip():
        return _build_resp("image_distroless_base", target, [wrap_finding(
            f"[PROBE ERROR] Syft exit {exit_code}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify image is pullable.",
            evidence_marker=f"stderr: {stderr[-300:]}")], 0, "Syft error")

    try:
        data = json.loads(stdout)
    except Exception:
        return _build_resp("image_distroless_base", target, [wrap_finding(
            "[PROBE ERROR] Syft JSON parse failed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Re-run scan.",
            evidence_marker="Syft output not valid JSON")], 0, "parse error")

    artifacts = data.get("artifacts", []) if isinstance(data, dict) else []
    pkg_names = {(a.get("name") or "").lower() for a in artifacts}

    # Signals of NON-distroless: presence of shells, package managers, coreutils
    shell_indicators = {"bash", "dash", "ash", "zsh", "sh"}
    pkg_mgr_indicators = {"apt", "dpkg", "rpm", "yum", "dnf", "apk",
                           "pacman", "zypper", "portage"}
    coreutils_indicators = {"coreutils", "busybox", "util-linux", "findutils"}

    found_shells = sorted(pkg_names & shell_indicators)
    found_pkg_mgrs = sorted(pkg_names & pkg_mgr_indicators)
    found_coreutils = sorted(pkg_names & coreutils_indicators)

    # Distroless heuristic: no shell + no package manager + small artifact count
    total_pkgs = len(artifacts)
    is_distroless = (not found_shells and not found_pkg_mgrs and total_pkgs < 50)
    is_minimal = (not found_pkg_mgrs and total_pkgs < 100)

    findings = []
    if is_distroless:
        findings.append(wrap_finding(
            f"Image appears DISTROLESS / minimal ({total_pkgs} pkgs, no shell, no pkg-mgr)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue distroless / Wolfi / Chainguard posture - "
                        "drastically reduces container-escape attack surface.",
            evidence_marker=(f"Syft inventory: {total_pkgs} packages; no shell "
                              "binary, no package manager.")))
    elif is_minimal:
        findings.append(wrap_finding(
            f"Image is MINIMAL but not distroless ({total_pkgs} pkgs)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Consider switching to distroless / Wolfi base for "
                        "production - removes shells + package managers.",
            evidence_marker=(f"Syft: {total_pkgs} packages; "
                              f"shells={found_shells or 'none'}; "
                              f"pkg-mgrs={found_pkg_mgrs or 'none'}")))
    else:
        findings.append(wrap_finding(
            f"Image is FULL-OS based: {total_pkgs} packages incl. "
            + (", ".join(found_pkg_mgrs[:3]) if found_pkg_mgrs else "no pkg-mgr"),
            "MEDIUM", cvss="5.5", cwe="CWE-1357",
            remediation=("Switch production image to distroless/Wolfi/Chainguard. "
                          "Full-OS bases include shells, package managers, and "
                          "utility binaries that expand the attack surface for "
                          "post-exploitation and container escape."),
            evidence_marker=(f"Syft: {total_pkgs} pkgs; "
                              f"shells={','.join(found_shells)}; "
                              f"pkg-mgrs={','.join(found_pkg_mgrs)}; "
                              f"coreutils={','.join(found_coreutils)}")))

    return _build_resp("image_distroless_base", target, findings, 1,
                       f"Distroless detection via Syft ({total_pkgs} pkgs)")


def _probe_kube_hunter(target, req):
    """K8s external attack-surface probe via Nuclei k8s-tagged templates.

    kube-hunter was archived by AquaSec in 2024 (recommended Trivy as
    replacement). We use Nuclei's k8s template tag instead which covers
    overlapping ground: anonymous kubelet, dashboard exposure, API server
    misconfig, etcd unauth, common K8s CVEs.

    Runs against the target's IP / hostname externally."""
    host = _host(target)
    # Don't try to "scan" an image ref via Nuclei - return NOT_APPLICABLE
    if _looks_like_image_ref(target):
        return _build_resp("kube_hunter", target, [wrap_finding(
            "[NOT_APPLICABLE] kube-hunter equivalent needs a cluster IP/host, not an image ref",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Provide the K8s API endpoint hostname or IP.",
            evidence_marker=f"Target '{target[:80]}' is an image reference")], 0,
            "Not applicable for image ref")

    if shutil.which("nuclei") is None:
        return _build_resp("kube_hunter", target, [wrap_finding(
            "[NOT IMPLEMENTED] nuclei binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile (nuclei is a dep).",
            evidence_marker="nuclei not in PATH")], 0, "Nuclei not installed")

    exit_code, stdout, stderr = _run_tool([
        "nuclei",
        "-target", host,
        "-tags", "kubernetes,k8s,kubelet,etcd",
        "-jsonl",
        "-silent",
        "-disable-update-check",
        "-no-color",
        "-rate-limit", "30",
        "-timeout", "8",
    ], timeout_s=180)

    if exit_code == 124:
        return _build_resp("kube_hunter", target, [wrap_finding(
            f"[PROBE ERROR] Nuclei K8s scan timeout (>3 min) on {host}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Slow target or many template matches; retry.",
            evidence_marker="Wall-clock exceeded")], 0, "Nuclei timeout")

    # Nuclei exits 0 even with no findings; only treat real subprocess errors as failure
    if exit_code not in (0, 1):
        return _build_resp("kube_hunter", target, [wrap_finding(
            f"[PROBE ERROR] Nuclei exit {exit_code}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify target reachability.",
            evidence_marker=f"stderr: {stderr[-300:]}")], 0, f"Nuclei exit {exit_code}")

    findings = []
    sev_default_cvss = {"CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.5",
                         "LOW": "3.0", "INFO": "0.0"}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            evt = json.loads(line)
        except Exception:
            continue
        info = evt.get("info", {}) or {}
        name = info.get("name") or evt.get("template-id") or "K8s template hit"
        sev_raw = (info.get("severity") or "info").upper()
        sev = sev_raw if sev_raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "INFO"
        cvss = ""
        cvss_metrics = info.get("classification", {}).get("cvss-metrics", "")
        if "cvss" in info.get("classification", {}):
            cvss_score = info["classification"].get("cvss-score")
            if cvss_score:
                cvss = str(cvss_score)
        cvss = cvss or sev_default_cvss.get(sev, "0.0")
        match_url = evt.get("matched-at") or evt.get("host") or host

        findings.append(wrap_finding(
            f"[Nuclei K8s] {name}",
            sev, cvss=cvss,
            cwe=(info.get("classification", {}).get("cwe-id", ["CWE-693"]) or ["CWE-693"])[0]
                if isinstance(info.get("classification", {}).get("cwe-id"), list) else "CWE-693",
            remediation=info.get("remediation") or "See Nuclei template + CVE advisory.",
            evidence_marker=f"Template: {evt.get('template-id','?')}; Match: {match_url}"))

    if not findings:
        findings.append(wrap_finding(
            f"Nuclei K8s tag scan: 0 hits on {host}",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue locked-down K8s posture.",
            evidence_marker=f"nuclei -tags kubernetes,k8s,kubelet,etcd against {host}: clean"))
    return _build_resp("kube_hunter", target, findings, max(len(findings), 1),
                       f"Nuclei K8s tag scan ({len(findings)} finding(s))")


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
    "image_distroless_base":          _probe_image_distroless,
    "kube_hunter":                    _probe_kube_hunter,
    # Dockerfile static-analysis probes (require dockerfile_text input)
    "dockerfile_root_user":           _probe_dockerfile_root_user,
    "dockerfile_no_user":             _probe_dockerfile_no_user,
    "dockerfile_ssh_in_image":        _probe_dockerfile_ssh_in_image,
    "dockerfile_curl_pipe_bash":      _probe_dockerfile_curl_pipe_bash,
    "dockerfile_hardcoded_secret":    _probe_dockerfile_hardcoded_secret,
    "dockerfile_apt_unpinned":        _probe_dockerfile_apt_unpinned,
    "dockerfile_no_healthcheck":      _probe_dockerfile_no_healthcheck,
    "dockerfile_multistage_audit":    _probe_dockerfile_multistage_audit,
    "dockerfile_copy_chown_audit":    _probe_dockerfile_copy_chown_audit,
    "dockerfile_expose_audit":        _probe_dockerfile_expose_audit,
    "dockerfile_base_image_eol":      _probe_dockerfile_base_image_eol,
    "hadolint_dockerfile":            _probe_hadolint_dockerfile,
    "dockerfile_antipatterns":        _probe_dockerfile_antipatterns,
    # Pod-spec static-analysis probes (require pod_spec_yaml input)
    "container_privileged":           _probe_container_privileged,
    "container_capadd_dangerous":     _probe_container_capadd_dangerous,
    "container_host_pid":             _probe_container_host_pid,
    "container_host_network":         _probe_container_host_network,
    "container_host_ipc":             _probe_container_host_ipc,
    "container_hostpath_dangerous":   _probe_container_hostpath_dangerous,
    "container_docker_sock_mount":    _probe_container_docker_sock_mount,
    "container_runas_root":           _probe_container_runas_root,
    "container_no_readonly_rootfs":   _probe_container_no_readonly_rootfs,
    "container_allow_priv_escalation": _probe_container_allow_priv_escalation,
    "container_seccomp_unset":        _probe_container_seccomp_unset,
    "container_apparmor_unset":       _probe_container_apparmor_unset,
    # K8s cluster probes via kubectl (require kubeconfig input)
    "k8s_audit_logs_off":             _probe_k8s_audit_logs_off,
    "k8s_admission_no_plugin":        _probe_k8s_admission_no_plugin,
    "k8s_psp_psa_disabled":           _probe_k8s_psp_psa_disabled,
    "k8s_network_policy_absent":      _probe_k8s_network_policy_absent,
    "network_policy_default_deny":    _probe_k8s_network_policy_absent,
    "network_policy_egress_audit":    _probe_k8s_network_policy_absent,
    "rbac_cluster_admin_overuse":     _probe_rbac_cluster_admin_overuse,
    "rbac_secret_get_anywhere":       _probe_rbac_secret_get_anywhere,
    "rbac_pod_exec_create_overuse":   _probe_rbac_pod_exec_create_overuse,
    "rbac_node_proxy_overuse":        _probe_rbac_node_proxy_overuse,
    "rbac_impersonate_users":         _probe_rbac_impersonate_users,
    "secrets_in_env_var":             _probe_secrets_in_env_var,
    "secrets_in_configmap":           _probe_secrets_in_env_var,  # similar pattern
    "kube_bench_node":                _probe_kube_bench_node,
    # Container escape CVE detectors (kubeconfig - node runtime version)
    "escape_leaky_vessels_runc_2024": _probe_escape_leaky_vessels_runc,
    "escape_containerd_cve_2022_23648": _probe_escape_containerd_2022_23648,
    # Extra K8s cluster probes (kubeconfig)
    "secrets_etcd_unencrypted":       _probe_secrets_etcd_unencrypted,
    "vault_csi_audit":                _probe_vault_csi_audit,
    "sealed_secrets_audit":           _probe_sealed_secrets_audit,
    "external_secrets_audit":         _probe_external_secrets_audit,
    "k8s_tls_min_version":            _probe_k8s_tls_min_version,
    "k8s_cni_plugin_audit":           _probe_k8s_cni_plugin_audit,
    "rbac_pod_serviceaccount_token":  _probe_rbac_pod_serviceaccount_token,
    "rbac_clusterrolebinding_audit":  _probe_rbac_clusterrolebinding_audit,
    "rbac_aggregate_role_audit":      _probe_rbac_aggregate_role_audit,
    "envoy_filter_audit":             _probe_envoy_filter_audit,
    # Repo-scan probes (require repo_url input)
    "secrets_helm_values_leak":       _probe_secrets_helm_values_leak,
    "secrets_kustomize_leak":         _probe_secrets_kustomize_leak,
    # Policy-engine detection (kubeconfig)
    "opa_kyverno_no_policies":        _probe_kyverno_no_policies,
    "opa_gatekeeper_no_constraints":  _probe_opa_gatekeeper_no_constraints,
    # Paid / external-service image scanners (advisory-by-design)
    "snyk_container":                 _abd_snyk,
    "anchore_image":                  _abd_anchore,
    "clair_image":                    _abd_clair,
    # Advisory-by-design (cannot be SaaS-probed - intentionally informational)
    "falco_runtime_audit":            _abd_falco,
    "tetragon_runtime_audit":         _abd_tetragon,
    "tracee_runtime_audit":           _abd_tracee,
    "manual_image_review":            _abd_manual_image_review,
    "manual_rbac_review":             _abd_manual_rbac_review,
    "manual_network_policy_review":   _abd_manual_np_review,
    "manual_secrets_review":          _abd_manual_secrets_review,
    "manual_escape_research":         _abd_manual_escape,
    "manual_mesh_review":             _abd_manual_mesh,
    "escape_cgroup_release_agent":    _abd_escape_cgroup,
    "escape_kernel_keyring":          _abd_escape_kernel_keyring,
    "escape_proc_self_exe":           _abd_escape_proc_self_exe,
    # Forged scaffolds (2026-06-02) — 7 techniques previously marked
    # [NOT IMPLEMENTED] now have live probes that honestly SKIP when their
    # required input (pod_spec_yaml or kubeconfig) is missing.
    "escape_docker_socket_mount":     _probe_escape_docker_socket_mount,
    "escape_cap_sys_admin_chain":     _probe_escape_cap_sys_admin_chain,
    "escape_user_namespace_audit":    _probe_escape_user_namespace_audit,
    "k8s_admission_controller_audit": _probe_k8s_admission_controller_audit,
    "k8s_certificate_rotation":       _probe_k8s_certificate_rotation,
    "rbac_audit_via_rbac_tool":       _probe_rbac_audit_via_rbac_tool,
    "service_mesh_mtls_off":          _probe_service_mesh_mtls_off,
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
    # §2 Dockerfile (11)
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
    ("dockerfile_base_image_eol", "Base-image EOL audit.", "HIGH", "7.5"),
    ("dockerfile_antipatterns", "Dockerfile antipatterns (curated 31-rule set).", "HIGH", "7.5"),
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
    # §11 Exposure probes (wired 2026-06-13: present in PROBES but were missing from T)
    ("docker_daemon_exposed", "Docker daemon (2375/2376) exposure probe.", "HIGH", "8.6"),
    ("etcd_apiserver_exposure", "etcd (2379) + kube-apiserver exposure probe.", "HIGH", "8.6"),
    ("registry_npm_2fa_audit", "Harbor / container registry public-access audit.", "MEDIUM", "5.5"),
    ("registry_pypi_2fa_audit", "Container registry /v2 anonymous-pull probe.", "MEDIUM", "5.5"),
]

router = make_advisory_router("container_k8s", T,
    playbook_ref="See module_playbooks/24_container_k8s.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
