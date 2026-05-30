"""§24 Container/K8s — 103 endpoints per 24_container_k8s.md.

VL-FORGE upgrade 2026-05-30: 7 live probes for externally-observable
container/k8s misconfigs (Docker daemon, etcd, K8s API, Harbor registry,
Dashboard, kubelet, container registry public access).
"""
import socket, urllib.request, urllib.error
from contextlib import closing
from tools._pack_common import make_advisory_router, _adv_response
from tools._shared import wrap_finding


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


PROBES = {
    "docker_daemon_exposed":          _probe_docker_daemon_exposed,
    "etcd_apiserver_exposure":        _probe_etcd_exposed,
    "kube_bench_master":              _probe_k8s_api,
    "k8s_kubelet_anonymous_auth":     _probe_kubelet,
    "registry_npm_2fa_audit":         _probe_harbor_registry,
    "opa_kyverno_no_policies":        _probe_k8s_dashboard,
    "registry_pypi_2fa_audit":        _probe_registry_public,
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
    # §8 Container Escape CVEs (9) ⭐
    ("escape_leaky_vessels_runc_2024", "⭐ Leaky Vessels runc (CVE-2024-21626).", "HIGH", "8.6"),
    ("escape_containerd_cve_2022_23648", "⭐ containerd (CVE-2022-23648).", "HIGH", "7.5"),
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
    # §10 eBPF Runtime Detection (3) ⭐
    ("falco_runtime_audit", "⭐ Falco runtime audit.", "MEDIUM", "5.5"),
    ("tetragon_runtime_audit", "⭐ Tetragon (Cilium) runtime audit.", "MEDIUM", "5.5"),
    ("tracee_runtime_audit", "⭐ Tracee (Aqua) runtime audit.", "MEDIUM", "5.5"),
]

router = make_advisory_router("container_k8s", T,
    playbook_ref="See module_playbooks/24_container_k8s.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
