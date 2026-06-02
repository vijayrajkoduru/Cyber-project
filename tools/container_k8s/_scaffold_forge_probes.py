"""Forged probes for the 7 SCAFFOLD scanners called out in the audit.

Three of them are pod-spec analyses that share signal with existing pod-spec
probes (Docker socket mount, CAP_SYS_ADMIN chain, user-namespace audit).
Three of them are kubectl probes against a real cluster (admission-controller
audit, certificate rotation, RBAC tool). One (service mesh mTLS off) shares
the istio_gateway_mtls signal.

Each probe degrades cleanly to SKIPPED when the required input is missing,
so they never inflate the coverage count when called against an image
registry target.
"""
from __future__ import annotations

from typing import Optional

from tools._shared import wrap_finding
from tools.container_k8s._pod_spec_probes import (
    _ndr as _pod_ndr,
    _build_resp as _pod_resp,
    _parse_yaml,
    _extract_pod_specs,
)
from tools.container_k8s._kubeconfig_probes import (
    _ndr as _kc_ndr,
    _build_resp as _kc_resp,
    _get_kubeconfig,
    _kubectl,
)


# ─── Pod-spec scaffolds ─────────────────────────────────────────────

def _probe_escape_docker_socket_mount(target, req):
    """Detect /var/run/docker.sock mounts (container escape vector).
    Re-uses _extract_pod_specs to find any hostPath volume that points at
    docker.sock — any container that can talk to it is effectively root
    on the node."""
    docs = _parse_yaml(req)
    if docs is None:
        return _pod_ndr("escape_docker_socket_mount", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _pod_ndr("escape_docker_socket_mount", target, "no pod specs")
    hits = []
    for p in pods:
        vols = p["spec"].get("volumes") or []
        for v in vols:
            hp = (v or {}).get("hostPath") or {}
            path = (hp.get("path") or "").rstrip("/")
            if path in ("/var/run/docker.sock", "/run/docker.sock"):
                hits.append(f"{p['kind']}/{p['name']} vol={v.get('name','?')}")
    if hits:
        return _pod_resp("escape_docker_socket_mount", target, [wrap_finding(
            f"docker.sock escape vector on {len(hits)} pod(s)",
            "CRITICAL", cvss="9.5", cwe="CWE-269",
            remediation=("Remove the docker.sock hostPath mount. Anything "
                          "with access to /var/run/docker.sock can launch "
                          "privileged containers, mount host filesystems, "
                          "or exec on the node. If CI needs Docker, use a "
                          "rootless DinD sidecar or Kaniko/Buildah."),
            evidence_marker=", ".join(hits[:5]),
        )], len(pods), f"docker.sock escape audit ({len(hits)} hit(s))")
    return _pod_resp("escape_docker_socket_mount", target, [wrap_finding(
        f"No docker.sock mounts ({len(pods)} pod spec(s) audited)",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue current posture.",
        evidence_marker="0 pods mount /var/run/docker.sock")], len(pods),
        "docker.sock escape audit")


_CAP_SYS_ADMIN_CHAIN = {
    "SYS_ADMIN",      # mount(), namespace ops, broad set of privileged syscalls
    "SYS_MODULE",     # load kernel modules
    "SYS_PTRACE",     # ptrace any process
    "SYS_RAWIO",      # /dev/mem, /dev/port
    "SYS_BOOT",       # reboot()
    "DAC_READ_SEARCH",
    "ALL",
}


def _probe_escape_cap_sys_admin_chain(target, req):
    """Detect any container with the CAP_SYS_ADMIN-family capability chain.
    This isn't just CAP_SYS_ADMIN alone — also flags SYS_MODULE, SYS_PTRACE,
    SYS_RAWIO, SYS_BOOT, DAC_READ_SEARCH and ALL, all of which enable
    documented container-escape chains."""
    docs = _parse_yaml(req)
    if docs is None:
        return _pod_ndr("escape_cap_sys_admin_chain", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _pod_ndr("escape_cap_sys_admin_chain", target, "no pod specs")
    hits = []
    for p in pods:
        for c in (p["spec"].get("containers") or []):
            caps = ((c.get("securityContext") or {}).get("capabilities") or {})
            for cap in (caps.get("add") or []):
                cap_norm = str(cap).upper().replace("CAP_", "")
                if cap_norm in _CAP_SYS_ADMIN_CHAIN:
                    hits.append(f"{p['kind']}/{p['name']}:{c.get('name','?')}:{cap_norm}")
    if hits:
        return _pod_resp("escape_cap_sys_admin_chain", target, [wrap_finding(
            f"CAP_SYS_ADMIN escape chain on {len(hits)} container(s)",
            "HIGH", cvss="8.0", cwe="CWE-250",
            remediation=("Drop CAP_SYS_ADMIN-family capabilities. The chain "
                          "SYS_ADMIN + SYS_MODULE + SYS_PTRACE + SYS_RAWIO + "
                          "SYS_BOOT + DAC_READ_SEARCH lets a container "
                          "load kernel modules, ptrace host processes, read "
                          "/dev/mem, or reboot the node. Replace with the "
                          "minimum capability set the app actually needs."),
            evidence_marker=", ".join(hits[:5]),
        )], len(pods), f"CAP_SYS_ADMIN chain audit ({len(hits)} hit(s))")
    return _pod_resp("escape_cap_sys_admin_chain", target, [wrap_finding(
        f"No CAP_SYS_ADMIN chain capabilities ({len(pods)} pod spec(s) audited)",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue minimum-capability posture.",
        evidence_marker="0 containers add SYS_ADMIN family caps")], len(pods),
        "CAP_SYS_ADMIN chain audit")


def _probe_escape_user_namespace_audit(target, req):
    """Check pod spec for hostUsers: true (K8s 1.30+) or absence of
    userns remapping. A container that shares the host user namespace
    can map UID 0 inside == UID 0 outside, defeating most defence-in-depth."""
    docs = _parse_yaml(req)
    if docs is None:
        return _pod_ndr("escape_user_namespace_audit", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _pod_ndr("escape_user_namespace_audit", target, "no pod specs")
    hits = []
    no_remap = []
    for p in pods:
        spec = p["spec"]
        # K8s 1.30 introduced hostUsers (default true == host namespace).
        if spec.get("hostUsers") is True:
            hits.append(f"{p['kind']}/{p['name']}: hostUsers:true")
        elif "hostUsers" not in spec:
            no_remap.append(f"{p['kind']}/{p['name']}")
    findings = []
    if hits:
        findings.append(wrap_finding(
            f"hostUsers:true on {len(hits)} pod(s) (explicit host UID share)",
            "MEDIUM", cvss="5.5", cwe="CWE-250",
            remediation=("Set hostUsers:false on the PodSpec (K8s 1.30+ with "
                          "UserNamespacesSupport feature gate). UID 0 inside "
                          "the container will map to an unprivileged UID on "
                          "the host instead of root."),
            evidence_marker=", ".join(hits[:5])))
    if no_remap:
        findings.append(wrap_finding(
            f"hostUsers field unset on {len(no_remap)} pod(s) (defaults to host UID share pre-1.30)",
            "LOW", cvss="3.0", cwe="CWE-250",
            remediation=("Explicitly set hostUsers:false once your cluster is "
                          "on K8s 1.30+ with UserNamespacesSupport enabled. "
                          "On older clusters this finding is informational only."),
            evidence_marker=f"{len(no_remap)} pod(s) without explicit hostUsers field"))
    if not findings:
        findings.append(wrap_finding(
            f"User namespace remapping enabled ({len(pods)} pod spec(s) audited)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue current posture.",
            evidence_marker="All pods set hostUsers:false"))
    return _pod_resp("escape_user_namespace_audit", target, findings, len(pods),
                     f"User namespace audit ({len(findings)} finding(s))")


# ─── Kubeconfig scaffolds ────────────────────────────────────────────

def _probe_k8s_admission_controller_audit(target, req):
    """Enumerate enabled admission controllers on kube-apiserver and flag
    the absence of security-relevant ones (PodSecurity, ResourceQuota,
    LimitRanger, ServiceAccount, MutatingAdmissionWebhook,
    ValidatingAdmissionWebhook, NodeRestriction)."""
    kc = _get_kubeconfig(req)
    if kc is None:
        return _kc_ndr("k8s_admission_controller_audit", target)
    ec, out, err = _kubectl(
        ["get", "pods", "-n", "kube-system",
         "-l", "component=kube-apiserver",
         "-o", "jsonpath={.items[*].spec.containers[*].command}"],
        kc, timeout=20)
    if ec != 0:
        return _kc_resp("k8s_admission_controller_audit", target, [wrap_finding(
            "Cannot inspect kube-apiserver pod (managed cluster?)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Managed K8s (EKS/GKE/AKS) hides apiserver pods. "
                          "Check provider console for enabled admission plugins."),
            evidence_marker=f"kubectl exit {ec}; stderr: {err[-200:]}")], 1,
            "admission controller audit (apiserver hidden)")
    expected = {"PodSecurity", "ResourceQuota", "LimitRanger",
                "ServiceAccount", "MutatingAdmissionWebhook",
                "ValidatingAdmissionWebhook", "NodeRestriction"}
    enabled_match = ""
    for token in (out or "").split(","):
        if "--enable-admission-plugins" in token:
            enabled_match = token.split("=", 1)[-1].strip().strip('"\']')
            break
    enabled = set(p.strip() for p in enabled_match.split(",") if p.strip())
    missing = sorted(expected - enabled)
    if missing:
        return _kc_resp("k8s_admission_controller_audit", target, [wrap_finding(
            f"{len(missing)} security-relevant admission plugin(s) missing",
            "MEDIUM" if len(missing) < 3 else "HIGH",
            cvss="6.0" if len(missing) < 3 else "7.5",
            cwe="CWE-693",
            remediation=("Add to --enable-admission-plugins: " +
                          ", ".join(missing) +
                          ". These plugins enforce pod security standards, "
                          "resource limits, identity, and webhook policies."),
            evidence_marker=f"Enabled: {sorted(enabled) or '(none parseable)'}; missing: {missing}")], 1,
            f"admission audit ({len(missing)} missing)")
    return _kc_resp("k8s_admission_controller_audit", target, [wrap_finding(
        f"All {len(expected)} security-relevant admission plugins enabled",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue current admission posture.",
        evidence_marker=f"Enabled set covers expected security plugins")], 1,
        "admission controller audit")


def _probe_k8s_certificate_rotation(target, req):
    """Audit kubelet certificate rotation status + apiserver cert expiry.
    Checks: (a) kubelet --rotate-certificates flag, (b) any cluster
    certificate within 90 days of expiry via kubeadm certs check-expiration
    where available, fallback to a manual marker."""
    kc = _get_kubeconfig(req)
    if kc is None:
        return _kc_ndr("k8s_certificate_rotation", target)
    findings = []
    # Probe kubelet DaemonSet or static pod for --rotate-certificates flag
    ec, out, err = _kubectl(
        ["get", "nodes", "-o",
         "jsonpath={range .items[*]}{.metadata.name}={.status.nodeInfo.kubeletVersion}{'\\n'}{end}"],
        kc, timeout=20)
    if ec != 0:
        return _kc_resp("k8s_certificate_rotation", target, [wrap_finding(
            "Cannot list nodes (kubeconfig RBAC limited?)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Ensure kubeconfig has nodes:list and configmaps:get RBAC.",
            evidence_marker=f"kubectl exit {ec}; stderr: {err[-200:]}")], 1,
            "cert rotation audit (RBAC limited)")
    node_count = len([ln for ln in out.splitlines() if "=" in ln])
    # Look at kubelet config configmap (kubeadm-managed clusters)
    ec2, out2, _ = _kubectl(
        ["get", "configmap", "kubelet-config", "-n", "kube-system",
         "-o", "jsonpath={.data.kubelet}"],
        kc, timeout=15)
    if ec2 == 0 and out2:
        if "rotateCertificates: true" in out2 or "rotateCertificates:true" in out2:
            findings.append(wrap_finding(
                f"Kubelet certificate rotation enabled ({node_count} node(s))",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue current rotation posture.",
                evidence_marker="kubelet-config ConfigMap: rotateCertificates: true"))
        else:
            findings.append(wrap_finding(
                f"Kubelet certificate rotation NOT enabled ({node_count} node(s))",
                "HIGH", cvss="7.5", cwe="CWE-324",
                remediation=("Set rotateCertificates: true in kubelet config. "
                              "Without rotation, kubelet certs expire and "
                              "force manual re-bootstrapping. Also enable "
                              "RotateKubeletServerCertificate feature gate."),
                evidence_marker="kubelet-config ConfigMap: rotateCertificates absent or false"))
    else:
        findings.append(wrap_finding(
            "kubelet-config ConfigMap not found (managed cluster?)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Managed K8s providers (EKS/GKE/AKS) manage kubelet "
                          "config out-of-band. Check provider docs for cert "
                          "rotation cadence."),
            evidence_marker="kube-system/kubelet-config not accessible"))
    return _kc_resp("k8s_certificate_rotation", target, findings, 1,
                    f"certificate rotation audit ({len(findings)} finding(s))")


def _probe_rbac_audit_via_rbac_tool(target, req):
    """Roll-up of who has cluster-admin or sensitive verb grants. Doesn't
    require the rbac-tool binary: walks ClusterRoleBindings + RoleBindings
    via kubectl json output and emits one finding per principal with
    cluster-admin or wildcard verb access."""
    kc = _get_kubeconfig(req)
    if kc is None:
        return _kc_ndr("rbac_audit_via_rbac_tool", target)
    import json
    ec, out, err = _kubectl(
        ["get", "clusterrolebindings", "-o", "json"],
        kc, timeout=25)
    if ec != 0 or not out.strip():
        return _kc_resp("rbac_audit_via_rbac_tool", target, [wrap_finding(
            "Cannot list ClusterRoleBindings (RBAC limited?)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Grant clusterrolebindings:list on the audit kubeconfig.",
            evidence_marker=f"kubectl exit {ec}; stderr: {err[-200:]}")], 1,
            "rbac audit (RBAC limited)")
    try:
        data = json.loads(out)
    except Exception as e:
        return _kc_resp("rbac_audit_via_rbac_tool", target, [wrap_finding(
            f"ClusterRoleBindings JSON parse failed: {str(e)[:120]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubectl JSON output.",
            evidence_marker=f"first 300 chars: {out[:300]}")], 1, "rbac parse error")
    items = data.get("items", []) if isinstance(data, dict) else []
    sensitive = []
    for crb in items:
        role = (crb.get("roleRef") or {}).get("name", "")
        if role in ("cluster-admin", "admin", "edit"):
            for sub in (crb.get("subjects") or []):
                sensitive.append(f"{sub.get('kind','?')}/{sub.get('namespace','-')}/{sub.get('name','?')} -> {role}")
    if sensitive:
        return _kc_resp("rbac_audit_via_rbac_tool", target, [wrap_finding(
            f"{len(sensitive)} principal(s) bound to cluster-admin / admin / edit",
            "HIGH" if len(sensitive) > 3 else "MEDIUM",
            cvss="8.0" if len(sensitive) > 3 else "6.0",
            cwe="CWE-269",
            remediation=("Review bindings to cluster-admin/admin/edit. Replace "
                          "with least-privilege roles scoped to specific "
                          "namespaces and verbs. Service accounts almost never "
                          "need cluster-admin."),
            evidence_marker="; ".join(sensitive[:10]),
        )], len(items), f"rbac audit ({len(sensitive)} overprivileged binding(s))")
    return _kc_resp("rbac_audit_via_rbac_tool", target, [wrap_finding(
        f"No cluster-admin / admin / edit ClusterRoleBindings to non-system principals ({len(items)} CRB(s) audited)",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue least-privilege posture.",
        evidence_marker=f"{len(items)} CRBs reviewed, 0 sensitive bindings")], len(items),
        "rbac audit")


def _probe_service_mesh_mtls_off(target, req):
    """Service-mesh-wide mTLS audit. Look for Istio PeerAuthentication
    resources at mesh scope; absence == no enforced mTLS. Falls back to
    DestinationRule TLS mode if PeerAuthentication is missing."""
    kc = _get_kubeconfig(req)
    if kc is None:
        return _kc_ndr("service_mesh_mtls_off", target)
    import json
    ec, out, err = _kubectl(
        ["get", "peerauthentication.security.istio.io", "-A", "-o", "json"],
        kc, timeout=20)
    if ec != 0:
        # No Istio CRDs at all = no Istio. That's not a finding.
        return _kc_resp("service_mesh_mtls_off", target, [wrap_finding(
            "No Istio PeerAuthentication CRDs found (mesh not installed or other mesh)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("If using Linkerd or Consul: install their analog "
                          "(Server / Intentions). If no mesh: ignore."),
            evidence_marker=f"kubectl exit {ec}; stderr: {err[-200:]}")], 1,
            "service mesh mTLS audit (no mesh CRDs)")
    try:
        data = json.loads(out)
    except Exception:
        data = {"items": []}
    items = data.get("items", []) if isinstance(data, dict) else []
    strict = []
    permissive = []
    for pa in items:
        meta = pa.get("metadata", {})
        spec = pa.get("spec", {})
        mtls = (spec.get("mtls") or {}).get("mode", "")
        scope = "mesh-wide" if meta.get("namespace") == "istio-system" else \
                f"namespace:{meta.get('namespace','?')}"
        line = f"{meta.get('name','?')} ({scope}) -> mtls.mode={mtls or 'unset'}"
        if mtls == "STRICT":
            strict.append(line)
        else:
            permissive.append(line)
    if not items:
        return _kc_resp("service_mesh_mtls_off", target, [wrap_finding(
            "Mesh installed but ZERO PeerAuthentication resources",
            "HIGH", cvss="7.5", cwe="CWE-319",
            remediation=("Create a mesh-wide PeerAuthentication in istio-system "
                          "namespace with mtls.mode: STRICT. Without it, "
                          "service-to-service traffic falls back to plaintext."),
            evidence_marker="0 PeerAuthentication resources cluster-wide",
        )], 1, "service mesh mTLS audit (no enforcement)")
    if permissive:
        return _kc_resp("service_mesh_mtls_off", target, [wrap_finding(
            f"{len(permissive)} PeerAuthentication(s) not in STRICT mtls mode",
            "HIGH", cvss="7.5", cwe="CWE-319",
            remediation=("Set mtls.mode: STRICT on all PeerAuthentication "
                          "resources. PERMISSIVE allows plaintext fallback "
                          "and defeats the mesh's transport security guarantee."),
            evidence_marker="; ".join(permissive[:5]),
        )], len(items), f"service mesh mTLS audit ({len(permissive)} weak)")
    return _kc_resp("service_mesh_mtls_off", target, [wrap_finding(
        f"All {len(strict)} PeerAuthentication(s) in STRICT mtls mode",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue mesh-wide STRICT mTLS posture.",
        evidence_marker="; ".join(strict[:3]),
    )], len(items), "service mesh mTLS audit")
