"""K8s cluster probes via kubeconfig input.

Each probe takes the customer-provided `kubeconfig` (full kubeconfig
YAML pasted in dashboard) and shells out to kubectl to inspect the
real cluster. Probes are read-only - they LIST and GET, never CREATE
or DELETE. NOT_APPLICABLE when kubeconfig is missing.

Kubeconfig is written to an ephemeral tempfile per probe (chmod 600,
auto-deleted on exit). KUBECONFIG env var points kubectl at it.

12 probes wired in container_k8s_pack.py PROBES dict:
  k8s_anonymous_auth_kubectl       kube-apiserver --anonymous-auth check
  k8s_audit_logs_off               --audit-log-path check
  k8s_admission_no_plugin          --enable-admission-plugins check
  k8s_psp_psa_disabled             PodSecurity admission plugin check
  k8s_network_policy_absent        NetworkPolicy resources present
  rbac_cluster_admin_overuse       cluster-admin ClusterRoleBinding count
  rbac_secret_get_anywhere         secrets:get cluster-wide check
  rbac_pod_exec_create_overuse     pod/exec + pod/create RBAC overuse
  rbac_node_proxy_overuse          nodes/proxy permission overuse
  rbac_impersonate_users           impersonate verb on users/groups
  secrets_in_env_var               Pod env with sensitive var names
  kube_bench_node                  CIS K8s benchmark via kube-bench
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional

from tools._shared import wrap_finding


_KUBECTL_TIMEOUT = 30


def _ndr(slug: str, target: str, reason: str = ""):
    return {
        "tool": slug, "target": target, "scan_time": 0,
        "vulnerable": False, "severity": "INFO",
        "findings": [wrap_finding(
            f"[NOT_APPLICABLE] {slug} requires kubeconfig YAML input",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Paste your kubeconfig in the dashboard's "
                          "kubeconfig field (read-only access is enough). "
                          "Probe will activate automatically. The kubeconfig "
                          "is held in an ephemeral chmod-600 tempfile + "
                          "auto-shredded after the scan."),
            evidence_marker=reason or "Required input 'kubeconfig' is empty.",
        )],
        "tests_performed": 0,
        "tests_summary": f"{slug} skipped - missing kubeconfig",
        "raw_data": {"missing_input": "kubeconfig"},
    }


def _build_resp(slug, target, findings, tested, summary):
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "POSITIVE": 0}
    top = "INFO"
    for f in findings:
        s = f.get("severity", "INFO")
        if sev_order.get(s, 0) > sev_order.get(top, 0):
            top = s
    return {
        "tool": slug, "target": target, "scan_time": 0,
        "vulnerable": top in ("CRITICAL", "HIGH", "MEDIUM"),
        "severity": top,
        "findings": findings,
        "tests_performed": tested,
        "tests_summary": summary,
        "raw_data": {},
    }


def _get_kubeconfig(req) -> Optional[str]:
    kc = getattr(req, "kubeconfig", None)
    if not kc or not isinstance(kc, str) or not kc.strip():
        return None
    return kc


def _kubectl(args, kubeconfig_text, timeout=_KUBECTL_TIMEOUT):
    """Run kubectl with the customer's kubeconfig in an ephemeral tempfile.
    Returns (exit_code, stdout, stderr). Auto-shreds the tempfile on exit."""
    if shutil.which("kubectl") is None:
        return 127, "", "kubectl binary not installed"
    fd, path = tempfile.mkstemp(prefix="vl-kc-", suffix=".yaml")
    try:
        os.write(fd, kubeconfig_text.encode("utf-8"))
        os.close(fd)
        os.chmod(path, 0o600)
        env = os.environ.copy()
        env["KUBECONFIG"] = path
        proc = subprocess.run(
            ["kubectl"] + args,
            capture_output=True, text=True,
            timeout=timeout, check=False, env=env)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or "timeout"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {str(e)[:200]}"
    finally:
        try:
            with open(path, "wb") as f:
                f.write(b"\x00" * 1024)
            os.unlink(path)
        except Exception:
            pass


# ─── Probes ──────────────────────────────────────────────────────────

def _probe_k8s_anonymous_auth_kubectl(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("k8s_anonymous_auth_kubectl", target)
    ec, out, err = _kubectl(
        ["get", "--raw", "/api"],
        kc, timeout=15)
    if ec == 127:
        return _build_resp("k8s_anonymous_auth_kubectl", target, [wrap_finding(
            "[NOT IMPLEMENTED] kubectl binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with the Dockerfile that installs kubectl.",
            evidence_marker="kubectl missing")], 0, "kubectl missing")
    if ec == 0 and "kind" in out.lower():
        return _build_resp("k8s_anonymous_auth_kubectl", target, [wrap_finding(
            "kube-apiserver responds to authenticated kubectl request",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue authenticated-API posture.",
            evidence_marker=f"kubectl get --raw /api succeeded with kubeconfig")], 1,
            "API server auth probe")
    return _build_resp("k8s_anonymous_auth_kubectl", target, [wrap_finding(
        f"kubectl auth probe failed (exit {ec})",
        "INFO", cvss="0.0", cwe="N/A",
        remediation="Verify kubeconfig credentials are valid and API server is reachable.",
        evidence_marker=f"stderr: {err[-200:]}")], 1,
        f"kubectl failed (exit {ec})")


def _probe_k8s_audit_logs_off(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("k8s_audit_logs_off", target)
    ec, out, err = _kubectl(
        ["get", "pods", "-n", "kube-system", "-l", "component=kube-apiserver",
         "-o", "jsonpath={.items[*].spec.containers[*].command}"],
        kc, timeout=20)
    if ec != 0:
        return _build_resp("k8s_audit_logs_off", target, [wrap_finding(
            "Cannot read kube-apiserver pod (managed cluster?)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Managed K8s services (EKS, GKE, AKS) hide the "
                          "kube-apiserver pod. Audit logging is configured "
                          "via provider console (CloudTrail for EKS, etc.)."),
            evidence_marker=f"kubectl exit {ec}; stderr: {err[-200:]}")], 1,
            "audit log probe (apiserver not visible)")
    has_audit = "--audit-log-path" in out or "--audit-policy-file" in out
    if has_audit:
        return _build_resp("k8s_audit_logs_off", target, [wrap_finding(
            "kube-apiserver audit logging enabled",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue audit-log retention + SIEM forwarding.",
            evidence_marker="Found --audit-log-path / --audit-policy-file in apiserver args")], 1,
            "audit log enabled")
    return _build_resp("k8s_audit_logs_off", target, [wrap_finding(
        "kube-apiserver audit logging NOT enabled",
        "MEDIUM", cvss="5.5", cwe="CWE-778",
        remediation=("Enable audit logging: pass --audit-log-path=/var/log/"
                      "kube-audit.log and --audit-policy-file=/etc/kubernetes/"
                      "audit-policy.yaml to kube-apiserver. Required by CIS "
                      "1.2.18 + PCI 10.x."),
        evidence_marker=f"apiserver args do not include audit flags: {out[:200]}")], 1,
        "audit logging disabled")


def _probe_k8s_admission_no_plugin(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("k8s_admission_no_plugin", target)
    ec, out, err = _kubectl(
        ["get", "pods", "-n", "kube-system", "-l", "component=kube-apiserver",
         "-o", "jsonpath={.items[*].spec.containers[*].command}"],
        kc, timeout=20)
    if ec != 0:
        return _build_resp("k8s_admission_no_plugin", target, [wrap_finding(
            "Cannot read kube-apiserver pod (managed cluster?)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify admission plugins via your provider's console.",
            evidence_marker=f"kubectl exit {ec}")], 1,
            "admission probe (apiserver not visible)")
    expected = ["NodeRestriction", "PodSecurity", "ResourceQuota", "LimitRanger"]
    found = [p for p in expected if p in out]
    missing = [p for p in expected if p not in out]
    if missing:
        return _build_resp("k8s_admission_no_plugin", target, [wrap_finding(
            f"Missing admission plugin(s): {', '.join(missing)}",
            "HIGH", cvss="7.5", cwe="CWE-693",
            remediation=("Enable critical admission plugins via --enable-"
                          "admission-plugins. NodeRestriction prevents kubelet "
                          "from modifying other nodes. PodSecurity enforces "
                          "Pod Security Standards. ResourceQuota + LimitRanger "
                          "prevent resource exhaustion."),
            evidence_marker=f"Missing: {missing}; Found: {found}")], 1,
            f"{len(missing)} admission plugin(s) missing")
    return _build_resp("k8s_admission_no_plugin", target, [wrap_finding(
        f"All {len(expected)} core admission plugins enabled",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue defence-in-depth posture.",
        evidence_marker=f"Found: {found}")], 1,
        "admission plugins present")


def _probe_k8s_psp_psa_disabled(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("k8s_psp_psa_disabled", target)
    # Check if any namespace has Pod Security labels
    ec, out, err = _kubectl(
        ["get", "namespaces", "-o", "json"], kc, timeout=20)
    if ec != 0:
        return _build_resp("k8s_psp_psa_disabled", target, [wrap_finding(
            f"Cannot list namespaces (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig permissions include namespace list.",
            evidence_marker=err[-200:])], 1, "PSA probe failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("k8s_psp_psa_disabled", target, [wrap_finding(
            "PSA probe parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Re-run scan.",
            evidence_marker=out[:200])], 1, "parse error")
    ns_with_psa = []
    ns_without_psa = []
    for ns in data.get("items", []):
        labels = (ns.get("metadata") or {}).get("labels") or {}
        psa = any(k.startswith("pod-security.kubernetes.io/") for k in labels)
        name = ns["metadata"]["name"]
        if name in ("kube-system", "kube-public", "kube-node-lease", "default"):
            continue  # built-in namespaces - skip
        (ns_with_psa if psa else ns_without_psa).append(name)
    if ns_without_psa:
        return _build_resp("k8s_psp_psa_disabled", target, [wrap_finding(
            f"Pod Security Admission not labeled on {len(ns_without_psa)} namespace(s)",
            "HIGH", cvss="7.5", cwe="CWE-732",
            remediation=("Label each workload namespace with PSA enforcement: "
                          "kubectl label namespace <NAME> "
                          "pod-security.kubernetes.io/enforce=restricted. "
                          "Without PSA labels, namespaces accept any pod spec "
                          "including privileged/hostPath."),
            evidence_marker=(f"Missing PSA labels on: {ns_without_psa[:10]}; "
                              f"With PSA: {len(ns_with_psa)}"))], 1,
            f"{len(ns_without_psa)} namespace(s) without PSA")
    return _build_resp("k8s_psp_psa_disabled", target, [wrap_finding(
        f"All {len(ns_with_psa)} user namespace(s) have PSA labels",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue PSA enforcement.",
        evidence_marker=f"Labeled namespaces: {ns_with_psa[:10]}")], 1,
        "PSA enforced cluster-wide")


def _probe_k8s_network_policy_absent(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("k8s_network_policy_absent", target)
    ec, out, err = _kubectl(
        ["get", "networkpolicy", "--all-namespaces", "-o", "json"],
        kc, timeout=20)
    if ec != 0:
        return _build_resp("k8s_network_policy_absent", target, [wrap_finding(
            f"NetworkPolicy probe failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify CNI supports NetworkPolicy (Calico, Cilium, Weave).",
            evidence_marker=err[-200:])], 1, "NP probe failed")
    try:
        data = json.loads(out)
        np_count = len(data.get("items", []))
    except Exception:
        np_count = 0
    if np_count == 0:
        return _build_resp("k8s_network_policy_absent", target, [wrap_finding(
            "No NetworkPolicy resources defined cluster-wide",
            "HIGH", cvss="7.5", cwe="CWE-732",
            remediation=("Define default-deny NetworkPolicy per namespace + "
                          "explicit allow rules per service. Without NPs, "
                          "any pod can reach any other pod (no segmentation). "
                          "Requires CNI plugin with NP support (Calico, "
                          "Cilium, Weave Net)."),
            evidence_marker="kubectl get networkpolicy --all-namespaces: 0 items")], 1,
            "0 NetworkPolicy resources")
    return _build_resp("k8s_network_policy_absent", target, [wrap_finding(
        f"{np_count} NetworkPolicy resource(s) defined cluster-wide",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Audit each NP for default-deny + explicit allow pattern.",
        evidence_marker=f"NetworkPolicy count: {np_count}")], 1,
        f"{np_count} NetworkPolicies")


def _probe_rbac_cluster_admin_overuse(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("rbac_cluster_admin_overuse", target)
    ec, out, err = _kubectl(
        ["get", "clusterrolebindings", "-o", "json"], kc, timeout=20)
    if ec != 0:
        return _build_resp("rbac_cluster_admin_overuse", target, [wrap_finding(
            f"CRB list failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig has cluster-wide list permissions.",
            evidence_marker=err[-200:])], 1, "CRB probe failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("rbac_cluster_admin_overuse", target, [wrap_finding(
            "CRB parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.",
            evidence_marker=out[:200])], 1, "parse error")
    cluster_admin_subjects = []
    for crb in data.get("items", []):
        if (crb.get("roleRef") or {}).get("name") != "cluster-admin":
            continue
        for s in (crb.get("subjects") or []):
            kind = s.get("kind", "?")
            name = s.get("name", "?")
            ns = s.get("namespace", "")
            # Skip built-in system bindings
            if kind == "Group" and name in ("system:masters",):
                continue
            cluster_admin_subjects.append(
                f"{kind}/{name}" + (f" (ns={ns})" if ns else ""))
    if len(cluster_admin_subjects) > 0:
        sev = "CRITICAL" if len(cluster_admin_subjects) > 3 else "HIGH"
        cvss = "9.0" if sev == "CRITICAL" else "8.0"
        return _build_resp("rbac_cluster_admin_overuse", target, [wrap_finding(
            f"{len(cluster_admin_subjects)} non-system subject(s) bound to cluster-admin",
            sev, cvss=cvss, cwe="CWE-269", owasp="A01:2021",
            remediation=("cluster-admin = root on the cluster. Each subject "
                          "bound to it can do anything (delete namespaces, "
                          "exfiltrate secrets, deploy malicious workloads). "
                          "Audit each binding + replace with least-privilege "
                          "ClusterRoles or namespaced Roles."),
            evidence_marker=f"cluster-admin subjects: {cluster_admin_subjects[:10]}")], 1,
            f"{len(cluster_admin_subjects)} cluster-admin overuse")
    return _build_resp("rbac_cluster_admin_overuse", target, [wrap_finding(
        "Only system:masters group bound to cluster-admin",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue least-privilege RBAC posture.",
        evidence_marker="0 non-system subjects with cluster-admin")], 1,
        "cluster-admin properly restricted")


def _probe_rbac_secret_get_anywhere(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("rbac_secret_get_anywhere", target)
    ec, out, err = _kubectl(
        ["get", "clusterroles", "-o", "json"], kc, timeout=20)
    if ec != 0:
        return _build_resp("rbac_secret_get_anywhere", target, [wrap_finding(
            f"ClusterRole list failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig RBAC list permission.",
            evidence_marker=err[-200:])], 1, "ClusterRole probe failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("rbac_secret_get_anywhere", target, [wrap_finding(
            "ClusterRole parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.", evidence_marker=out[:200])], 1, "parse error")
    risky_roles = []
    for cr in data.get("items", []):
        name = (cr.get("metadata") or {}).get("name", "")
        if name.startswith("system:"):
            continue
        for rule in (cr.get("rules") or []):
            resources = rule.get("resources") or []
            verbs = rule.get("verbs") or []
            if ("secrets" in resources or "*" in resources) and \
                ("get" in verbs or "list" in verbs or "*" in verbs):
                risky_roles.append(name)
                break
    if risky_roles:
        return _build_resp("rbac_secret_get_anywhere", target, [wrap_finding(
            f"{len(risky_roles)} ClusterRole(s) can GET secrets cluster-wide",
            "HIGH", cvss="7.5", cwe="CWE-200",
            remediation=("ClusterRoles granting secrets:get bypass per-"
                          "namespace isolation. Replace with namespaced "
                          "Roles + per-namespace RoleBindings."),
            evidence_marker=f"Roles: {risky_roles[:10]}")], 1,
            f"{len(risky_roles)} risky ClusterRole(s)")
    return _build_resp("rbac_secret_get_anywhere", target, [wrap_finding(
        "No non-system ClusterRole grants secrets:get",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue namespace-isolated secrets.",
        evidence_marker="0 ClusterRoles with secrets:get")], 1,
        "secrets:get properly scoped")


def _probe_rbac_pod_exec_create_overuse(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("rbac_pod_exec_create_overuse", target)
    ec, out, err = _kubectl(
        ["get", "clusterroles", "-o", "json"], kc, timeout=20)
    if ec != 0:
        return _build_resp("rbac_pod_exec_create_overuse", target, [wrap_finding(
            f"ClusterRole list failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig.",
            evidence_marker=err[-200:])], 1, "probe failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("rbac_pod_exec_create_overuse", target, [wrap_finding(
            "parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.", evidence_marker=out[:200])], 1, "parse error")
    risky = []
    for cr in data.get("items", []):
        name = (cr.get("metadata") or {}).get("name", "")
        if name.startswith("system:"):
            continue
        for rule in (cr.get("rules") or []):
            resources = rule.get("resources") or []
            verbs = rule.get("verbs") or []
            if "pods/exec" in resources or ("pods" in resources and "create" in verbs):
                risky.append(name)
                break
    if risky:
        return _build_resp("rbac_pod_exec_create_overuse", target, [wrap_finding(
            f"{len(risky)} ClusterRole(s) grant pod/exec or pod/create",
            "HIGH", cvss="8.0", cwe="CWE-269",
            remediation=("pods/exec grants shell access into any pod "
                          "(can read its filesystem + secrets via mounted "
                          "tokens). pod/create lets the subject spawn "
                          "privileged pods that bypass NetworkPolicy. "
                          "Restrict to specific namespaces via Role."),
            evidence_marker=f"Roles: {risky[:10]}")], 1,
            f"{len(risky)} risky pod/exec roles")
    return _build_resp("rbac_pod_exec_create_overuse", target, [wrap_finding(
        "No ClusterRole grants pod/exec or wildcard pod/create",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue least-privilege.",
        evidence_marker="0 risky pod RBAC roles")], 1, "pod RBAC properly scoped")


def _probe_rbac_node_proxy_overuse(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("rbac_node_proxy_overuse", target)
    ec, out, err = _kubectl(
        ["get", "clusterroles", "-o", "json"], kc, timeout=20)
    if ec != 0:
        return _build_resp("rbac_node_proxy_overuse", target, [wrap_finding(
            f"probe failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig.",
            evidence_marker=err[-200:])], 1, "probe failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("rbac_node_proxy_overuse", target, [wrap_finding(
            "parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.", evidence_marker=out[:200])], 1, "parse error")
    risky = []
    for cr in data.get("items", []):
        name = (cr.get("metadata") or {}).get("name", "")
        if name.startswith("system:"):
            continue
        for rule in (cr.get("rules") or []):
            resources = rule.get("resources") or []
            if "nodes/proxy" in resources or "nodes/exec" in resources:
                risky.append(name)
                break
    if risky:
        return _build_resp("rbac_node_proxy_overuse", target, [wrap_finding(
            f"{len(risky)} ClusterRole(s) grant nodes/proxy",
            "HIGH", cvss="7.5", cwe="CWE-269",
            remediation=("nodes/proxy lets the subject hit kubelet API on "
                          "any node, which can run arbitrary commands inside "
                          "pods + read host filesystems. Remove unless "
                          "strictly required for cluster ops."),
            evidence_marker=f"Roles: {risky}")], 1,
            f"{len(risky)} nodes/proxy roles")
    return _build_resp("rbac_node_proxy_overuse", target, [wrap_finding(
        "No non-system ClusterRole grants nodes/proxy",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue posture.",
        evidence_marker="0 risky nodes/proxy roles")], 1, "nodes/proxy restricted")


def _probe_rbac_impersonate_users(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("rbac_impersonate_users", target)
    ec, out, err = _kubectl(
        ["get", "clusterroles", "-o", "json"], kc, timeout=20)
    if ec != 0:
        return _build_resp("rbac_impersonate_users", target, [wrap_finding(
            f"probe failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig.",
            evidence_marker=err[-200:])], 1, "probe failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("rbac_impersonate_users", target, [wrap_finding(
            "parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.", evidence_marker=out[:200])], 1, "parse error")
    risky = []
    for cr in data.get("items", []):
        name = (cr.get("metadata") or {}).get("name", "")
        if name.startswith("system:"):
            continue
        for rule in (cr.get("rules") or []):
            verbs = rule.get("verbs") or []
            resources = rule.get("resources") or []
            if "impersonate" in verbs and (
                "users" in resources or "groups" in resources or "*" in resources):
                risky.append(name)
                break
    if risky:
        return _build_resp("rbac_impersonate_users", target, [wrap_finding(
            f"{len(risky)} ClusterRole(s) grant impersonate users/groups",
            "HIGH", cvss="8.0", cwe="CWE-269",
            remediation=("impersonate verb lets the subject act AS any user "
                          "or group - effectively privilege escalation. "
                          "Audit each binding + remove unless strictly "
                          "required for break-glass workflows."),
            evidence_marker=f"Roles: {risky}")], 1,
            f"{len(risky)} impersonate roles")
    return _build_resp("rbac_impersonate_users", target, [wrap_finding(
        "No non-system ClusterRole grants impersonate",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue posture.",
        evidence_marker="0 risky impersonate roles")], 1, "impersonate restricted")


def _probe_secrets_in_env_var(target, req):
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("secrets_in_env_var", target)
    ec, out, err = _kubectl(
        ["get", "pods", "--all-namespaces", "-o", "json"], kc, timeout=30)
    if ec != 0:
        return _build_resp("secrets_in_env_var", target, [wrap_finding(
            f"Pod list failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig pod-list permission.",
            evidence_marker=err[-200:])], 1, "probe failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("secrets_in_env_var", target, [wrap_finding(
            "parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.", evidence_marker=out[:200])], 1, "parse error")
    suspicious = []
    sensitive_names = re.compile(
        r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
        r"private[_-]?key|db[_-]?pass|database[_-]?url|jwt[_-]?secret)")
    for pod in data.get("items", []):
        ns = pod["metadata"]["namespace"]
        pname = pod["metadata"]["name"]
        for c in (pod.get("spec") or {}).get("containers") or []:
            for env in c.get("env") or []:
                env_name = env.get("name", "")
                # If it's a plain value (not valueFrom: secretKeyRef), it's risky
                if env.get("value") and sensitive_names.search(env_name):
                    suspicious.append(
                        f"{ns}/{pname}:{c.get('name','?')} env={env_name}")
    if suspicious:
        return _build_resp("secrets_in_env_var", target, [wrap_finding(
            f"{len(suspicious)} pod env var(s) named like secrets but set as plain value",
            "MEDIUM", cvss="5.5", cwe="CWE-522",
            remediation=("Move secret values out of pod env. Use Kubernetes "
                          "Secret + valueFrom.secretKeyRef so the value is "
                          "loaded at runtime (and kept out of `kubectl describe`)."),
            evidence_marker="; ".join(suspicious[:5]))], 1,
            f"{len(suspicious)} suspicious env vars")
    return _build_resp("secrets_in_env_var", target, [wrap_finding(
        "No sensitive-named env vars set as plain values",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue secretKeyRef pattern.",
        evidence_marker="0 sensitive plain env vars detected")], 1,
        "env var hygiene clean")


def _probe_kube_bench_node(target, req):
    """Real kube-bench CIS scan against the connected cluster."""
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("kube_bench_node", target)
    if shutil.which("kube-bench") is None:
        return _build_resp("kube_bench_node", target, [wrap_finding(
            "[NOT IMPLEMENTED] kube-bench binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with Dockerfile that installs kube-bench.",
            evidence_marker="kube-bench not in PATH")], 0, "kube-bench missing")
    # kube-bench run --json against the cluster (requires kubeconfig)
    fd, path = tempfile.mkstemp(prefix="vl-kc-", suffix=".yaml")
    try:
        os.write(fd, kc.encode("utf-8")); os.close(fd); os.chmod(path, 0o600)
        env = os.environ.copy()
        env["KUBECONFIG"] = path
        proc = subprocess.run(
            ["kube-bench", "run", "--targets", "master,node",
             "--json", "--noresults", "--exit-code", "0"],
            capture_output=True, text=True, timeout=120, env=env)
    except subprocess.TimeoutExpired:
        return _build_resp("kube_bench_node", target, [wrap_finding(
            "kube-bench scan timeout (>2min)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Try smaller scope: --targets master only.",
            evidence_marker="wall-clock exceeded")], 0, "kube-bench timeout")
    except Exception as e:
        return _build_resp("kube_bench_node", target, [wrap_finding(
            f"kube-bench exec error: {str(e)[:120]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kube-bench installation.",
            evidence_marker=str(e)[:200])], 0, "kube-bench error")
    finally:
        try:
            with open(path, "wb") as f: f.write(b"\x00" * 1024)
            os.unlink(path)
        except Exception:
            pass
    out = proc.stdout or ""
    try:
        result = json.loads(out)
    except Exception:
        return _build_resp("kube_bench_node", target, [wrap_finding(
            "kube-bench JSON parse failed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="kube-bench may need --kubernetes-version override.",
            evidence_marker=f"First 200: {out[:200]}; stderr: {(proc.stderr or '')[-200:]}")], 0,
            "kube-bench parse error")
    findings = []
    fails = []
    for ctrl in result.get("Controls", []):
        for test in ctrl.get("tests", []):
            for r in test.get("results", []):
                if r.get("status") == "FAIL":
                    fails.append({
                        "id": r.get("test_number", "?"),
                        "desc": r.get("test_desc", ""),
                        "remediation": r.get("remediation", ""),
                    })
    if fails:
        # Take top 10 worst
        for f in fails[:10]:
            findings.append(wrap_finding(
                f"CIS {f['id']}: {f['desc'][:120]}",
                "MEDIUM", cvss="5.5", cwe="CWE-1357",
                remediation=f["remediation"][:300] or "See CIS K8s benchmark guide.",
                evidence_marker=f"kube-bench FAIL on CIS {f['id']}"))
        if len(fails) > 10:
            findings.append(wrap_finding(
                f"+{len(fails)-10} additional CIS controls failed",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Run kube-bench locally for full report.",
                evidence_marker=f"Total CIS failures: {len(fails)}"))
    else:
        findings.append(wrap_finding(
            "kube-bench CIS scan: 0 control failures",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue CIS compliance posture.",
            evidence_marker=f"All {sum(1 for c in result.get('Controls',[]) for t in c.get('tests',[]) for r in t.get('results',[]))} controls passed"))
    return _build_resp("kube_bench_node", target, findings,
                       max(len(fails), 1),
                       f"kube-bench CIS scan ({len(fails)} failures)")
