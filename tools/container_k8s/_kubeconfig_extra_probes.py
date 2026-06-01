"""Additional K8s cluster probes via kubeconfig.

Builds on _kubeconfig_probes.py. Same security model:
  - ephemeral kubeconfig tempfile (chmod 600 + null-overwrite + unlink)
  - read-only kubectl operations (get / list)
  - 20-second per-call timeout
  - NOT_APPLICABLE when kubeconfig missing

10 additional probes:
  secrets_etcd_unencrypted        check EncryptionConfiguration via apiserver flags
  vault_csi_audit                 detect Vault CSI provider DaemonSet
  sealed_secrets_audit            detect SealedSecrets controller + CRD count
  external_secrets_audit          detect ExternalSecrets operator + ESO resources
  k8s_tls_min_version             kube-apiserver --tls-min-version flag
  k8s_cni_plugin_audit            detect CNI (Calico, Cilium, Weave, Flannel, AWS VPC)
  rbac_pod_serviceaccount_token   pods with automountServiceAccountToken!=false
  rbac_clusterrolebinding_audit   total CRB count + outliers
  rbac_aggregate_role_audit       ClusterRoles with aggregationRule
  envoy_filter_audit              kubectl get envoyfilters cluster-wide
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


def _ndr(slug, target, reason=""):
    return {
        "tool": slug, "target": target, "scan_time": 0,
        "vulnerable": False, "severity": "INFO",
        "findings": [wrap_finding(
            f"[NOT_APPLICABLE] {slug} requires kubeconfig YAML input",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Paste kubeconfig in dashboard. Probe auto-activates.",
            evidence_marker=reason or "kubeconfig empty")],
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
        "severity": top, "findings": findings,
        "tests_performed": tested, "tests_summary": summary,
        "raw_data": {},
    }


def _get_kc(req):
    kc = getattr(req, "kubeconfig", None)
    if not kc or not isinstance(kc, str) or not kc.strip():
        return None
    return kc


def _kubectl(args, kc, timeout=20):
    if shutil.which("kubectl") is None:
        return 127, "", "kubectl missing"
    fd, path = tempfile.mkstemp(prefix="vl-kc-", suffix=".yaml")
    try:
        os.write(fd, kc.encode("utf-8")); os.close(fd); os.chmod(path, 0o600)
        env = os.environ.copy(); env["KUBECONFIG"] = path
        proc = subprocess.run(["kubectl"] + args,
                                capture_output=True, text=True,
                                timeout=timeout, check=False, env=env)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or "timeout"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {str(e)[:200]}"
    finally:
        try:
            with open(path, "wb") as f: f.write(b"\x00" * 1024)
            os.unlink(path)
        except Exception: pass


# ─── Probes ──────────────────────────────────────────────────────────

def _probe_secrets_etcd_unencrypted(target, req):
    """kube-apiserver --encryption-provider-config flag indicates etcd encryption."""
    kc = _get_kc(req)
    if kc is None:
        return _ndr("secrets_etcd_unencrypted", target)
    ec, out, err = _kubectl(
        ["get", "pods", "-n", "kube-system", "-l", "component=kube-apiserver",
         "-o", "jsonpath={.items[*].spec.containers[*].command}"], kc)
    if ec != 0:
        return _build_resp("secrets_etcd_unencrypted", target, [wrap_finding(
            "Cannot read kube-apiserver pod (managed cluster?)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Managed K8s (EKS/GKE/AKS) handles etcd encryption "
                          "transparently. Verify via provider console."),
            evidence_marker=f"kubectl exit {ec}")], 1, "apiserver not visible")
    has_enc = "--encryption-provider-config" in out
    if has_enc:
        return _build_resp("secrets_etcd_unencrypted", target, [wrap_finding(
            "kube-apiserver has --encryption-provider-config (etcd encryption enabled)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Verify the config uses aescbc/kms (not 'identity').",
            evidence_marker="apiserver args include --encryption-provider-config")], 1,
            "etcd encryption configured")
    return _build_resp("secrets_etcd_unencrypted", target, [wrap_finding(
        "etcd encryption-at-rest NOT configured",
        "HIGH", cvss="7.5", cwe="CWE-311",
        remediation=("Configure etcd encryption-at-rest. Create an "
                      "EncryptionConfiguration with aescbc or kms provider, "
                      "pass --encryption-provider-config=/etc/kubernetes/"
                      "encryption-config.yaml to kube-apiserver. Without "
                      "this, ALL Kubernetes Secrets are stored in plain "
                      "text in etcd. Per CIS 1.6.x + PCI 3.4.x."),
        evidence_marker=f"apiserver args: {out[:200]} - no --encryption-provider-config")], 1,
        "etcd encryption disabled")


def _probe_vault_csi_audit(target, req):
    """Detect Vault CSI provider DaemonSet."""
    kc = _get_kc(req)
    if kc is None:
        return _ndr("vault_csi_audit", target)
    ec, out, err = _kubectl(
        ["get", "daemonsets", "--all-namespaces", "-o", "json"], kc)
    if ec != 0:
        return _build_resp("vault_csi_audit", target, [wrap_finding(
            f"DaemonSet list failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig.", evidence_marker=err[-200:])], 1,
            "DS list failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("vault_csi_audit", target, [wrap_finding(
            "parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.", evidence_marker=out[:200])], 1, "parse error")
    vault_ds = []
    for ds in data.get("items", []):
        name = (ds.get("metadata") or {}).get("name", "").lower()
        if "vault" in name and ("csi" in name or "agent" in name):
            ns = (ds.get("metadata") or {}).get("namespace", "?")
            vault_ds.append(f"{ns}/{name}")
    if vault_ds:
        return _build_resp("vault_csi_audit", target, [wrap_finding(
            f"Vault CSI provider detected: {', '.join(vault_ds)}",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation=("Vault CSI is good practice for secrets management. "
                          "Verify the SecretProviderClass resources point at "
                          "your Vault instance + use volumes (not env vars)."),
            evidence_marker=f"Vault DaemonSets: {vault_ds}")], 1,
            "Vault CSI installed")
    return _build_resp("vault_csi_audit", target, [wrap_finding(
        "No Vault CSI provider detected (informational)",
        "INFO", cvss="0.0", cwe="N/A",
        remediation=("If using HashiCorp Vault for secrets, consider Vault "
                      "CSI provider for mounting secrets as volumes (better "
                      "than env-var injection). Optional."),
        evidence_marker="No DaemonSets matching vault-csi/vault-agent")], 1,
        "no Vault CSI present")


def _probe_sealed_secrets_audit(target, req):
    """Detect Sealed Secrets controller (Bitnami)."""
    kc = _get_kc(req)
    if kc is None:
        return _ndr("sealed_secrets_audit", target)
    # Try the CRD
    ec, out, err = _kubectl(["get", "sealedsecrets", "--all-namespaces",
                              "-o", "json"], kc, timeout=15)
    if ec == 0:
        try:
            data = json.loads(out)
            count = len(data.get("items", []))
        except Exception:
            count = 0
        return _build_resp("sealed_secrets_audit", target, [wrap_finding(
            f"SealedSecrets controller present ({count} SealedSecret resource(s))",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation=("Good - SealedSecrets allow encrypted secrets to be "
                          "committed to git safely. Verify the controller "
                          "private key is backed up + rotation policy."),
            evidence_marker=f"kubectl get sealedsecrets: {count} resources")], 1,
            f"{count} SealedSecrets")
    # CRD doesn't exist
    return _build_resp("sealed_secrets_audit", target, [wrap_finding(
        "SealedSecrets controller NOT installed (informational)",
        "INFO", cvss="0.0", cwe="N/A",
        remediation=("If you commit secrets to git, install Bitnami SealedSecrets "
                      "or similar (External Secrets Operator, SOPS). Optional."),
        evidence_marker=f"kubectl get sealedsecrets failed: {err[-200:]}")], 1,
        "no SealedSecrets")


def _probe_external_secrets_audit(target, req):
    """Detect External Secrets Operator (ESO)."""
    kc = _get_kc(req)
    if kc is None:
        return _ndr("external_secrets_audit", target)
    ec, out, err = _kubectl(["get", "externalsecrets", "--all-namespaces",
                              "-o", "json"], kc, timeout=15)
    if ec == 0:
        try:
            data = json.loads(out)
            count = len(data.get("items", []))
        except Exception:
            count = 0
        return _build_resp("external_secrets_audit", target, [wrap_finding(
            f"External Secrets Operator present ({count} ExternalSecret resource(s))",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation=("Good - ESO syncs secrets from external vaults "
                          "(AWS Secrets Manager, GCP SM, Azure KV, Vault, "
                          "1Password) into K8s Secrets. Verify the "
                          "SecretStore configuration is least-privileged."),
            evidence_marker=f"kubectl get externalsecrets: {count} resources")], 1,
            f"{count} ExternalSecrets")
    return _build_resp("external_secrets_audit", target, [wrap_finding(
        "External Secrets Operator NOT installed (informational)",
        "INFO", cvss="0.0", cwe="N/A",
        remediation=("Optional - install if you use AWS Secrets Manager, "
                      "GCP Secret Manager, Vault, etc. for centralized "
                      "secrets management."),
        evidence_marker=f"kubectl get externalsecrets failed: {err[-200:]}")], 1,
        "no ESO")


def _probe_k8s_tls_min_version(target, req):
    """kube-apiserver --tls-min-version flag."""
    kc = _get_kc(req)
    if kc is None:
        return _ndr("k8s_tls_min_version", target)
    ec, out, err = _kubectl(
        ["get", "pods", "-n", "kube-system", "-l", "component=kube-apiserver",
         "-o", "jsonpath={.items[*].spec.containers[*].command}"], kc)
    if ec != 0:
        return _build_resp("k8s_tls_min_version", target, [wrap_finding(
            "Cannot read kube-apiserver pod (managed cluster?)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Managed clusters set TLS via provider. Verify in console.",
            evidence_marker=f"kubectl exit {ec}")], 1, "apiserver not visible")
    m = re.search(r"--tls-min-version[= ](\S+)", out)
    if m:
        ver = m.group(1).strip(",")
        if ver in ("VersionTLS10", "VersionTLS11"):
            return _build_resp("k8s_tls_min_version", target, [wrap_finding(
                f"kube-apiserver --tls-min-version={ver} (DEPRECATED)",
                "HIGH", cvss="7.5", cwe="CWE-326",
                remediation=("Set --tls-min-version=VersionTLS12 (or TLS13). "
                              "TLS 1.0/1.1 are deprecated + vulnerable to "
                              "BEAST, POODLE, etc."),
                evidence_marker=f"Current: --tls-min-version={ver}")], 1,
                f"weak TLS {ver}")
        if ver in ("VersionTLS12", "VersionTLS13"):
            return _build_resp("k8s_tls_min_version", target, [wrap_finding(
                f"kube-apiserver --tls-min-version={ver}",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue modern TLS posture.",
                evidence_marker=f"Current: --tls-min-version={ver}")], 1,
                f"strong TLS {ver}")
    return _build_resp("k8s_tls_min_version", target, [wrap_finding(
        "kube-apiserver --tls-min-version not explicitly set (default may be weak)",
        "MEDIUM", cvss="5.5", cwe="CWE-326",
        remediation=("Explicitly set --tls-min-version=VersionTLS12 to "
                      "kube-apiserver. Default historical behaviour allowed "
                      "TLS 1.0/1.1."),
        evidence_marker="No --tls-min-version flag in apiserver args")], 1,
        "TLS minimum version unset")


def _probe_k8s_cni_plugin_audit(target, req):
    """Detect installed CNI plugin from kube-system pods."""
    kc = _get_kc(req)
    if kc is None:
        return _ndr("k8s_cni_plugin_audit", target)
    ec, out, err = _kubectl(
        ["get", "pods", "-n", "kube-system", "-o",
         "jsonpath={.items[*].metadata.name}"], kc)
    if ec != 0:
        return _build_resp("k8s_cni_plugin_audit", target, [wrap_finding(
            f"kube-system pod list failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig.", evidence_marker=err[-200:])], 1,
            "kube-system list failed")
    detected = []
    cni_signatures = {
        "calico": ["calico-node", "calico-kube-controllers"],
        "cilium": ["cilium-", "cilium-operator"],
        "weave-net": ["weave-net-"],
        "flannel": ["kube-flannel-"],
        "aws-node": ["aws-node-"],  # AWS VPC CNI
        "kube-router": ["kube-router-"],
        "canal": ["canal-"],
    }
    for cni, sigs in cni_signatures.items():
        for s in sigs:
            if s in out:
                detected.append(cni)
                break
    detected = list(set(detected))
    if detected:
        # NetworkPolicy-supporting CNIs
        np_capable = {"calico", "cilium", "weave-net", "kube-router", "canal"}
        np_ok = any(c in np_capable for c in detected)
        sev = "POSITIVE" if np_ok else "MEDIUM"
        cvss = "0.0" if np_ok else "5.5"
        msg = (f"CNI plugin(s) detected: {', '.join(detected)}"
                + (" (NetworkPolicy supported)" if np_ok else " (NetworkPolicy NOT supported)"))
        return _build_resp("k8s_cni_plugin_audit", target, [wrap_finding(
            msg, sev, cvss=cvss, cwe="N/A" if np_ok else "CWE-732",
            remediation=("Continue current CNI." if np_ok else
                          "Switch to a NetworkPolicy-capable CNI (Calico, "
                          "Cilium, Weave Net) for traffic segmentation."),
            evidence_marker=f"Detected: {detected}")], 1,
            f"CNI: {', '.join(detected)}")
    return _build_resp("k8s_cni_plugin_audit", target, [wrap_finding(
        "Unable to identify CNI plugin from kube-system pods",
        "INFO", cvss="0.0", cwe="N/A",
        remediation="Manual review: kubectl get pods -n kube-system.",
        evidence_marker=f"No known CNI signatures in: {out[:200]}")], 1,
        "CNI unknown")


def _probe_rbac_pod_serviceaccount_token(target, req):
    """Pods with automountServiceAccountToken not explicitly false."""
    kc = _get_kc(req)
    if kc is None:
        return _ndr("rbac_pod_serviceaccount_token", target)
    ec, out, err = _kubectl(["get", "pods", "--all-namespaces",
                              "-o", "json"], kc, timeout=30)
    if ec != 0:
        return _build_resp("rbac_pod_serviceaccount_token", target, [wrap_finding(
            f"Pod list failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig.", evidence_marker=err[-200:])], 1,
            "pod list failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("rbac_pod_serviceaccount_token", target, [wrap_finding(
            "parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.", evidence_marker=out[:200])], 1, "parse error")
    automount_pods = []
    safe_pods = 0
    for pod in data.get("items", []):
        ns = pod["metadata"]["namespace"]
        # Skip kube-system - service accounts inside have specific roles
        if ns in ("kube-system", "kube-public"):
            continue
        spec = pod.get("spec") or {}
        automount = spec.get("automountServiceAccountToken")
        if automount is False:
            safe_pods += 1
        else:
            automount_pods.append(f"{ns}/{pod['metadata']['name']}")
    if len(automount_pods) > 10:
        return _build_resp("rbac_pod_serviceaccount_token", target, [wrap_finding(
            f"{len(automount_pods)} pod(s) have automountServiceAccountToken!=false",
            "MEDIUM", cvss="5.5", cwe="CWE-269",
            remediation=("Set automountServiceAccountToken: false on Pods/SA "
                          "that don't need to call the K8s API. Default-true "
                          "lets every pod read its SA token from /var/run/"
                          "secrets/kubernetes.io/serviceaccount and call the "
                          "API with that token - useful pivot for attackers."),
            evidence_marker=f"Automount: {len(automount_pods)}, locked-down: {safe_pods}; "
                              f"first 5: {automount_pods[:5]}")], 1,
            f"{len(automount_pods)} pods auto-mount SA token")
    return _build_resp("rbac_pod_serviceaccount_token", target, [wrap_finding(
        f"SA token auto-mount audit: {len(automount_pods)} pods, "
        f"{safe_pods} locked-down",
        "LOW" if automount_pods else "POSITIVE",
        cvss="3.0" if automount_pods else "0.0",
        cwe="CWE-269" if automount_pods else "N/A",
        remediation=("Audit which pods actually need K8s API access; "
                      "set automountServiceAccountToken:false on the rest."),
        evidence_marker=f"Automount:{len(automount_pods)}, locked:{safe_pods}")], 1,
        "SA token audit")


def _probe_rbac_clusterrolebinding_audit(target, req):
    """Overview of all ClusterRoleBindings."""
    kc = _get_kc(req)
    if kc is None:
        return _ndr("rbac_clusterrolebinding_audit", target)
    ec, out, err = _kubectl(["get", "clusterrolebindings", "-o", "json"], kc)
    if ec != 0:
        return _build_resp("rbac_clusterrolebinding_audit", target, [wrap_finding(
            f"CRB list failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig.",
            evidence_marker=err[-200:])], 1, "probe failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("rbac_clusterrolebinding_audit", target, [wrap_finding(
            "parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.", evidence_marker=out[:200])], 1, "parse error")
    crbs = data.get("items", [])
    user_crbs = [c for c in crbs if not (c.get("metadata", {}).get("name", "")
                                           .startswith("system:"))]
    sev = "INFO"
    if len(user_crbs) > 50:
        sev = "LOW"
    return _build_resp("rbac_clusterrolebinding_audit", target, [wrap_finding(
        f"ClusterRoleBindings: {len(crbs)} total, {len(user_crbs)} non-system",
        sev, cvss="3.0" if sev == "LOW" else "0.0", cwe="N/A",
        remediation=("Audit non-system CRBs quarterly. Each binding grants "
                      "cluster-wide permissions to its subjects. Consider "
                      "namespaced Roles + RoleBindings where possible."),
        evidence_marker=f"Total CRBs: {len(crbs)}, non-system: {len(user_crbs)}")], 1,
        f"CRB inventory ({len(user_crbs)} non-system)")


def _probe_rbac_aggregate_role_audit(target, req):
    """ClusterRoles with aggregationRule - dynamic role composition."""
    kc = _get_kc(req)
    if kc is None:
        return _ndr("rbac_aggregate_role_audit", target)
    ec, out, err = _kubectl(["get", "clusterroles", "-o", "json"], kc)
    if ec != 0:
        return _build_resp("rbac_aggregate_role_audit", target, [wrap_finding(
            f"ClusterRole list failed (exit {ec})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig.",
            evidence_marker=err[-200:])], 1, "probe failed")
    try:
        data = json.loads(out)
    except Exception:
        return _build_resp("rbac_aggregate_role_audit", target, [wrap_finding(
            "parse error", "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.", evidence_marker=out[:200])], 1, "parse error")
    aggregated = []
    for cr in data.get("items", []):
        if cr.get("aggregationRule"):
            name = cr.get("metadata", {}).get("name", "?")
            if not name.startswith("system:"):
                aggregated.append(name)
    if len(aggregated) > 5:
        return _build_resp("rbac_aggregate_role_audit", target, [wrap_finding(
            f"{len(aggregated)} non-system ClusterRoles use aggregationRule",
            "LOW", cvss="3.0", cwe="CWE-269",
            remediation=("aggregationRule lets ClusterRoles auto-grow when "
                          "labels match. Easy to misconfigure - a malicious "
                          "label can grant unintended permissions. Audit "
                          "matchLabels selectors."),
            evidence_marker=f"Aggregated CRs: {aggregated[:10]}")], 1,
            f"{len(aggregated)} aggregated CRs")
    return _build_resp("rbac_aggregate_role_audit", target, [wrap_finding(
        f"ClusterRole aggregation audit: {len(aggregated)} non-system aggregated",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue posture.",
        evidence_marker=f"Aggregated count: {len(aggregated)}")], 1,
        "aggregationRule scoped")


def _probe_envoy_filter_audit(target, req):
    """Detect Istio EnvoyFilter custom resources."""
    kc = _get_kc(req)
    if kc is None:
        return _ndr("envoy_filter_audit", target)
    ec, out, err = _kubectl(["get", "envoyfilters", "--all-namespaces",
                              "-o", "json"], kc, timeout=15)
    if ec != 0:
        # CRD doesn't exist = no Istio = N/A
        return _build_resp("envoy_filter_audit", target, [wrap_finding(
            "EnvoyFilter CRD not present (no Istio)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="N/A for non-Istio clusters.",
            evidence_marker=f"kubectl get envoyfilters failed: {err[-150:]}")], 1,
            "no Istio")
    try:
        data = json.loads(out)
        filters = data.get("items", [])
    except Exception:
        filters = []
    if not filters:
        return _build_resp("envoy_filter_audit", target, [wrap_finding(
            "Istio present but 0 EnvoyFilter resources",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Default Istio policy applies - no custom filters.",
            evidence_marker="0 EnvoyFilters")], 1, "no custom filters")
    # Look for risky patterns: lua filters (RCE), arbitrary HTTP filter insertion
    risky = []
    for f in filters:
        name = f.get("metadata", {}).get("name", "?")
        spec = f.get("spec", {})
        config_patches = spec.get("configPatches") or []
        for cp in config_patches:
            patch = json.dumps(cp.get("patch", {}))
            if '"envoy.filters.http.lua"' in patch or '"inline_code"' in patch:
                risky.append(f"{name} (lua filter)")
                break
    if risky:
        return _build_resp("envoy_filter_audit", target, [wrap_finding(
            f"EnvoyFilter contains Lua filter(s): {len(risky)} resource(s)",
            "MEDIUM", cvss="5.5", cwe="CWE-94",
            remediation=("Lua filters execute arbitrary code in Envoy. "
                          "Audit the inline_code for safety + ensure only "
                          "trusted operators can create EnvoyFilters."),
            evidence_marker=f"Risky filters: {risky[:5]}")], 1,
            f"{len(risky)} Lua filters")
    return _build_resp("envoy_filter_audit", target, [wrap_finding(
        f"{len(filters)} EnvoyFilter resource(s) - no Lua/inline_code patterns",
        "INFO", cvss="0.0", cwe="N/A",
        remediation="Manual review of each EnvoyFilter recommended for "
                    "Istio environments.",
        evidence_marker=f"EnvoyFilter count: {len(filters)}")], 1,
        f"{len(filters)} EnvoyFilters")
