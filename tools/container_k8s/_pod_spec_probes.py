"""K8s Pod/Deployment spec static-analysis probes.

Each probe takes the customer-provided `pod_spec_yaml` input (paste a
K8s Pod, Deployment, StatefulSet, DaemonSet, or Job manifest) and
checks for a specific dangerous setting. All pure-Python YAML parsing
via PyYAML (already in requirements.txt).

Precondition: req.pod_spec_yaml must be present + parseable YAML. If
absent or invalid, returns honest NOT_APPLICABLE.

12 probes wired in container_k8s_pack.py PROBES:
  container_privileged              securityContext.privileged: true
  container_capadd_dangerous        dangerous CAP_ADD entries
  container_host_pid                hostPID: true
  container_host_network            hostNetwork: true
  container_host_ipc                hostIPC: true
  container_hostpath_dangerous      sensitive hostPath volume mounts
  container_docker_sock_mount       /var/run/docker.sock hostPath
  container_runas_root              runAsUser: 0 OR no runAsUser
  container_no_readonly_rootfs      readOnlyRootFilesystem: false / absent
  container_allow_priv_escalation   allowPrivilegeEscalation: true / absent
  container_seccomp_unset           seccompProfile not set
  container_apparmor_unset          AppArmor annotation absent
"""
from __future__ import annotations

from typing import Optional, List, Dict, Any
import yaml

from tools._shared import wrap_finding


_DANGEROUS_CAPS = {
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "SYS_RAWIO", "SYS_BOOT", "BPF", "PERFMON",
    "DAC_READ_SEARCH", "LINUX_IMMUTABLE", "MAC_ADMIN", "MAC_OVERRIDE",
    "NET_RAW", "AUDIT_CONTROL", "SETFCAP",
}

_DANGEROUS_HOSTPATHS = (
    "/", "/etc", "/var", "/var/run", "/var/run/docker.sock", "/var/lib/docker",
    "/var/lib/kubelet", "/proc", "/sys", "/dev", "/root", "/home", "/usr",
    "/boot", "/lib", "/lib64", "/sbin", "/bin",
)


def _ndr(slug: str, target: str, reason: str = ""):
    """NOT_APPLICABLE response when pod_spec_yaml is missing/invalid."""
    return {
        "tool": slug, "target": target, "scan_time": 0,
        "vulnerable": False, "severity": "INFO",
        "findings": [wrap_finding(
            f"[NOT_APPLICABLE] {slug} requires pod_spec_yaml input",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Paste the K8s Pod/Deployment YAML manifest in the "
                          "dashboard's pod_spec_yaml field. Probe will activate "
                          "automatically."),
            evidence_marker=reason or "Required input 'pod_spec_yaml' is empty.",
        )],
        "tests_performed": 0,
        "tests_summary": f"{slug} skipped - missing pod_spec_yaml",
        "raw_data": {"missing_input": "pod_spec_yaml"},
    }


def _build_resp(slug: str, target: str, findings: list, tested: int, summary: str):
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


def _parse_yaml(req) -> Optional[List[Dict[str, Any]]]:
    """Parse pod_spec_yaml. Supports single doc or multi-doc YAML.
    Returns list of K8s resource dicts that have pod-spec semantics."""
    raw = getattr(req, "pod_spec_yaml", None)
    if not raw or not isinstance(raw, str) or not raw.strip():
        return None
    try:
        docs = list(yaml.safe_load_all(raw))
    except Exception:
        return None
    return [d for d in docs if isinstance(d, dict)]


def _extract_pod_specs(docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """From a list of K8s resources, extract the pod template specs.
    Handles: Pod (spec direct), Deployment / StatefulSet / DaemonSet /
    Job / CronJob (spec.template.spec)."""
    out = []
    for d in docs:
        kind = (d.get("kind") or "").lower()
        name = (d.get("metadata") or {}).get("name", "?")
        if kind == "pod":
            spec = d.get("spec")
            if isinstance(spec, dict):
                out.append({"kind": "Pod", "name": name, "spec": spec,
                             "metadata": d.get("metadata") or {}})
        elif kind in ("deployment", "statefulset", "daemonset", "replicaset",
                       "replicationcontroller", "job"):
            template = ((d.get("spec") or {}).get("template") or {})
            spec = template.get("spec")
            if isinstance(spec, dict):
                out.append({"kind": d.get("kind"), "name": name, "spec": spec,
                             "metadata": template.get("metadata") or {}})
        elif kind == "cronjob":
            spec = (((((d.get("spec") or {}).get("jobTemplate") or {})
                       .get("spec") or {}).get("template") or {}).get("spec"))
            if isinstance(spec, dict):
                out.append({"kind": "CronJob", "name": name, "spec": spec,
                             "metadata": {}})
    return out


def _iter_containers(spec: Dict[str, Any]):
    """Yield (container_name, container_dict) for both .containers and
    .initContainers in a PodSpec."""
    for key in ("containers", "initContainers", "ephemeralContainers"):
        for c in (spec.get(key) or []):
            if isinstance(c, dict):
                yield c.get("name", "?"), c


# ─── Probe implementations ───────────────────────────────────────────

def _probe_container_privileged(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_privileged", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_privileged", target,
                     "pod_spec_yaml parsed but contains no Pod/Deployment/etc.")

    findings = []
    privileged_hits = []
    total_containers = 0
    for p in pods:
        for cname, c in _iter_containers(p["spec"]):
            total_containers += 1
            ctx = c.get("securityContext") or {}
            if ctx.get("privileged") is True:
                privileged_hits.append(f"{p['kind']}/{p['name']}:{cname}")

    if privileged_hits:
        findings.append(wrap_finding(
            f"securityContext.privileged: true on {len(privileged_hits)} container(s)",
            "CRITICAL", cvss="9.0", cwe="CWE-250", owasp="A05:2021",
            remediation=("Remove 'privileged: true'. Use targeted capabilities "
                          "via capabilities.add instead. Privileged containers "
                          "bypass nearly all kernel security, equivalent to root "
                          "on the host."),
            evidence_marker=f"Privileged: {', '.join(privileged_hits[:5])}"))
    else:
        findings.append(wrap_finding(
            f"No privileged containers ({total_containers} container(s) audited)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue least-privilege posture.",
            evidence_marker=f"0 of {total_containers} containers have privileged:true"))
    return _build_resp("container_privileged", target, findings,
                       total_containers, "Privileged-container audit")


def _probe_container_capadd_dangerous(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_capadd_dangerous", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_capadd_dangerous", target, "no pod specs")

    findings = []
    dangerous = []
    total = 0
    for p in pods:
        for cname, c in _iter_containers(p["spec"]):
            total += 1
            ctx = c.get("securityContext") or {}
            caps = (ctx.get("capabilities") or {}).get("add") or []
            for cap in caps:
                cap_up = str(cap).upper().replace("CAP_", "")
                if cap_up in _DANGEROUS_CAPS:
                    dangerous.append(f"{p['kind']}/{p['name']}:{cname} CAP_{cap_up}")

    if dangerous:
        findings.append(wrap_finding(
            f"Dangerous CAP_ADD on {len(dangerous)} container(s)",
            "HIGH", cvss="8.0", cwe="CWE-250",
            remediation=("Drop dangerous Linux capabilities. CAP_SYS_ADMIN, "
                          "CAP_NET_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE expand "
                          "container-escape surface. Only add the minimum caps "
                          "your app strictly requires."),
            evidence_marker=", ".join(dangerous[:5])))
    else:
        findings.append(wrap_finding(
            "No dangerous CAP_ADD in pod spec",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue least-capabilities posture.",
            evidence_marker=f"Probed {total} containers; 0 dangerous capabilities added"))
    return _build_resp("container_capadd_dangerous", target, findings, total,
                       "Dangerous capability audit")


def _probe_container_host_pid(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_host_pid", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_host_pid", target, "no pod specs")

    hits = [f"{p['kind']}/{p['name']}" for p in pods
             if p["spec"].get("hostPID") is True]
    if hits:
        return _build_resp("container_host_pid", target, [wrap_finding(
            f"hostPID: true on {len(hits)} pod(s)",
            "HIGH", cvss="8.0", cwe="CWE-668",
            remediation=("Remove hostPID: true. Sharing the host PID namespace "
                          "lets containers see + signal every process on the "
                          "node, including kubelet + container runtime."),
            evidence_marker=f"hostPID:true: {', '.join(hits[:5])}")], len(pods),
            f"hostPID audit ({len(hits)} hit(s))")
    return _build_resp("container_host_pid", target, [wrap_finding(
        f"No hostPID:true ({len(pods)} pod spec(s) audited)",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue host-PID isolation.",
        evidence_marker="0 pods set hostPID:true")], len(pods), "hostPID audit")


def _probe_container_host_network(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_host_network", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_host_network", target, "no pod specs")

    hits = [f"{p['kind']}/{p['name']}" for p in pods
             if p["spec"].get("hostNetwork") is True]
    if hits:
        return _build_resp("container_host_network", target, [wrap_finding(
            f"hostNetwork: true on {len(hits)} pod(s)",
            "HIGH", cvss="7.5", cwe="CWE-668",
            remediation=("Remove hostNetwork:true. Containers share the host "
                          "network namespace, bypassing NetworkPolicy + service "
                          "mesh enforcement, and gaining direct access to all "
                          "host network interfaces."),
            evidence_marker=f"hostNetwork:true: {', '.join(hits[:5])}")], len(pods),
            f"hostNetwork audit ({len(hits)} hit(s))")
    return _build_resp("container_host_network", target, [wrap_finding(
        f"No hostNetwork:true ({len(pods)} pod spec(s) audited)",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue network namespace isolation.",
        evidence_marker="0 pods set hostNetwork:true")], len(pods), "hostNetwork audit")


def _probe_container_host_ipc(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_host_ipc", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_host_ipc", target, "no pod specs")

    hits = [f"{p['kind']}/{p['name']}" for p in pods
             if p["spec"].get("hostIPC") is True]
    if hits:
        return _build_resp("container_host_ipc", target, [wrap_finding(
            f"hostIPC: true on {len(hits)} pod(s)",
            "HIGH", cvss="7.5", cwe="CWE-668",
            remediation=("Remove hostIPC:true. Shared host IPC lets containers "
                          "communicate with host processes via SysV IPC, message "
                          "queues, shared memory - bypassing isolation."),
            evidence_marker=f"hostIPC:true: {', '.join(hits[:5])}")], len(pods),
            f"hostIPC audit ({len(hits)} hit(s))")
    return _build_resp("container_host_ipc", target, [wrap_finding(
        f"No hostIPC:true ({len(pods)} pod spec(s) audited)",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue IPC namespace isolation.",
        evidence_marker="0 pods set hostIPC:true")], len(pods), "hostIPC audit")


def _probe_container_hostpath_dangerous(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_hostpath_dangerous", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_hostpath_dangerous", target, "no pod specs")

    findings = []
    dangerous = []
    total_volumes = 0
    for p in pods:
        for v in (p["spec"].get("volumes") or []):
            if not isinstance(v, dict):
                continue
            total_volumes += 1
            hp = v.get("hostPath")
            if not hp:
                continue
            path = (hp.get("path") or "").rstrip("/") or hp.get("path")
            if path and (path in _DANGEROUS_HOSTPATHS
                          or path.startswith("/proc/")
                          or path.startswith("/sys/")
                          or path.startswith("/dev/")):
                dangerous.append(f"{p['kind']}/{p['name']} vol={v.get('name','?')} path={path}")

    if dangerous:
        findings.append(wrap_finding(
            f"Dangerous hostPath mount(s): {len(dangerous)}",
            "CRITICAL", cvss="9.0", cwe="CWE-668", owasp="A05:2021",
            remediation=("hostPath volumes pointing to /, /etc, /var, /proc, /sys, "
                          "/dev allow direct host filesystem access from inside the "
                          "container. Remove or restrict to a specific app data "
                          "subdirectory. Better: use a PersistentVolume."),
            evidence_marker="; ".join(dangerous[:5])))
    else:
        findings.append(wrap_finding(
            f"No dangerous hostPath mounts ({total_volumes} volume(s) audited)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue safe-volume posture.",
            evidence_marker=f"0 hostPath volumes hit the dangerous-path catalog "
                              f"(checked {len(_DANGEROUS_HOSTPATHS)} sensitive paths)"))
    return _build_resp("container_hostpath_dangerous", target, findings,
                       total_volumes, "hostPath danger audit")


def _probe_container_docker_sock_mount(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_docker_sock_mount", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_docker_sock_mount", target, "no pod specs")

    hits = []
    for p in pods:
        for v in (p["spec"].get("volumes") or []):
            if not isinstance(v, dict):
                continue
            hp = v.get("hostPath")
            if hp and "docker.sock" in (hp.get("path") or ""):
                hits.append(f"{p['kind']}/{p['name']} vol={v.get('name','?')}")

    if hits:
        return _build_resp("container_docker_sock_mount", target, [wrap_finding(
            f"docker.sock mounted into {len(hits)} pod(s)",
            "CRITICAL", cvss="9.5", cwe="CWE-269", owasp="A04:2021",
            remediation=("Mounting /var/run/docker.sock is equivalent to root on "
                          "the node. Any container can launch privileged containers, "
                          "mount host filesystems, exfiltrate secrets. Remove the "
                          "mount. If CI/CD needs docker, use rootless buildkit or "
                          "kaniko instead."),
            evidence_marker="; ".join(hits[:5]))], len(pods),
            f"docker.sock mount audit ({len(hits)} hit(s))")
    return _build_resp("container_docker_sock_mount", target, [wrap_finding(
        "No docker.sock hostPath mounts",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue current posture.",
        evidence_marker=f"0 of {sum(len(p['spec'].get('volumes') or []) for p in pods)} "
                          "volumes mount docker.sock")], len(pods),
        "docker.sock mount audit")


def _probe_container_runas_root(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_runas_root", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_runas_root", target, "no pod specs")

    findings = []
    root_hits = []
    nonroot_hits = []
    unset_hits = []
    total = 0
    for p in pods:
        pod_ctx = p["spec"].get("securityContext") or {}
        pod_uid = pod_ctx.get("runAsUser")
        for cname, c in _iter_containers(p["spec"]):
            total += 1
            cctx = c.get("securityContext") or {}
            uid = cctx.get("runAsUser", pod_uid)
            label = f"{p['kind']}/{p['name']}:{cname}"
            if uid == 0:
                root_hits.append(label)
            elif uid is None:
                unset_hits.append(label)
            else:
                nonroot_hits.append(label)

    if root_hits:
        findings.append(wrap_finding(
            f"runAsUser:0 (root) explicitly set on {len(root_hits)} container(s)",
            "HIGH", cvss="7.5", cwe="CWE-250",
            remediation=("Change runAsUser to a non-zero UID. Combine with "
                          "runAsNonRoot: true so K8s admission refuses any image "
                          "that ships as root."),
            evidence_marker=", ".join(root_hits[:5])))
    if unset_hits:
        findings.append(wrap_finding(
            f"runAsUser unset on {len(unset_hits)} container(s) - "
            f"will use image default (often root)",
            "MEDIUM", cvss="5.5", cwe="CWE-250",
            remediation=("Set runAsUser explicitly to a non-zero UID, or set "
                          "runAsNonRoot: true to fail-fast at admission for "
                          "root-only images."),
            evidence_marker=", ".join(unset_hits[:5])))
    if not findings:
        findings.append(wrap_finding(
            f"All {len(nonroot_hits)} container(s) run as non-root",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue non-root posture.",
            evidence_marker=f"Non-root: {len(nonroot_hits)}, "
                              f"explicit-root: 0, unset: 0"))
    return _build_resp("container_runas_root", target, findings, total,
                       "runAsUser audit")


def _probe_container_no_readonly_rootfs(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_no_readonly_rootfs", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_no_readonly_rootfs", target, "no pod specs")

    rw_hits = []
    ro_hits = []
    total = 0
    for p in pods:
        for cname, c in _iter_containers(p["spec"]):
            total += 1
            ctx = c.get("securityContext") or {}
            ro = ctx.get("readOnlyRootFilesystem")
            label = f"{p['kind']}/{p['name']}:{cname}"
            if ro is True:
                ro_hits.append(label)
            else:
                rw_hits.append(label)

    if rw_hits:
        return _build_resp("container_no_readonly_rootfs", target, [wrap_finding(
            f"readOnlyRootFilesystem not enabled on {len(rw_hits)} container(s)",
            "MEDIUM", cvss="5.5", cwe="CWE-732",
            remediation=("Set securityContext.readOnlyRootFilesystem: true. "
                          "Use emptyDir volumes for paths that need write access "
                          "(/tmp, /var/cache, etc.). Stops attackers from writing "
                          "malware to the container filesystem post-compromise."),
            evidence_marker=f"Writable rootfs: {', '.join(rw_hits[:5])}; "
                              f"read-only: {len(ro_hits)}")], total,
            f"readOnlyRootFilesystem audit ({len(rw_hits)} writable)")
    return _build_resp("container_no_readonly_rootfs", target, [wrap_finding(
        f"All {len(ro_hits)} container(s) have readOnlyRootFilesystem:true",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue read-only-rootfs posture.",
        evidence_marker=f"Read-only rootfs: {len(ro_hits)} of {total}")], total,
        "readOnlyRootFilesystem audit (all read-only)")


def _probe_container_allow_priv_escalation(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_allow_priv_escalation", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_allow_priv_escalation", target, "no pod specs")

    bad = []
    good = []
    total = 0
    for p in pods:
        for cname, c in _iter_containers(p["spec"]):
            total += 1
            ctx = c.get("securityContext") or {}
            ape = ctx.get("allowPrivilegeEscalation")
            label = f"{p['kind']}/{p['name']}:{cname}"
            # Default is True if unset - flag as bad.
            if ape is False:
                good.append(label)
            else:
                bad.append(label)

    if bad:
        return _build_resp("container_allow_priv_escalation", target, [wrap_finding(
            f"allowPrivilegeEscalation not explicitly false on {len(bad)} container(s)",
            "HIGH", cvss="7.5", cwe="CWE-250",
            remediation=("Set securityContext.allowPrivilegeEscalation: false. "
                          "Default is true, which permits setuid binaries inside "
                          "the container to gain capabilities the pod did not "
                          "originally have."),
            evidence_marker=f"Escalation-allowed: {', '.join(bad[:5])}; "
                              f"explicit-false: {len(good)}")], total,
            f"allowPrivilegeEscalation audit ({len(bad)} not-locked-down)")
    return _build_resp("container_allow_priv_escalation", target, [wrap_finding(
        f"All {len(good)} container(s) have allowPrivilegeEscalation:false",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue privilege-escalation-blocked posture.",
        evidence_marker=f"Locked down: {len(good)} of {total}")], total,
        "allowPrivilegeEscalation audit (all locked)")


def _probe_container_seccomp_unset(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_seccomp_unset", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_seccomp_unset", target, "no pod specs")

    bad = []
    good = []
    for p in pods:
        pod_seccomp = ((p["spec"].get("securityContext") or {})
                         .get("seccompProfile") or {}).get("type")
        # Newer K8s syntax: seccompProfile.type = RuntimeDefault / Localhost / Unconfined
        for cname, c in _iter_containers(p["spec"]):
            cctx = c.get("securityContext") or {}
            sec = (cctx.get("seccompProfile") or {}).get("type", pod_seccomp)
            label = f"{p['kind']}/{p['name']}:{cname}"
            if sec in ("RuntimeDefault", "Localhost"):
                good.append(f"{label}={sec}")
            else:
                bad.append(label)

    total = len(bad) + len(good)
    if bad:
        return _build_resp("container_seccomp_unset", target, [wrap_finding(
            f"seccompProfile unset on {len(bad)} container(s)",
            "MEDIUM", cvss="5.5", cwe="CWE-693",
            remediation=("Set securityContext.seccompProfile.type: RuntimeDefault "
                          "(or Localhost for custom profile). Blocks ~80% of "
                          "syscalls the container doesn't need - kills most "
                          "container-escape kernel exploits before they execute."),
            evidence_marker=f"No seccomp: {', '.join(bad[:5])}; "
                              f"with seccomp: {len(good)}")], total,
            f"seccompProfile audit ({len(bad)} unset)")
    return _build_resp("container_seccomp_unset", target, [wrap_finding(
        f"All {len(good)} container(s) have seccompProfile set",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue seccomp-enforced posture.",
        evidence_marker=f"All seccomp-enforced: {good[:3]}")], total,
        "seccompProfile audit (all set)")


def _probe_container_apparmor_unset(target, req):
    docs = _parse_yaml(req)
    if docs is None:
        return _ndr("container_apparmor_unset", target)
    pods = _extract_pod_specs(docs)
    if not pods:
        return _ndr("container_apparmor_unset", target, "no pod specs")

    # AppArmor in K8s is set via pod annotations:
    #   container.apparmor.security.beta.kubernetes.io/<container>: <profile>
    # In K8s 1.30+ also supported via securityContext.appArmorProfile.
    bad = []
    good = []
    for p in pods:
        annotations = (p["metadata"] or {}).get("annotations") or {}
        for cname, c in _iter_containers(p["spec"]):
            label = f"{p['kind']}/{p['name']}:{cname}"
            ann_key = f"container.apparmor.security.beta.kubernetes.io/{cname}"
            cctx = c.get("securityContext") or {}
            modern = (cctx.get("appArmorProfile") or {}).get("type")
            legacy = annotations.get(ann_key)
            if modern in ("RuntimeDefault", "Localhost") or legacy in (
                "runtime/default",) or (legacy and legacy.startswith("localhost/")):
                good.append(label)
            else:
                bad.append(label)

    total = len(bad) + len(good)
    if bad:
        return _build_resp("container_apparmor_unset", target, [wrap_finding(
            f"AppArmor not set on {len(bad)} container(s)",
            "MEDIUM", cvss="5.5", cwe="CWE-693",
            remediation=("Add pod annotation 'container.apparmor.security.beta."
                          "kubernetes.io/<container>: runtime/default' (legacy) "
                          "or securityContext.appArmorProfile.type: RuntimeDefault "
                          "(K8s 1.30+). Complements seccomp at the LSM layer."),
            evidence_marker=f"No AppArmor: {', '.join(bad[:5])}; "
                              f"with AppArmor: {len(good)}")], total,
            f"AppArmor audit ({len(bad)} unset)")
    return _build_resp("container_apparmor_unset", target, [wrap_finding(
        f"All {len(good)} container(s) have AppArmor set",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue AppArmor posture.",
        evidence_marker=f"All AppArmor-enforced: {good[:3]}")], total,
        "AppArmor audit (all set)")
