"""Container escape CVE detectors via kubeconfig (node container-runtime
version inspection) or pod_spec_yaml (capability + mount checks).

Banner-based detection - cluster reveals container-runtime version
in node.status.nodeInfo.containerRuntimeVersion. Compare against
known-vulnerable ranges per CVE.

CVE -> vulnerable range catalog (curated 2024-Q4):
  CVE-2024-21626  Leaky Vessels (runc /proc fd escape)
                  Affected: runc < 1.1.12
                  Fix: runc 1.1.12+
  CVE-2022-23648  containerd CVE (host filesystem leak via OCI bind)
                  Affected: containerd < 1.6.10, < 1.5.16, < 1.4.13
                  Fix: containerd 1.6.10+
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional, Tuple

from tools._shared import wrap_finding


def _ndr(slug, target, reason=""):
    return {
        "tool": slug, "target": target, "scan_time": 0,
        "vulnerable": False, "severity": "INFO",
        "findings": [wrap_finding(
            f"[NOT_APPLICABLE] {slug} requires kubeconfig YAML input",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Paste kubeconfig in the dashboard field. Probe auto-activates.",
            evidence_marker=reason or "kubeconfig empty",
        )],
        "tests_performed": 0,
        "tests_summary": f"{slug} skipped - missing kubeconfig",
        "_skipped": True,
        "skipped_reason": "kubeconfig not provided (image-target scan)",
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


def _get_kubeconfig(req):
    kc = getattr(req, "kubeconfig", None)
    if not kc or not isinstance(kc, str) or not kc.strip():
        return None
    return kc


def _get_node_runtimes(kubeconfig_text) -> Tuple[int, list]:
    """Return (exit_code, [{node, runtime_name, runtime_version, kernel}, ...])."""
    if shutil.which("kubectl") is None:
        return 127, []
    fd, path = tempfile.mkstemp(prefix="vl-kc-", suffix=".yaml")
    try:
        os.write(fd, kubeconfig_text.encode("utf-8")); os.close(fd); os.chmod(path, 0o600)
        env = os.environ.copy()
        env["KUBECONFIG"] = path
        proc = subprocess.run(
            ["kubectl", "get", "nodes", "-o", "json"],
            capture_output=True, text=True, timeout=20, env=env, check=False)
    except Exception:
        return 1, []
    finally:
        try:
            with open(path, "wb") as f: f.write(b"\x00" * 1024)
            os.unlink(path)
        except Exception:
            pass
    if proc.returncode != 0:
        return proc.returncode, []
    try:
        data = json.loads(proc.stdout or "{}")
    except Exception:
        return 1, []
    out = []
    for n in data.get("items", []):
        info = (n.get("status") or {}).get("nodeInfo") or {}
        crv = info.get("containerRuntimeVersion", "")  # e.g. "containerd://1.6.9"
        match = re.match(r"^([a-zA-Z]+)://([0-9][0-9A-Za-z.\-+_]*)", crv)
        runtime_name, runtime_version = ("?", "?")
        if match:
            runtime_name = match.group(1).lower()
            runtime_version = match.group(2)
        out.append({
            "node": (n.get("metadata") or {}).get("name", "?"),
            "runtime_name": runtime_name,
            "runtime_version": runtime_version,
            "kernel": info.get("kernelVersion", "?"),
            "os_image": info.get("osImage", "?"),
        })
    return 0, out


def _semver_lt(a: str, b: str) -> bool:
    """True if a < b in semver-ish ordering. Strips +/-suffixes."""
    def parts(s):
        s = re.sub(r"[+\-].*", "", s)
        return tuple(int(x) if x.isdigit() else 0
                      for x in s.split("."))
    try:
        return parts(a) < parts(b)
    except Exception:
        return False


def _probe_escape_leaky_vessels_runc(target, req):
    """CVE-2024-21626 - runc < 1.1.12 fd escape via /proc/self/fd."""
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("escape_leaky_vessels_runc_2024", target)
    ec, nodes = _get_node_runtimes(kc)
    if ec == 127:
        return _build_resp("escape_leaky_vessels_runc_2024", target, [wrap_finding(
            "[NOT IMPLEMENTED] kubectl missing", "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend.", evidence_marker="kubectl not in PATH")], 0,
            "kubectl missing")
    if ec != 0 or not nodes:
        return _build_resp("escape_leaky_vessels_runc_2024", target, [wrap_finding(
            "Cannot enumerate cluster nodes",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig has nodes:list permission.",
            evidence_marker=f"kubectl get nodes exit {ec}, parsed nodes: {len(nodes)}")], 0,
            "node enum failed")

    # runc version isn't always exposed via nodeInfo (containerd often hides it).
    # Use containerd version as proxy: containerd >= 1.6.28 / 1.7.13 ship patched runc.
    # When runtime is containerd, check containerd version.
    vulnerable_nodes = []
    safe_nodes = []
    unknown_nodes = []
    for n in nodes:
        rt = n["runtime_name"]
        ver = n["runtime_version"]
        if rt == "containerd":
            # containerd 1.7.13+ / 1.6.28+ bundle patched runc 1.1.12
            if _semver_lt(ver, "1.6.28") and not (
                ver.startswith("1.5.") or ver.startswith("1.4.")):
                vulnerable_nodes.append(f"{n['node']} containerd={ver}")
            elif (ver.startswith("1.7.") and _semver_lt(ver, "1.7.13")):
                vulnerable_nodes.append(f"{n['node']} containerd={ver}")
            else:
                safe_nodes.append(f"{n['node']} containerd={ver}")
        elif rt == "docker":
            # Docker bundles its own runc. Docker 26.0+ ships patched runc.
            if _semver_lt(ver, "26.0.0"):
                vulnerable_nodes.append(f"{n['node']} docker={ver}")
            else:
                safe_nodes.append(f"{n['node']} docker={ver}")
        else:
            unknown_nodes.append(f"{n['node']} runtime={rt}/{ver}")

    if vulnerable_nodes:
        return _build_resp("escape_leaky_vessels_runc_2024", target, [wrap_finding(
            f"Leaky Vessels CVE-2024-21626 likely on {len(vulnerable_nodes)} node(s)",
            "HIGH", cvss="8.6", cwe="CWE-269", owasp="A06:2021",
            remediation=("Patch container runtime: containerd >= 1.6.28 / "
                          "1.7.13 OR docker >= 26.0 (both ship runc 1.1.12+ "
                          "with the fix). Until patched, restrict pod creation "
                          "permissions and audit /proc/*/fd reads in runtime "
                          "logs."),
            evidence_marker=f"Vulnerable: {vulnerable_nodes[:5]}; Safe: {len(safe_nodes)}")], 1,
            f"runc CVE-2024-21626 likely on {len(vulnerable_nodes)} nodes")
    if safe_nodes and not unknown_nodes:
        return _build_resp("escape_leaky_vessels_runc_2024", target, [wrap_finding(
            f"All {len(safe_nodes)} node(s) running patched container runtime",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue patch posture.",
            evidence_marker=f"Patched runtimes: {safe_nodes[:5]}")], 1,
            "all nodes patched")
    return _build_resp("escape_leaky_vessels_runc_2024", target, [wrap_finding(
        f"Could not determine runtime patch status on {len(unknown_nodes)} node(s)",
        "INFO", cvss="0.0", cwe="N/A",
        remediation="Inspect node container-runtime version manually + cross-reference CVE-2024-21626.",
        evidence_marker=f"Unknown: {unknown_nodes[:5]}; Safe: {len(safe_nodes)}")], 1,
        "runtime version uncertain")


def _probe_escape_containerd_2022_23648(target, req):
    """CVE-2022-23648 - containerd image-pull host-filesystem leak."""
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("escape_containerd_cve_2022_23648", target)
    ec, nodes = _get_node_runtimes(kc)
    if ec == 127:
        return _build_resp("escape_containerd_cve_2022_23648", target, [wrap_finding(
            "[NOT IMPLEMENTED] kubectl missing", "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend.", evidence_marker="kubectl missing")], 0,
            "kubectl missing")
    if ec != 0:
        return _build_resp("escape_containerd_cve_2022_23648", target, [wrap_finding(
            "Cannot enumerate nodes", "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig permissions.",
            evidence_marker=f"exit {ec}")], 0, "node enum failed")

    vulnerable = []
    safe = []
    for n in nodes:
        if n["runtime_name"] != "containerd":
            continue
        ver = n["runtime_version"]
        # Patched: 1.6.10+, 1.5.16+, 1.4.13+
        if ver.startswith("1.4.") and _semver_lt(ver, "1.4.13"):
            vulnerable.append(f"{n['node']} containerd={ver}")
        elif ver.startswith("1.5.") and _semver_lt(ver, "1.5.16"):
            vulnerable.append(f"{n['node']} containerd={ver}")
        elif ver.startswith("1.6.") and _semver_lt(ver, "1.6.10"):
            vulnerable.append(f"{n['node']} containerd={ver}")
        elif _semver_lt(ver, "1.4.0"):
            vulnerable.append(f"{n['node']} containerd={ver} (very old)")
        else:
            safe.append(f"{n['node']} containerd={ver}")

    if vulnerable:
        return _build_resp("escape_containerd_cve_2022_23648", target, [wrap_finding(
            f"containerd CVE-2022-23648 on {len(vulnerable)} node(s)",
            "HIGH", cvss="7.5", cwe="CWE-22", owasp="A01:2021",
            remediation=("Upgrade containerd to 1.6.10+, 1.5.16+, or 1.4.13+. "
                          "Vulnerable versions allow OCI image pull with "
                          "specially-crafted symlinks to read host filesystem "
                          "during image extraction."),
            evidence_marker=f"Vulnerable: {vulnerable[:5]}")], 1,
            f"{len(vulnerable)} vulnerable containerd nodes")
    if safe:
        return _build_resp("escape_containerd_cve_2022_23648", target, [wrap_finding(
            f"All {len(safe)} containerd node(s) patched against CVE-2022-23648",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue patch posture.",
            evidence_marker=f"Patched: {safe[:5]}")], 1, "all containerd nodes patched")
    return _build_resp("escape_containerd_cve_2022_23648", target, [wrap_finding(
        "No containerd nodes detected",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="N/A for non-containerd runtimes.",
        evidence_marker=f"Runtimes: {[n['runtime_name'] for n in nodes[:5]]}")], 1,
        "no containerd nodes")


# ---------------------------------------------------------------------------
# Kernel-version escape CVEs (VL-FORGE 2026-06-28 — §8 #94/#95/#96 to 100%)
#
# nodeInfo exposes kernelVersion (e.g. "5.15.0-91-generic"). Distro kernels
# back-port stable fixes WITHOUT bumping the upstream X.Y.Z, so a kernel that
# parses as "vulnerable" by upstream version may already carry the backport.
# We therefore report findings with an explicit "confirm backport" caveat and
# never claim certainty — matching the "likely / uncertain" honesty of the
# runtime-version probes above.
# ---------------------------------------------------------------------------

def _kernel_upstream(kver):
    """Parse 'X.Y.Z-<distro>' -> (X, Y, Z); distro suffix stripped. None on fail."""
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", kver or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _dirty_pipe_vulnerable(kver):
    """CVE-2022-0847. Bug introduced in 5.8; fixed 5.16.11 / 5.15.25 / 5.10.102
    (and 5.17+). True=likely vuln, False=safe, None=unparseable."""
    t = _kernel_upstream(kver)
    if t is None:
        return None
    maj, mn, pa = t
    if maj != 5:
        return False            # <5: bug not yet introduced; >=6: post-fix
    if mn < 8:
        return False            # introduced in 5.8
    if mn == 10:
        return pa < 102
    if mn == 15:
        return pa < 25
    if mn == 16:
        return pa < 11
    if mn >= 17:
        return False            # fixed upstream
    return True                 # 5.8/5.9/5.11-5.14 EOL series: no backport line


def _cgroup_release_agent_vulnerable(kver):
    """CVE-2022-0492. Long-standing logic bug; fixed 5.17 and back-ported to
    5.16.11 / 5.15.25 / 5.10.102 (Feb-2022 stable batch)."""
    t = _kernel_upstream(kver)
    if t is None:
        return None
    maj, mn, pa = t
    if maj >= 6:
        return False
    if maj < 5:
        return True             # old kernel, predates fix
    if mn >= 17:
        return False
    if mn == 16:
        return pa < 11
    if mn == 15:
        return pa < 25
    if mn == 10:
        return pa < 102
    return True                 # other 5.x series without a backport line


def _probe_escape_dirty_pipe(target, req):
    """§8 #94 — Dirty Pipe (CVE-2022-0847): arbitrary overwrite of read-only
    files via pipe page-cache, usable for container-to-host escape."""
    slug = "escape_dirty_pipe_2022_0847"
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr(slug, target)
    ec, nodes = _get_node_runtimes(kc)
    if ec == 127:
        return _build_resp(slug, target, [wrap_finding(
            "[NOT IMPLEMENTED] kubectl missing", "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend.", evidence_marker="kubectl missing")], 0,
            "kubectl missing")
    if ec != 0 or not nodes:
        return _build_resp(slug, target, [wrap_finding(
            "Cannot enumerate cluster nodes", "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig has nodes:list permission.",
            evidence_marker=f"exit {ec}, nodes {len(nodes)}")], 0, "node enum failed")

    vuln, safe, unknown = [], [], []
    for n in nodes:
        v = _dirty_pipe_vulnerable(n["kernel"])
        tag = f"{n['node']} kernel={n['kernel']}"
        (vuln if v is True else safe if v is False else unknown).append(tag)

    if vuln:
        return _build_resp(slug, target, [wrap_finding(
            f"Dirty Pipe CVE-2022-0847 likely on {len(vuln)} node(s)",
            "HIGH", cvss="7.8", cwe="CWE-281", owasp="A06:2021",
            remediation=("Patch kernel to >= 5.16.11 / 5.15.25 / 5.10.102 (or "
                          "5.17+). Distro back-ports may already fix this at the "
                          "same upstream version — confirm with the vendor "
                          "advisory before treating as exploitable. Mitigate by "
                          "dropping CAP_DAC_OVERRIDE and enforcing read-only "
                          "rootfs + seccomp until patched."),
            evidence_marker=f"Vulnerable: {vuln[:5]}; Safe: {len(safe)}; Unknown: {len(unknown)}")],
            len(nodes), f"Dirty Pipe likely on {len(vuln)} nodes")
    if safe and not unknown:
        return _build_resp(slug, target, [wrap_finding(
            f"All {len(safe)} node kernel(s) past the Dirty Pipe fix",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue patch posture.",
            evidence_marker=f"Safe kernels: {safe[:5]}")], len(nodes), "all nodes patched")
    return _build_resp(slug, target, [wrap_finding(
        f"Could not determine Dirty Pipe status on {len(unknown)} node(s)",
        "INFO", cvss="0.0", cwe="N/A",
        remediation="Inspect kernel version manually + cross-reference CVE-2022-0847.",
        evidence_marker=f"Unknown: {unknown[:5]}; Safe: {len(safe)}")], len(nodes),
        "kernel version uncertain")


def _probe_escape_cgroup_release_agent(target, req):
    """§8 #96 — cgroups-v1 release_agent escape (CVE-2022-0492). A privileged
    or CAP_SYS_ADMIN container on an unpatched kernel can write release_agent
    and run a host-side binary as root."""
    slug = "escape_cgroup_release_agent"
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr(slug, target)
    ec, nodes = _get_node_runtimes(kc)
    if ec == 127:
        return _build_resp(slug, target, [wrap_finding(
            "[NOT IMPLEMENTED] kubectl missing", "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend.", evidence_marker="kubectl missing")], 0,
            "kubectl missing")
    if ec != 0 or not nodes:
        return _build_resp(slug, target, [wrap_finding(
            "Cannot enumerate cluster nodes", "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig has nodes:list permission.",
            evidence_marker=f"exit {ec}, nodes {len(nodes)}")], 0, "node enum failed")

    vuln, safe, unknown = [], [], []
    for n in nodes:
        v = _cgroup_release_agent_vulnerable(n["kernel"])
        tag = f"{n['node']} kernel={n['kernel']}"
        (vuln if v is True else safe if v is False else unknown).append(tag)

    if vuln:
        return _build_resp(slug, target, [wrap_finding(
            f"cgroup release_agent escape (CVE-2022-0492) reachable on {len(vuln)} node(s)",
            "HIGH", cvss="7.0", cwe="CWE-269", owasp="A04:2021",
            remediation=("Patch kernel to >= 5.16.11 / 5.15.25 / 5.10.102 (or "
                          "5.17+). Exploitation also requires cgroups-v1 + an "
                          "unconfined container (CAP_SYS_ADMIN or no AppArmor/"
                          "seccomp); enforce Pod Security 'restricted', drop "
                          "CAP_SYS_ADMIN, and move to cgroups-v2 to close the "
                          "path even before patching. Confirm distro back-port "
                          "status before treating as exploitable."),
            evidence_marker=f"Vulnerable: {vuln[:5]}; Safe: {len(safe)}; Unknown: {len(unknown)}")],
            len(nodes), f"release_agent escape likely on {len(vuln)} nodes")
    if safe and not unknown:
        return _build_resp(slug, target, [wrap_finding(
            f"All {len(safe)} node kernel(s) past the CVE-2022-0492 fix",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue patch posture; prefer cgroups-v2.",
            evidence_marker=f"Safe kernels: {safe[:5]}")], len(nodes), "all nodes patched")
    return _build_resp(slug, target, [wrap_finding(
        f"Could not determine CVE-2022-0492 status on {len(unknown)} node(s)",
        "INFO", cvss="0.0", cwe="N/A",
        remediation="Inspect kernel version + cgroup mode manually.",
        evidence_marker=f"Unknown: {unknown[:5]}; Safe: {len(safe)}")], len(nodes),
        "kernel version uncertain")


def _probe_escape_runc_proc_self_exe(target, req):
    """§8 #95 — runc /proc/self/exe overwrite (CVE-2019-5736). Detect via the
    container-runtime version: docker < 18.09.2 or containerd < 1.2.4 bundle
    the vulnerable runc."""
    slug = "escape_proc_self_exe"
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr(slug, target)
    ec, nodes = _get_node_runtimes(kc)
    if ec == 127:
        return _build_resp(slug, target, [wrap_finding(
            "[NOT IMPLEMENTED] kubectl missing", "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend.", evidence_marker="kubectl missing")], 0,
            "kubectl missing")
    if ec != 0 or not nodes:
        return _build_resp(slug, target, [wrap_finding(
            "Cannot enumerate cluster nodes", "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify kubeconfig has nodes:list permission.",
            evidence_marker=f"exit {ec}, nodes {len(nodes)}")], 0, "node enum failed")

    vuln, safe, unknown = [], [], []
    for n in nodes:
        rt, ver = n["runtime_name"], n["runtime_version"]
        if rt == "docker":
            (vuln if _semver_lt(ver, "18.9.2") else safe).append(f"{n['node']} docker={ver}")
        elif rt == "containerd":
            (vuln if _semver_lt(ver, "1.2.4") else safe).append(f"{n['node']} containerd={ver}")
        else:
            unknown.append(f"{n['node']} runtime={rt}/{ver}")

    if vuln:
        return _build_resp(slug, target, [wrap_finding(
            f"runc /proc/self/exe escape (CVE-2019-5736) likely on {len(vuln)} node(s)",
            "HIGH", cvss="8.6", cwe="CWE-78", owasp="A06:2021",
            remediation=("Upgrade the container runtime: docker >= 18.09.2 or "
                          "containerd >= 1.2.4 (both ship patched runc). A "
                          "malicious image/exec can overwrite the host runc "
                          "binary and gain root on the node."),
            evidence_marker=f"Vulnerable: {vuln[:5]}; Safe: {len(safe)}; Unknown: {len(unknown)}")],
            len(nodes), f"CVE-2019-5736 likely on {len(vuln)} nodes")
    if safe and not unknown:
        return _build_resp(slug, target, [wrap_finding(
            f"All {len(safe)} node runtime(s) ship patched runc",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue patch posture.",
            evidence_marker=f"Patched: {safe[:5]}")], len(nodes), "all nodes patched")
    return _build_resp(slug, target, [wrap_finding(
        f"Could not determine CVE-2019-5736 status on {len(unknown)} node(s)",
        "INFO", cvss="0.0", cwe="N/A",
        remediation="Inspect runtime version manually + cross-reference CVE-2019-5736.",
        evidence_marker=f"Unknown: {unknown[:5]}; Safe: {len(safe)}")], len(nodes),
        "runtime version uncertain")
