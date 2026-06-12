"""container_privesc_surface_probe - findings rules.

Severity model (zero false positives):
  CRITICAL - the Docker Engine API answered an UNAUTHENTICATED /version or
             /info request. Anyone who can reach this port owns the host
             (mount / as a volume in a container = instant root). Stamped
             verified_exploit=True (we received a real Docker API JSON body).
  HIGH     - the kubelet read-only / API port answered an UNAUTHENTICATED
             request returning node/pod data. Stamped verified_exploit=True.
  INFO     - a TLS-protected Docker/k8s endpoint was reachable but DID NOT
             answer without auth (good — reachable but not open). Not a finding.
  INFO     - [ADVISORY-BY-DESIGN] the §7 container/cloud privesc catalogue
             that requires on-host / in-cluster context to verify (IMDS->IAM,
             privileged container, capability escape, runc Leaky Vessels,
             EKS IRSA, K8s RBAC). Always INFO.
  INFO     - probe could not run / nothing exposed.

A graded severity is emitted ONLY when an exposed control-plane endpoint
ACTUALLY returned data without authentication. Reachability alone (open port,
TLS handshake) is INFO, never graded.
"""


def rule_docker_api_open(s):
    hits = s.get("cps_docker_open") or []
    if not hits:
        return None
    sample = ", ".join(f"{h.get('endpoint')} ({h.get('detail', '')[:40]})"
                       for h in hits[:4])
    return {
        "name": "Unauthenticated Docker Engine API exposed",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": "A01:2021",
        "verified_exploit": True,
        "evidence": (
            f"The Docker Engine API answered an UNAUTHENTICATED request on: "
            f"{sample}. Anyone who can reach this port can create a container "
            "that bind-mounts the host root filesystem and obtain instant root "
            "on the host (a textbook container-to-host privilege escalation). "
            "This is a direct observation — the API returned a real Docker JSON "
            "body without credentials."
        ),
        "remediation": (
            "1. NEVER expose the Docker daemon TCP socket (2375/2376) to any "
            "untrusted network. Bind it to localhost or use the unix socket only. "
            "2. If remote access is required, enable mutual TLS (2376 + "
            "--tlsverify with client certs) and a firewall allow-list. "
            "3. Audit who can reach this port now and rotate any secrets the host "
            "may hold. Reference: Docker 'Protect the Docker daemon socket'."
        ),
    }


def rule_kubelet_open(s):
    hits = s.get("cps_kubelet_open") or []
    if not hits:
        return None
    sample = ", ".join(f"{h.get('endpoint')} ({h.get('detail', '')[:40]})"
                       for h in hits[:4])
    return {
        "name": "Unauthenticated Kubernetes kubelet / API endpoint exposed",
        "severity": "HIGH",
        "cvss": "8.6",
        "cwe": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": "A01:2021",
        "verified_exploit": True,
        "evidence": (
            f"A Kubernetes node endpoint answered an UNAUTHENTICATED request on: "
            f"{sample}. An open kubelet (10250) or anonymous-auth API server can "
            "leak pod specs, environment secrets, and in many configurations "
            "allow command execution inside running pods — a path to cluster and "
            "node privilege escalation. This is a direct observation — the "
            "endpoint returned data without credentials."
        ),
        "remediation": (
            "1. Set kubelet --anonymous-auth=false and --authorization-mode=Webhook. "
            "2. Disable the deprecated read-only port (--read-only-port=0). "
            "3. On the API server set --anonymous-auth=false and enforce RBAC. "
            "4. Restrict 6443/10250/10255 to the control-plane network only. "
            "Reference: CIS Kubernetes Benchmark kubelet section."
        ),
    }


def rule_reachable_not_open(s):
    # Endpoints that were reachable (port/TLS up) but correctly required auth.
    reach = s.get("cps_reachable_protected") or []
    if not reach:
        return None
    if s.get("cps_docker_open") or s.get("cps_kubelet_open"):
        return None
    sample = ", ".join(reach[:6])
    return {
        "name": "Container control-plane port reachable but authentication enforced",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (
            f"These container/orchestration control-plane endpoints were reachable "
            f"from the scanner but rejected the unauthenticated probe (good): "
            f"{sample}. Reachability is reported for surface awareness; it is NOT "
            "a finding because the endpoint enforced authentication."
        ),
        "remediation": (
            "Confirm these ports are intentionally reachable from the scanner's "
            "vantage point and firewalled to trusted networks only. Keep "
            "authentication/TLS enforced."
        ),
    }


# §7 container/cloud catalogue that genuinely needs on-host / in-cluster
# context. Surfaced as honest advisory-by-design INFO, never graded.
_ADVISORY_CATALOGUE = [
    ("Cloud metadata service (IMDSv1) -> IAM credential theft",
     "169.254.169.254 is link-local and only reachable FROM the instance (or "
     "via an SSRF chain). Enforce IMDSv2 (hop-limit 1, tokens required); not "
     "remotely confirmable from an external SaaS scan."),
    ("Docker socket bind-mount inside a container (/var/run/docker.sock)",
     "Requires inspecting container mounts on the host. If a container mounts "
     "the docker socket, it can spawn a privileged sibling and own the host."),
    ("Privileged container / --privileged or added capabilities",
     "Requires reading the container runtime config on the host (capsh --print, "
     "/proc/1/status CapEff). cap_sys_admin / cap_dac_read_search enable escape."),
    ("runc Leaky Vessels (CVE-2024-21626) container breakout",
     "Requires the runc/containerd version on the host. Patch runc >= 1.1.12; "
     "not observable from an external port scan."),
    ("Kubernetes RBAC privilege escalation (escalate/bind/impersonate verbs)",
     "Requires in-cluster credentials and a RBAC graph (KubeHound). Audit "
     "ClusterRoles granting escalate/bind/impersonate or wildcard verbs."),
    ("EKS IRSA / Workload Identity token abuse",
     "Requires the pod's projected service-account token + cloud IAM context. "
     "Audit trust policies and least-privilege on the IRSA role."),
]


def rule_advisory_catalogue(s):
    if not s.get("cps_ran"):
        return None
    lines = [f"- {title}: {how}" for title, how in _ADVISORY_CATALOGUE]
    return {
        "name": ("[ADVISORY-BY-DESIGN] Container / cloud privilege-escalation "
                 "catalogue (on-host / in-cluster verification required)"),
        "severity": "INFO",
        "cwe": "CWE-1395",
        "owasp": "N/A",
        "evidence": (
            "These §7 techniques require a foothold inside a container, on the "
            "host, or in the cluster (mount table, capability set, runc version, "
            "RBAC graph, projected SA token, instance metadata). They cannot be "
            "confirmed from an external SaaS scan and are surfaced as advisory so "
            "the report is complete, NOT as detected vulnerabilities:\n"
            + "\n".join(lines)
        ),
        "remediation": (
            "Run the in-context checks listed per item (capsh --print, inspect "
            "container mounts, runc --version, kubectl auth can-i --list, enforce "
            "IMDSv2). Reference: module_playbooks/12_privesc.md section 7; "
            "https://github.com/DataDog/KubeHound ; Docker/Kubernetes hardening guides."
        ),
    }


def rule_probe_error(s):
    if not s.get("cps_ran"):
        err = ("no target supplied" if s.get("cps_no_target")
               else (s.get("cps_error") or "probe did not run"))
        return {
            "name": "Container privesc-surface probe could not run",
            "severity": "INFO",
            "cwe": "CWE-1006",
            "evidence": f"{s.get('cps_target', '?')}: {err}.",
            "remediation": (
                "Confirm the target is reachable from the scanner, then re-run."
            ),
        }
    # Ran, nothing exposed, nothing reachable -> clean INFO baseline.
    if (not s.get("cps_docker_open") and not s.get("cps_kubelet_open")
            and not s.get("cps_reachable_protected")):
        return {
            "name": "No exposed container / orchestration control plane detected",
            "severity": "INFO",
            "cwe": "CWE-200",
            "evidence": (
                f"{s.get('cps_target', '?')}: none of the probed Docker / "
                "Kubernetes control-plane ports (2375/2376/6443/10250/10255) "
                "responded to an unauthenticated request. Good — no externally "
                "exposed container control plane was observed from this vantage."
            ),
            "remediation": (
                "Keep container/orchestration control-plane ports off untrusted "
                "networks. For on-host container privesc, see the advisory item."
            ),
        }
    return None


CONTAINER_PRIVESC_SURFACE_PROBE_FINDING_RULES = [
    rule_docker_api_open,
    rule_kubelet_open,
    rule_reachable_not_open,
    rule_advisory_catalogue,
    rule_probe_error,
]
