"""kernel_hypervisor_escape_advisory - findings rules.

Severity model (ALL INFO by design):
  INFO  - [ADVISORY-BY-DESIGN] §7 kernel-exploit catalogue (Dirty COW,
          Dirty Pipe, PwnKit, Baron Samedit, nf_tables UAF, KASLR bypass,
          Windows/macOS kernel chains).
  INFO  - [ADVISORY-BY-DESIGN] §8 hypervisor / container-escape catalogue
          (Leaky Vessels, cgroup release_agent, privileged container,
          KVM/Hyper-V/ESXi/gVisor/Kata, TEE/SGX/TrustZone).
  INFO  - reachability note / probe could not run.

This scanner NEVER emits a graded severity. Both catalogues require an
on-host / in-guest foothold or hardware adjacency and are advisory-by-design.
The one externally-checkable escape primitive in §8 (exposed Docker remote
API) is handled by docker_api_exposure_probe, which CAN grade CRITICAL.
"""

_KERNEL_CATALOGUE = [
    "Dirty COW (CVE-2016-5195) copy-on-write race -> root. Confirm with "
    "'uname -r' on the host vs the patched kernel matrix.",
    "Dirty Pipe (CVE-2022-0847) splice() pipe-buffer overwrite. Needs the "
    "running kernel (5.8 - 5.16.11/5.15.25/5.10.102).",
    "PwnKit (CVE-2021-4034) polkit pkexec argv[0] underflow. On-host "
    "'pkexec --version' + polkit patch check.",
    "Sudo Baron Samedit (CVE-2021-3156) heap overflow. On-host 'sudoedit -s /'.",
    "nf_tables use-after-free (CVE-2024-1086) -> local root. Needs kernel "
    "version + nftables availability on the host.",
    "Windows kernel privesc (HEVD-style), macOS kernel CVE chains, KASLR "
    "bypass - manual analyst work against the specific build.",
]
_HYPERVISOR_CATALOGUE = [
    "Leaky Vessels - runc CVE-2024-21626 working-directory file-descriptor "
    "leak -> container escape. Confirm runc version inside the build "
    "pipeline; patched in runc 1.1.12.",
    "cgroup release_agent escape (requires CAP_SYS_ADMIN inside the "
    "container) - in-guest only.",
    "Privileged container ( --privileged ) -> host root via /dev or "
    "/proc/sysrq-trigger - in-guest only.",
    "KVM / Hyper-V CVE, VMware ESXi escape chains, gVisor / Kata escape - "
    "require an in-guest foothold and the specific hypervisor build.",
    "TEE / SGX / TrustZone bypass - hardware-adjacent research, not "
    "remotely observable.",
]


def _advisory(name, label, items, target):
    return {
        "name": name,
        "severity": "INFO",
        "cwe": "CWE-1395",
        "owasp": "N/A",
        "evidence": (
            f"Target {target}. {label} require an on-host / in-guest foothold "
            "or hardware adjacency and cannot be confirmed from an external SaaS "
            "scan. Surfaced as advisory so the report is complete, NOT as "
            "detected vulnerabilities:\n"
            + "\n".join(f"  - {it}" for it in items)
        ),
        "remediation": (
            "Run the listed on-host checks (kernel version vs CVE matrix, runc "
            "version, container capability review). For the one externally-"
            "checkable escape primitive (exposed Docker remote API) see the "
            "docker_api_exposure_probe scanner. Reference: "
            "module_playbooks/10_system_exploit.md sections 7, 8."
        ),
    }


def rule_kernel_catalogue(s):
    if not s.get("khe_ran"):
        return None
    return _advisory(
        "[ADVISORY-BY-DESIGN] Kernel local-privesc CVE catalogue (on-host kernel "
        "version required)",
        "The §7 kernel-exploit techniques",
        _KERNEL_CATALOGUE,
        s.get("khe_target", "?"),
    )


def rule_hypervisor_catalogue(s):
    if not s.get("khe_ran"):
        return None
    return _advisory(
        "[ADVISORY-BY-DESIGN] Hypervisor / container-escape catalogue (in-guest "
        "foothold required)",
        "The §8 hypervisor / container-escape techniques",
        _HYPERVISOR_CATALOGUE,
        s.get("khe_target", "?"),
    )


def rule_reachability(s):
    if not s.get("khe_ran"):
        err = "no target supplied" if s.get("khe_no_target") else "probe did not run"
        return {
            "name": "Kernel/hypervisor advisory probe could not run",
            "severity": "INFO",
            "cwe": "CWE-1006",
            "evidence": f"{s.get('khe_target', '?')}: {err}.",
            "remediation": "Supply a reachable target and re-run.",
        }
    return {
        "name": "Kernel/hypervisor-escape advisory anchored to a live reachability check",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (
            f"{s.get('khe_target', '?')} TCP reachable={s.get('khe_reachable')}. "
            "This scanner is advisory-by-design: the §7/§8 techniques need an "
            "on-host / in-guest foothold to confirm. The reachability check only "
            "proves the host was live when the advisory was produced."
            + (f" Connect error: {s.get('khe_error')}." if s.get("khe_error") else "")
        ),
        "remediation": (
            "No remote action fixes these classes directly: patch kernels, "
            "upgrade runc, drop container privileges/capabilities, and keep "
            "hypervisor builds current. Verify on-host per the advisory items."
        ),
    }


KERNEL_HYPERVISOR_ESCAPE_ADVISORY_FINDING_RULES = [
    rule_kernel_catalogue,
    rule_hypervisor_catalogue,
    rule_reachability,
]
