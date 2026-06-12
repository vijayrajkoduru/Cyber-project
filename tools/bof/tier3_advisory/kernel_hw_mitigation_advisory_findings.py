"""kernel_hw_mitigation_advisory - findings rules.

ADVISORY-BY-DESIGN: a single INFO finding. §6 #60 KASLR + §8 #75-#80 are
kernel / hypervisor / secure-world / on-device research bypasses that need a
running privileged target, a post-compromise foothold, specific silicon, or
active exploitation - none available to a detection-only SaaS over an uploaded
userland file. The STATIC userland CFI opt-in (CET / PAC / BTI) is covered by
cfi_modern_mitigation_audit. Never graded.
"""


def rule_advisory(s):
    if not s.get("kern_advisory"):
        return None
    techniques = s.get("kern_techniques") or []
    return {
        "name": "[ADVISORY-BY-DESIGN] Kernel & hardware-mitigation bypass research",
        "severity": "INFO",
        "evidence": (
            f"{len(techniques)} §6/§8 techniques (KASLR bypass, CET shadow-stack "
            "bypass, ARM64EC / macOS / iOS pointer-auth bypass, hypervisor escape, "
            "TEE / SGX / TrustZone enclave bypass) target a running kernel, "
            "hypervisor, or secure-world and require a post-compromise foothold, "
            "specific silicon, or active research-grade exploitation. None can be "
            "performed by a detection-only SaaS against an uploaded userland binary."
        ),
        "remediation": (
            "Endpoint is advisory-by-design, NOT a forge gap. The STATIC userland "
            "control-flow-integrity opt-in (Intel CET IBT/SHSTK, ARM PAC/BTI) IS "
            "decoded by the cfi_modern_mitigation_audit scanner. For the kernel / HW "
            "layer, engage an authorized red-team / research program: kernel work needs "
            "an info-leak + on-host execution; PAC/MTE bypass needs the target Apple / "
            "ARM silicon; hypervisor escape needs a guest foothold + a specific CVE; "
            "enclave bypass needs the SGX/TrustZone runtime (often + side-channel). "
            "Defensively: keep kernels / hypervisors / microcode patched, enable "
            "KASLR + kCFI + CET, and apply vendor enclave SDK mitigations. See "
            "playbook §6 #60 and §8 #75-#80."
        ),
        "cwe": "CWE-1265",
        "owasp": "A05:2021",
    }


KERNEL_HW_MITIGATION_ADVISORY_FINDING_RULES = [rule_advisory]
