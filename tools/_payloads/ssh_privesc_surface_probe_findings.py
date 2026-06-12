"""ssh_privesc_surface_probe - findings rules.

Severity model:
  LOW   - an OpenSSH version was ACTUALLY parsed from the banner AND it is
          below the EOL floor (7.4). Stamped verified_exploit=True (the
          banner is a direct observation, not advisory). This flags an
          unmaintained SSH stack; it does NOT assert a specific privesc CVE.
  INFO  - OS/SSH fingerprint (always, when a banner was read).
  INFO  - [ADVISORY-BY-DESIGN] the §1/§4/§7 local-privesc + kernel CVE
          catalogue, which requires an on-host foothold to verify and
          therefore cannot be SaaS-probed.
  INFO  - probe failed / no banner.

ZERO graded severity is ever derived from a planned-CVE severity. Local
privesc / kernel / sudo CVEs are advisory INFO only.
"""

# Local-privesc + kernel catalogue surfaced as honest advisory INFO. None of
# these can be confirmed from a remote SSH banner (kernel + sudo versions are
# not in the banner), so they are advisory-by-design, NOT forge gaps.
_ADVISORY_CATALOGUE = [
    ("Linux local privilege escalation enumeration (LinPEAS / LinEnum / "
     "linuxprivchecker)",
     "Requires an authenticated shell on the host. Run LinPEAS / linux-exploit-"
     "suggester on the box and review sudo -l, world-writable cron, writable "
     "PATH, /etc/passwd perms, NFS no_root_squash, and docker-group membership."),
    ("SUID/SGID binary + Linux capability abuse (GTFOBins)",
     "Requires on-host enumeration: 'find / -perm -4000 -type f 2>/dev/null' and "
     "'getcap -r / 2>/dev/null', then cross-reference GTFOBins. Not observable "
     "from the SSH banner."),
    ("Sudo misconfiguration / NOPASSWD policy review",
     "Requires authenticated 'sudo -l' on the host. Audit /etc/sudoers and "
     "/etc/sudoers.d for NOPASSWD, TTY/askpass and wildcard rules."),
    ("Sudo Baron Samedit (CVE-2021-3156) heap overflow",
     "Confirm with 'sudoedit -s /' on the host; patched in sudo 1.9.5p2. The "
     "sudo version is not exposed in the SSH banner, so this cannot be remotely "
     "confirmed."),
    ("PwnKit polkit pkexec local root (CVE-2021-4034)",
     "On-host check: 'pkexec --version' and confirm polkit is patched. Not "
     "remotely observable."),
    ("Dirty COW (CVE-2016-5195) / Dirty Pipe (CVE-2022-0847) kernel privesc",
     "Requires the running kernel version ('uname -r') from the host. Kernel "
     "version is not exposed remotely; verify on the box and patch the kernel."),
    ("nf_tables use-after-free local root (CVE-2024-1086)",
     "Requires the running kernel version + nftables config from the host. Patch "
     "to a fixed kernel build; not remotely confirmable."),
]


def rule_openssh_eol(s):
    # Graded LOW only when a real version is parsed AND it is past EOL.
    if not s.get("sshpe_ran"):
        return None
    if not s.get("sshpe_openssh_eol"):
        return None
    ver = s.get("sshpe_openssh_version") or ""
    if not ver:
        return None
    distro = s.get("sshpe_distro_tag") or "unknown distro"
    return {
        "name": (f"End-of-life OpenSSH {ver} detected (unmaintained SSH stack "
                 "broadens the local-privesc surface)"),
        "severity": "LOW",
        "cvss": "3.7",
        "cwe":  "CWE-1104",
        "cwe_name": "Use of Unmaintained Third Party Components",
        "owasp": "A06:2021",
        "verified_exploit": True,
        "evidence": (
            f"{s.get('sshpe_target', '?')} advertised banner OpenSSH {ver} "
            f"({distro}). OpenSSH {ver} is below the maintained floor (7.4), so "
            "the host is almost certainly running an end-of-life base OS image "
            "whose kernel, sudo and polkit are also unpatched - the substrate "
            "that the §1/§4/§7 local-privesc and kernel-exploit techniques "
            "target. This is a banner observation, not an assertion that any "
            "specific privesc CVE is exploitable (that needs an on-host check)."
        ),
        "remediation": (
            "Upgrade the base OS to a supported release so OpenSSH, the kernel, "
            "sudo and polkit all return to vendor support. After upgrade, re-run "
            "this scan; the banner should report a current OpenSSH build."
        ),
    }


def rule_fingerprint(s):
    if not s.get("sshpe_ran"):
        return None
    if not s.get("sshpe_banner"):
        return None
    ver = s.get("sshpe_openssh_version") or "unparsed"
    distro = s.get("sshpe_distro_tag") or "no distro tag"
    return {
        "name": "SSH service fingerprint (privesc surface baseline)",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (
            f"{s.get('sshpe_target', '?')} banner: "
            f"'{(s.get('sshpe_banner') or '')[:120]}'. Parsed OpenSSH={ver}, "
            f"OS distro tag={distro}. This is the externally visible substrate "
            "for the local privilege-escalation techniques in this module; the "
            "techniques themselves are confirmed on-host (see advisory items)."
        ),
        "remediation": (
            "Keep the SSH stack and base OS current. The local-privesc surface "
            "shrinks every time the kernel / sudo / polkit are patched."
        ),
    }


def rule_advisory_catalogue(s):
    # One consolidated advisory-by-design INFO covering the on-host privesc +
    # kernel techniques that cannot be SaaS-probed. Always INFO.
    if not s.get("sshpe_ran"):
        return None
    lines = [f"- {title}: {how}" for title, how in _ADVISORY_CATALOGUE]
    return {
        "name": ("[ADVISORY-BY-DESIGN] Linux local privilege-escalation + kernel "
                 "exploit catalogue (on-host verification required)"),
        "severity": "INFO",
        "cwe": "CWE-1395",
        "owasp": "N/A",
        "evidence": (
            "These §1/§4/§7 techniques require an authenticated foothold on the "
            "host (shell, kernel version, sudo policy, SUID inventory) and "
            "therefore cannot be confirmed from an external SaaS scan. Surfaced "
            "as advisory so the report is complete, NOT as a detected "
            "vulnerability:\n" + "\n".join(lines)
        ),
        "remediation": (
            "Run the on-host checks listed for each item (LinPEAS, sudo -l, find "
            "-perm -4000, getcap -r /, uname -r vs the kernel CVE matrix). "
            "Reference: module_playbooks/10_system_exploit.md sections 1, 4, 7; "
            "GTFOBins; https://github.com/peass-ng/PEASS-ng"
        ),
    }


def rule_probe_error(s):
    if s.get("sshpe_ran") and s.get("sshpe_banner"):
        return None
    err = s.get("sshpe_error") or ("no target supplied"
                                    if s.get("sshpe_no_target") else "no SSH banner")
    return {
        "name": "SSH privesc-surface probe could not read a banner",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (f"{s.get('sshpe_target', '?')}: {err}. Port may be filtered, "
                     "the target down, or not running SSH."),
        "remediation": (
            "Confirm SSH is listening on the expected port and reachable from "
            "the scanner. If SSH is internal-only, run the scan from a trusted "
            "host on that network."
        ),
    }


SSH_PRIVESC_SURFACE_PROBE_FINDING_RULES = [
    rule_openssh_eol,
    rule_fingerprint,
    rule_advisory_catalogue,
    rule_probe_error,
]
