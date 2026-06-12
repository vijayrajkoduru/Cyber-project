"""os_fingerprint_privesc_advisory - findings rules.

Severity model (ALL INFO by design):
  INFO  - HTTP OS fingerprint (Server / X-Powered-By / ASP.NET version).
  INFO  - [ADVISORY-BY-DESIGN] the §2/§3/§5/§6 on-host privesc catalogue
          (Windows PrivEsc, macOS PrivEsc, format-string / memory
          corruption, DLL hijacking) keyed to the inferred OS family.
  INFO  - probe could not run.

This scanner NEVER emits a graded severity. An OS hint from a banner is not
a vulnerability, and every technique here requires an on-host foothold or
local binary analysis to verify.
"""

# OS-keyed advisory catalogue. Each entry is surfaced as advisory-by-design
# INFO - the technique requires on-host / local execution and cannot be
# SaaS-probed. None of these planned severities ever flow through as a finding
# severity.
_WINDOWS_CATALOGUE = [
    "WinPEAS / PowerUp / PrivescCheck automated enumeration (run on the host).",
    "Unquoted service path + writable service binary (PowerUp "
    "Get-ServiceUnquoted / Get-ModifiableServiceFile).",
    "AlwaysInstallElevated registry policy (HKLM+HKCU "
    "Software\\Policies\\Microsoft\\Windows\\Installer).",
    "Stored credentials (cmdkey /list) + DPAPI / Credential Manager review.",
    "Scheduled-task + COM hijack abuse (schtasks, modifiable task XML).",
    "SeImpersonatePrivilege -> Potato family (PrintSpoofer / GodPotato) - "
    "requires the token privilege, confirmed on-host.",
    "UAC bypass (UACME) - local-only.",
]
_MAC_CATALOGUE = [
    "macPEAS enumeration (run on the host).",
    "TCC (Transparency, Consent & Control) bypass review.",
    "SUID/SGID binary abuse + GTFOBins lookup ('find / -perm -4000').",
    "Launch Agent / Daemon + Login Item persistence + plist permission abuse.",
    "XPC service abuse and sudoers misconfiguration ('sudo -l').",
    "SIP / Apple-Silicon specific research items (manual analyst).",
]
_MEMCORRUPT_CATALOGUE = [
    "Format-string read/write primitive (%s/%x/%n) - requires the target "
    "binary + a debugger (pwntools), local analysis only.",
    "GOT overwrite / stack-canary leak via format string.",
    "Integer overflow, heap UAF / double-free, race-condition and TOCTOU "
    "exploitation - all require the binary and a controlled local environment.",
]
_DLL_CATALOGUE = [
    "DLL search-order + phantom DLL hijack (on-host filesystem analysis).",
    "Side-loading a malicious DLL next to a legitimate signed binary.",
    "AppCert / AppInit DLL injection (registry, local).",
    "LOLBAS Microsoft-signed binary side-loading (local execution).",
]


def _catalogue_for(os_family: str):
    sections = []
    if os_family == "Windows":
        sections.append(("§2 Windows PrivEsc", _WINDOWS_CATALOGUE))
        sections.append(("§6 DLL Hijacking / Side-loading", _DLL_CATALOGUE))
    elif os_family == "macOS":
        sections.append(("§3 macOS PrivEsc", _MAC_CATALOGUE))
    else:
        # Linux / unknown: still list the cross-platform memory-corruption set.
        sections.append(("§2 Windows PrivEsc (if any Windows host present)",
                         _WINDOWS_CATALOGUE))
        sections.append(("§3 macOS PrivEsc (if any macOS host present)",
                         _MAC_CATALOGUE))
    sections.append(("§5 Format String / Memory Corruption", _MEMCORRUPT_CATALOGUE))
    return sections


def rule_fingerprint(s):
    if not s.get("osfp_ran"):
        return None
    if not (s.get("osfp_server") or s.get("osfp_powered_by")
            or s.get("osfp_aspnet_version")):
        return None
    return {
        "name": "HTTP OS fingerprint (privesc playbook selector)",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (
            f"{s.get('osfp_target_url', '?')} (status {s.get('osfp_status')}) "
            f"Server='{s.get('osfp_server') or '-'}', "
            f"X-Powered-By='{s.get('osfp_powered_by') or '-'}', "
            f"ASP.NET='{s.get('osfp_aspnet_version') or '-'}'. Inferred OS "
            f"family: {s.get('osfp_os_family')}. This selects which on-host "
            "privesc playbook applies; it is not itself a vulnerability."
        ),
        "remediation": (
            "Suppress version-leaking response headers (Server, X-Powered-By, "
            "X-AspNet-Version) to reduce reconnaissance value. This does not fix "
            "any privesc issue - it only narrows what an attacker learns for "
            "free."
        ),
    }


def rule_advisory_catalogue(s):
    if not s.get("osfp_ran"):
        return None
    os_family = s.get("osfp_os_family") or "unknown"
    blocks = []
    for label, items in _catalogue_for(os_family):
        blocks.append(label + ":\n" + "\n".join(f"  - {it}" for it in items))
    return {
        "name": ("[ADVISORY-BY-DESIGN] Windows / macOS privesc + memory-corruption "
                 "+ DLL-hijack catalogue (on-host / local execution required)"),
        "severity": "INFO",
        "cwe": "CWE-1395",
        "owasp": "N/A",
        "evidence": (
            f"Inferred OS family: {os_family}. The §2/§3/§5/§6 techniques below "
            "require a foothold on the host or local binary analysis and cannot "
            "be confirmed from an external SaaS scan. Surfaced as advisory so the "
            "report is complete, NOT as detected vulnerabilities:\n\n"
            + "\n\n".join(blocks)
        ),
        "remediation": (
            "Execute the relevant on-host checks (WinPEAS / PowerUp / macPEAS, "
            "service-path + AlwaysInstallElevated audit, DLL search-order review, "
            "binary fuzzing for memory-corruption). Reference: "
            "module_playbooks/10_system_exploit.md sections 2, 3, 5, 6; "
            "https://github.com/itm4n/PrivescCheck ; https://lolbas-project.github.io/"
        ),
    }


def rule_probe_error(s):
    if s.get("osfp_server") or s.get("osfp_powered_by") or s.get("osfp_aspnet_version"):
        return None
    if s.get("osfp_ran") and s.get("osfp_status"):
        # Reached the target but it leaked no OS-identifying headers.
        return {
            "name": "HTTP response leaked no OS-identifying headers",
            "severity": "INFO",
            "cwe": "CWE-200",
            "evidence": (
                f"{s.get('osfp_target_url', '?')} responded {s.get('osfp_status')} "
                "with no Server / X-Powered-By / ASP.NET headers. OS family could "
                "not be inferred from HTTP. This is good hygiene (less recon "
                "value), not a finding."
            ),
            "remediation": (
                "Keep version headers suppressed. For privesc assessment, OS "
                "identification must come from an on-host check or an "
                "authenticated scan."
            ),
        }
    err = s.get("osfp_error") or ("no target supplied"
                                   if s.get("osfp_no_target") else "no HTTP response")
    return {
        "name": "OS fingerprint probe could not run",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": f"{s.get('osfp_target_url', '?')}: {err}.",
        "remediation": (
            "Confirm the target serves HTTP(S) and is reachable from the scanner, "
            "then re-run."
        ),
    }


OS_FINGERPRINT_PRIVESC_ADVISORY_FINDING_RULES = [
    rule_fingerprint,
    rule_advisory_catalogue,
    rule_probe_error,
]
