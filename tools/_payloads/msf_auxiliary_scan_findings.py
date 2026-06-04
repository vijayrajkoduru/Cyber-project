"""msf_auxiliary_scan - findings rules.

Severity model:
  MEDIUM    findings reported by the auxiliary scanner (each [+] line is
            a positive detection that the customer should review)
  INFO      msfconsole missing / module path rejected / no target /
            informational [*] output / scan failure
  POSITIVE  scanner ran cleanly and produced 0 [+] findings (target
            withstood the auxiliary scan)
"""


def rule_binary_missing(s):
    if not s.get("msf_auxiliary_scan_binary_missing"):
        return None
    return {
        "name": "Metasploit Framework not installed on scanner host",
        "severity": "INFO",
        "evidence": ("shutil.which('msfconsole') returned None. The "
                     "auxiliary scanner probe could not run because "
                     "msfconsole is absent."),
        "remediation": (
            "Install Metasploit Framework: "
            "apt install metasploit-framework + msfdb init. "
            "Re-run after the install completes."
        ),
        "cwe": "CWE-1006",
    }


def rule_no_target(s):
    if not s.get("msf_auxiliary_scan_no_target"):
        return None
    return {
        "name": "Metasploit auxiliary scan skipped - no target supplied",
        "severity": "INFO",
        "evidence": ("ScanRequest.target was empty. Auxiliary modules need "
                     "a RHOSTS value to run."),
        "remediation": ("Provide a target host or CIDR in ScanRequest.target "
                        "(or options.RHOSTS) and re-run."),
        "cwe": "CWE-1006",
    }


def rule_invalid_module(s):
    bad = s.get("msf_auxiliary_scan_invalid_module")
    if not bad:
        return None
    return {
        "name": f"Metasploit module path rejected by safety filter: {bad[:80]}",
        "severity": "INFO",
        "evidence": (
            f"The supplied options.module value '{str(bad)[:120]}' did not "
            "match the auxiliary/* whitelist. VulnusLab's MSF-lite wrapper "
            "refuses exploit/, post/, payload/, and encoder/ trees - those "
            "must be driven from a dedicated red-team engagement playbook."
        ),
        "remediation": (
            "Supply a module path beginning with 'auxiliary/' (e.g. "
            "auxiliary/scanner/smb/smb_version, "
            "auxiliary/scanner/http/http_version, "
            "auxiliary/scanner/ssl/openssl_heartbleed) and re-run."
        ),
        "cwe": "CWE-20",
    }


def rule_findings_reported(s):
    succ = s.get("msf_auxiliary_scan_successes") or []
    if not succ:
        return None
    module = s.get("msf_auxiliary_scan_module") or "auxiliary scanner"
    target = s.get("msf_auxiliary_scan_target") or "target"
    sample = "; ".join(succ[:3])
    return {
        "name": (f"Metasploit {module} reported {len(succ)} finding(s) "
                 f"against {target}"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "evidence": (
            f"msfconsole returned {len(succ)} [+] line(s). Examples: "
            f"{sample}. Review each result against the module's "
            "documentation; some [+] lines (e.g. SMB banner versions) are "
            "informational while others (e.g. ms17_010 vulnerable) require "
            "immediate patching."
        ),
        "remediation": (
            "1. For each [+] result, look up the module's CVE / CWE map at "
            "https://docs.metasploit.com/. 2. Patch or harden the affected "
            "service. 3. Re-run with the same module to confirm the [+] line "
            "disappears."
        ),
    }


def rule_scan_error(s):
    err = s.get("msf_auxiliary_scan_error")
    if not err:
        return None
    return {
        "name": "Metasploit auxiliary scan failed",
        "severity": "INFO",
        "evidence": f"Probe error: {str(err)[:300]}",
        "remediation": (
            "1. Re-run the same module manually: `msfconsole -q -x \"use "
            "<module>; set RHOSTS <target>; run; exit\"`. 2. If the failure "
            "reproduces, check msfconsole's `setg LogLevel 3` output for "
            "stack traces. 3. Ensure RHOSTS is reachable from the scanner host."
        ),
        "cwe": "CWE-754",
    }


def rule_positive_clean(s):
    if s.get("msf_auxiliary_scan_binary_missing"):
        return None
    if s.get("msf_auxiliary_scan_no_target"):
        return None
    if s.get("msf_auxiliary_scan_invalid_module"):
        return None
    if s.get("msf_auxiliary_scan_error"):
        return None
    if (s.get("msf_auxiliary_scan_successes") or []):
        return None
    module = s.get("msf_auxiliary_scan_module") or "auxiliary scanner"
    target = s.get("msf_auxiliary_scan_target") or "target"
    info_count = len(s.get("msf_auxiliary_scan_informational") or [])
    return {
        "name": (f"Metasploit {module} - 0 findings against {target}"),
        "severity": "POSITIVE",
        "evidence": (
            f"msfconsole ran the module without producing any [+] result "
            f"lines ({info_count} informational [*] line(s) emitted)."
        ),
        "remediation": (
            "Keep the affected service patched and re-run this module "
            "after each major patch cycle - new CVEs land in MSF's "
            "auxiliary tree on a regular cadence."
        ),
        "cwe": "CWE-1357",
    }


MSF_AUXILIARY_SCAN_FINDING_RULES = [
    rule_binary_missing,
    rule_no_target,
    rule_invalid_module,
    rule_findings_reported,
    rule_scan_error,
    rule_positive_clean,
]
