"""atomic_red_team_runner - findings rules.

Severity model:
  INFO     - per-test execution rollup + missing-input transparency
  LOW      - many techniques exercised; customer must verify SIEM caught
  POSITIVE - host successfully ran the Atomic suite (auth + reach OK)
"""


def rule_atomic_rollup(s):
    if not s.get("atomic_runner_results"):
        return None
    executed = int(s.get("atomic_runner_total") or 0)
    planned = int(s.get("atomic_runner_planned") or 0)
    techs = s.get("atomic_runner_techniques") or []
    os_kind = s.get("atomic_runner_os") or "linux"
    target = s.get("atomic_runner_target") or "?"
    port = s.get("atomic_runner_port") or "?"
    sample_ids = ", ".join(techs[:10])

    return {
        "name": (f"Atomic Red Team probe set executed: {executed}/{planned} tests, "
                  f"{len(techs)} MITRE techniques touched on {os_kind}://{target}:{port}"),
        "severity": "LOW",
        "cwe": "CWE-693",
        "owasp": "A09:2021",
        "evidence": (
            f"VulnusLab executed {executed} of {planned} Atomic Red Team simulations "
            f"({os_kind} via {'SSH' if os_kind == 'linux' else 'WinRM'}) on {target}:{port}. "
            f"Techniques exercised: {sample_ids}. "
            "Each test emits a known telemetry signature; success here means the "
            "host ran the command, NOT that data was exfiltrated."
        ),
        "remediation": (
            "1. Pull EDR/SIEM events for the test window. Verify alerts fired for: "
            "T1003.001 (LSASS process access), T1059.001 (PowerShell EncodedCommand), "
            "T1547.001 (Registry Run key writes), T1053.005 (Scheduled task creation), "
            "T1027.005 (base64-encoded payload strings). "
            "2. For each technique with NO alert: build a Sigma rule (atomicredteam.io "
            "has Sigma snippets per test). "
            "3. Re-run this probe; coverage should climb test-by-test. "
            "4. Map detected vs undetected techniques to ATT&CK Navigator via the "
            "mitre_attack_simulation_summary scanner."
        ),
        "mitre_techniques": techs,
        "references": [
            "https://atomicredteam.io/",
            "https://attack.mitre.org/",
            "https://github.com/redcanaryco/atomic-red-team",
        ],
    }


def rule_input_missing(s):
    if not s.get("atomic_input_missing"):
        return None
    return {
        "name": "Atomic Red Team runner skipped - SSH/WinRM credentials not supplied",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": ("This probe needs options.atomic_user + "
                     "options.atomic_password (or options.atomic_ssh_key for "
                     "Linux). Set options.atomic_os='windows' for WinRM."),
        "remediation": (
            "Re-run with: target=<host IP>, options.atomic_user=<svc account>, "
            "options.atomic_password=<password>, options.atomic_os='linux' or "
            "'windows', options.atomic_port=22 (SSH) or 5985 (WinRM). "
            "Pick a NON-PROD lab host on the customer LAN."
        ),
    }


def rule_connect_error(s):
    err = s.get("atomic_connect_error")
    if not err:
        return None
    return {
        "name": f"Atomic runner could not connect: {err[:80]}",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": f"Connection error: {err}",
        "remediation": (
            "Verify host reachable, port open, credentials valid. SSH expects "
            "22, WinRM 5985 (HTTP) or 5986 (HTTPS). For WinRM, run "
            "Enable-PSRemoting -Force on the target Windows box first."
        ),
    }


def rule_positive(s):
    if s.get("atomic_input_missing"):
        return None
    if s.get("atomic_connect_error"):
        return None
    if int(s.get("atomic_runner_total") or 0) == 0:
        return None
    if int(s.get("atomic_runner_total") or 0) < int(s.get("atomic_runner_planned") or 1):
        return None
    return {
        "name": "Atomic Red Team suite ran cleanly - host is reachable and authenticates",
        "severity": "POSITIVE",
        "evidence": (
            f"All {s.get('atomic_runner_planned')} simulations executed against "
            f"{s.get('atomic_runner_target')}. This proves the test harness works "
            "and the host's auth surface is intact (not necessarily detection)."
        ),
        "remediation": (
            "Next step: roll detection-validation into a recurring purple-team "
            "cadence (monthly). Track techniques-without-alerts as Jira backlog."
        ),
        "cwe": "CWE-693",
        "owasp": "A09:2021",
    }


ATOMIC_RED_TEAM_RUNNER_FINDING_RULES = [
    rule_atomic_rollup,
    rule_input_missing,
    rule_connect_error,
    rule_positive,
]
