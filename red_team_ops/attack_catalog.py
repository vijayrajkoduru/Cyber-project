"""MITRE ATT&CK technique EMULATION library.

Each entry describes a technique, a NON-DESTRUCTIVE emulation/test, and blue-team
detection guidance. These are emulation definitions for detection-testing and
attack-path planning — NOT weaponized exploit code. Destructive techniques are
included for completeness but carry `risk` tags so safety.py blocks execution.

Schema:
  id           ATT&CK technique id (T####[.###])
  name         technique name
  tactic       ATT&CK tactic (kill-chain phase)
  desc         what an adversary does
  emulation    safe emulation/test step (what the engine records / an analyst runs)
  detection    how a blue team detects it
  risk         list of safety tags (see safety.FORBIDDEN); empty = safe to emulate
  atomic_safe  True if a vetted benign atomic test exists (allows IMPACT_ATOMIC)
  platforms    applicable platforms
"""
from __future__ import annotations

from . import _curated   # noqa: E402  (AI-curated offline knowledge base)

TACTICS = [
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion",
    "credential_access", "discovery", "lateral_movement", "collection",
    "command_and_control", "exfiltration", "impact",
]

# Built-in fallback set — used only if the curated data files are missing, so the
# engine always works. The shipped catalog comes from _curated/*.json (141+
# techniques, 16 adversary-emulation playbooks).
_FALLBACK_TECHNIQUES = [
    # ── Reconnaissance ──
    {"id": "T1595", "name": "Active Scanning", "tactic": "reconnaissance",
     "desc": "Scan in-scope hosts for open ports/services.",
     "emulation": "Enumerate authorized targets (ports/services/banners) — read-only.",
     "detection": "IDS port-scan signatures; spikes in connection attempts.",
     "risk": [], "atomic_safe": True, "platforms": ["network"]},
    {"id": "T1589", "name": "Gather Victim Identity Information", "tactic": "reconnaissance",
     "desc": "Collect emails/usernames for the in-scope org.",
     "emulation": "OSINT username/email enumeration on authorized domains.",
     "detection": "Hard to detect (external); monitor for credential-stuffing follow-on.",
     "risk": [], "atomic_safe": True, "platforms": ["osint"]},

    # ── Initial Access ──
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial_access",
     "desc": "Exploit a vuln in an internet-facing app to gain a foothold.",
     "emulation": "Verify (non-destructively) that an in-scope app is vulnerable; do NOT drop a shell.",
     "detection": "WAF alerts, app error spikes, unexpected child processes.",
     "risk": [], "atomic_safe": False, "platforms": ["web"]},
    {"id": "T1566", "name": "Phishing", "tactic": "initial_access",
     "desc": "Send a phishing lure to authorized test users.",
     "emulation": "Send an authorized simulated-phishing email to consented test recipients only.",
     "detection": "Mail gateway, user-report rate, link-click telemetry.",
     "risk": [], "atomic_safe": True, "platforms": ["email"]},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "initial_access",
     "desc": "Use legitimate credentials to access in-scope systems.",
     "emulation": "Authenticate with provided test credentials to confirm access paths.",
     "detection": "Impossible-travel, new-device, off-hours logins.",
     "risk": [], "atomic_safe": True, "platforms": ["identity"]},

    # ── Execution ──
    {"id": "T1059.001", "name": "PowerShell", "tactic": "execution",
     "desc": "Run commands via PowerShell on a foothold host.",
     "emulation": "Atomic benign PowerShell test (e.g. whoami) on an authorized host.",
     "detection": "Script-block logging, AMSI, suspicious parent-child chains.",
     "risk": [], "atomic_safe": True, "platforms": ["windows"]},
    {"id": "T1059.004", "name": "Unix Shell", "tactic": "execution",
     "desc": "Run shell commands on a Unix foothold.",
     "emulation": "Benign id/uname command on an authorized host.",
     "detection": "auditd/EDR process telemetry, anomalous shells.",
     "risk": [], "atomic_safe": True, "platforms": ["linux"]},

    # ── Persistence ──
    {"id": "T1053.005", "name": "Scheduled Task", "tactic": "persistence",
     "desc": "Create a scheduled task for persistence.",
     "emulation": "Create a clearly-tagged benign task, then REMOVE it within the window.",
     "detection": "Task-creation events (4698), schtasks telemetry.",
     "risk": [], "atomic_safe": True, "platforms": ["windows"]},
    {"id": "T1098", "name": "Account Manipulation", "tactic": "persistence",
     "desc": "Add/modify accounts to keep access.",
     "emulation": "Emulate-only: log the technique; do not create real persistent accounts.",
     "detection": "Directory change auditing, new privileged group members.",
     "risk": ["destructive_persistence"], "atomic_safe": False, "platforms": ["identity"]},

    # ── Privilege Escalation ──
    {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation",
     "desc": "Exploit a local vuln to gain higher privileges.",
     "emulation": "Identify a privesc vector (version/config) on an authorized host; do not weaponize.",
     "detection": "EDR exploit-guard, unexpected SYSTEM/root processes.",
     "risk": [], "atomic_safe": False, "platforms": ["windows", "linux"]},
    {"id": "T1548.003", "name": "Sudo and Sudo Caching", "tactic": "privilege_escalation",
     "desc": "Abuse sudo misconfig to elevate.",
     "emulation": "Read-only check of sudoers / sudo -l on an authorized host.",
     "detection": "sudo logs, auth.log anomalies.",
     "risk": [], "atomic_safe": True, "platforms": ["linux"]},

    # ── Defense Evasion ──
    {"id": "T1562.001", "name": "Impair Defenses: Disable Tools", "tactic": "defense_evasion",
     "desc": "Disable AV/EDR/logging.",
     "emulation": "Emulate-only: log the intent; do NOT actually disable security controls.",
     "detection": "Service-stop events, EDR self-protection alerts.",
     "risk": [], "atomic_safe": False, "platforms": ["windows", "linux"]},
    {"id": "T1070.004", "name": "Indicator Removal: File Deletion", "tactic": "defense_evasion",
     "desc": "Delete artifacts/logs to cover tracks.",
     "emulation": "BLOCKED — destructive. Recorded as a gap to detect, not executed.",
     "detection": "Log-clear events (1102), gaps in log continuity.",
     "risk": ["data_destruction"], "atomic_safe": False, "platforms": ["windows", "linux"]},

    # ── Credential Access ──
    {"id": "T1110", "name": "Brute Force", "tactic": "credential_access",
     "desc": "Guess credentials via spray/brute.",
     "emulation": "Rate-limited password spray against authorized auth endpoints with test wordlist.",
     "detection": "Lockout spikes, failed-auth bursts, 4625 floods.",
     "risk": [], "atomic_safe": True, "platforms": ["identity"]},
    {"id": "T1558.003", "name": "Kerberoasting", "tactic": "credential_access",
     "desc": "Request service tickets and crack offline.",
     "emulation": "Request SPNs for authorized AD; mark crackable; do not reuse real creds.",
     "detection": "4769 RC4 ticket requests, abnormal SPN queries.",
     "risk": [], "atomic_safe": False, "platforms": ["windows"]},
    {"id": "T1003.001", "name": "OS Credential Dumping: LSASS", "tactic": "credential_access",
     "desc": "Dump LSASS to extract credentials.",
     "emulation": "Emulate-only: log the technique; do not capture real production creds.",
     "detection": "LSASS access by non-system processes (EDR).",
     "risk": ["credential_harvest_live"], "atomic_safe": False, "platforms": ["windows"]},

    # ── Discovery ──
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "discovery",
     "desc": "Enumerate services on reachable hosts.",
     "emulation": "Read-only service scan of in-scope hosts.",
     "detection": "Internal scan signatures, east-west connection spikes.",
     "risk": [], "atomic_safe": True, "platforms": ["network"]},
    {"id": "T1087", "name": "Account Discovery", "tactic": "discovery",
     "desc": "Enumerate accounts/groups.",
     "emulation": "Read-only directory enumeration on authorized AD/cloud IAM.",
     "detection": "LDAP query spikes, recon tool signatures.",
     "risk": [], "atomic_safe": True, "platforms": ["identity"]},

    # ── Lateral Movement ──
    {"id": "T1021.001", "name": "Remote Services: RDP", "tactic": "lateral_movement",
     "desc": "Move laterally via RDP.",
     "emulation": "Confirm RDP reachability/auth on in-scope hosts only.",
     "detection": "4624 type-10 logons, unusual RDP source/dest pairs.",
     "risk": [], "atomic_safe": True, "platforms": ["windows"]},
    {"id": "T1550.002", "name": "Pass the Hash", "tactic": "lateral_movement",
     "desc": "Authenticate with a stolen NTLM hash.",
     "emulation": "Emulate-only within scope: log the path; do not reuse real captured hashes.",
     "detection": "NTLM logons without preceding interactive auth.",
     "risk": ["credential_harvest_live"], "atomic_safe": False, "platforms": ["windows"]},

    # ── Collection ──
    {"id": "T1005", "name": "Data from Local System", "tactic": "collection",
     "desc": "Stage sensitive data from a foothold.",
     "emulation": "Identify (do not copy) sensitive-data locations on authorized hosts.",
     "detection": "Mass file reads, staging-dir creation.",
     "risk": [], "atomic_safe": False, "platforms": ["windows", "linux"]},

    # ── Command and Control ──
    {"id": "T1071.001", "name": "Application Layer Protocol: Web", "tactic": "command_and_control",
     "desc": "Beacon over HTTP(S).",
     "emulation": "Emulate a benign beacon pattern to an authorized listener for detection testing.",
     "detection": "Beacon jitter analysis, rare-domain TLS, JA3 anomalies.",
     "risk": [], "atomic_safe": True, "platforms": ["network"]},

    # ── Exfiltration (real exfil forbidden) ──
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "exfiltration",
     "desc": "Exfiltrate data over the C2 channel.",
     "emulation": "BLOCKED — emulate with benign canary data only; never real customer data.",
     "detection": "Large outbound transfers, DLP triggers.",
     "risk": ["real_exfiltration"], "atomic_safe": False, "platforms": ["network"]},

    # ── Impact (always forbidden) ──
    {"id": "T1486", "name": "Data Encrypted for Impact (Ransomware)", "tactic": "impact",
     "desc": "Encrypt data to deny access.",
     "emulation": "BLOCKED — destructive. Listed only as a detection/resilience objective.",
     "detection": "Mass file rename/entropy spikes, shadow-copy deletion.",
     "risk": ["data_destruction"], "atomic_safe": False, "platforms": ["windows", "linux"]},
    {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "impact",
     "desc": "Exhaust resources to disrupt service.",
     "emulation": "BLOCKED — DoS. Listed only as a resilience objective.",
     "detection": "Resource-exhaustion alerts, availability monitors.",
     "risk": ["denial_of_service"], "atomic_safe": False, "platforms": ["any"]},
]

# Built-in fallback scenarios (ordered chains of technique ids).
_FALLBACK_SCENARIOS = {
    "external_foothold": ["T1595", "T1589", "T1190", "T1078"],
    "phishing_to_persistence": ["T1566", "T1059.001", "T1053.005", "T1098"],
    "ad_compromise": ["T1087", "T1558.003", "T1003.001", "T1550.002", "T1021.001"],
    "full_kill_chain": [
        "T1595", "T1190", "T1059.004", "T1053.005", "T1068",
        "T1562.001", "T1110", "T1046", "T1021.001", "T1005",
        "T1071.001", "T1041", "T1486",
    ],
}


# ── Load the AI-curated knowledge base (fall back to built-ins if absent) ─────
_curated_techniques = _curated.load_techniques()
TECHNIQUES = _curated_techniques if _curated_techniques else _FALLBACK_TECHNIQUES

_curated_scenarios = _curated.load_scenarios()
if _curated_scenarios:
    # Curated form: name -> {label, adversary, description, techniques[]}
    SCENARIOS = {k: v.get("techniques", []) for k, v in _curated_scenarios.items()}
    SCENARIO_META = {
        k: {"label": v.get("label", k), "adversary": v.get("adversary", ""),
            "description": v.get("description", "")}
        for k, v in _curated_scenarios.items()
    }
else:
    SCENARIOS = _FALLBACK_SCENARIOS
    SCENARIO_META = {k: {"label": k, "adversary": "", "description": ""} for k in SCENARIOS}

_BY_ID = {t["id"]: t for t in TECHNIQUES}


def get(tid: str) -> dict | None:
    return _BY_ID.get(tid)


def by_tactic(tactic: str) -> list[dict]:
    return [t for t in TECHNIQUES if t["tactic"] == tactic]


def scenario(name: str) -> list[dict]:
    return [_BY_ID[i] for i in SCENARIOS.get(name, []) if i in _BY_ID]


def scenario_meta(name: str) -> dict:
    return SCENARIO_META.get(name, {"label": name, "adversary": "", "description": ""})


def all_scenarios() -> list[str]:
    return sorted(SCENARIOS)
