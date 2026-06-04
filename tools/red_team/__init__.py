"""red_team module - Adversary Emulation / Red Team detection-baseline probes.

Per module_playbooks/27_red_team.md - 8 sections, 88 techniques.
Starter set (5 scanners) covers detection-engineering validation: each
probe emits a LOUD, known-TTP signal (Atomic Red Team test, C2 beacon
pattern, DNS exfil, lateral pivot signal, MITRE ATT&CK Navigator layer)
so the customer can verify their SIEM/EDR caught it.

Scanners are DETECTION TESTS, not real attacks:
  - tier1_simulation (3): atomic_red_team_runner, c2_beacon_test,
                          exfil_dns_simulation
  - tier2_detection  (2): lateral_pivot_signal_check,
                          mitre_attack_simulation_summary

Customer input pattern: every probe takes customer-supplied targets
(c2_callback_url, exfil_dns_domain, lateral_target) via ScanRequest.options
so the test signals are sent only to customer-controlled receivers — we
never hit production. All findings are INFO/LOW (these are test pings)
with remediation = "verify your SIEM caught this".

MITRE ATT&CK techniques exercised (rollup summary in #5):
  T1003 Credential Dumping (simulated, no actual dump)
  T1027.005 Indicator Removal from Tools (obfuscation)
  T1053.005 Scheduled Task / Job
  T1059.001 Command and Scripting: PowerShell
  T1071.001 Application Layer Protocol: Web Protocols (C2 HTTPS)
  T1071.004 Application Layer Protocol: DNS (C2 DNS)
  T1078 Valid Accounts (PtH attempt)
  T1547.001 Boot or Logon Autostart: Registry Run Keys
  T1550.002 Use Alternate Authentication Material: Pass the Hash
  T1570 Lateral Tool Transfer (psexec)
  T1572 Protocol Tunneling
  TA0010 Exfiltration (DNS subdomain encoding)
"""
