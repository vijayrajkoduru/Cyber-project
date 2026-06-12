"""tier4_advisory - honest advisory-by-design coverage of the red_team
playbook techniques (module_playbooks/27_red_team.md) that genuinely CANNOT
be detected from an external, unauthenticated SaaS VA scan.

Adversary emulation is, by definition, an on-host / post-foothold / active
operation: running Atomic Red Team or CALDERA abilities executes code on the
customer's endpoints; standing up Cobalt Strike / Sliver / Mythic and running
an operation is active C2; threat-actor TTP emulation chains real techniques;
purple-teaming and detection-as-code require the customer's SIEM/EDR. None of
that is safely or honestly reproducible from a black-box remote scan.

The externally-observable slivers ARE implemented as REAL graded probes
elsewhere in this module:
  - tier1_simulation  : atomic_red_team_runner (customer-supplied host creds),
                        c2_beacon_test, exfil_dns_simulation
  - tier2_detection   : lateral_pivot_signal_check (customer LAN host),
                        mitre_attack_simulation_summary
  - tier3_c2_infra    : c2_framework_exposure, detection_tooling_exposure
                        (REAL exposure detection of C2 / SIEM consoles)

Everything that remains is emitted here as INFO [ADVISORY-BY-DESIGN] findings
with vulnerable:false. The planned playbook severity is recorded in the
remediation text ONLY — it is NEVER used as a finding severity, guaranteeing
zero false positives.
"""
