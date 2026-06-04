"""tier2_detection - lateral-movement + MITRE rollup detection probes.

Probes that generate lateral-pivot signals (impacket-psexec / WMI with
bogus hash, expected to fail auth but generate Windows 4624/4625/4648
events) and a MITRE ATT&CK Navigator layer summarising every technique
exercised across the red_team module.
"""
