"""privesc module - Privilege Escalation enumeration probes.

Per module_playbooks/12_privesc.md - 7 sections, 88 techniques.
Starter set (5 scanners) covers the highest-impact playbook items:
  - tier1_linux: linpeas_remote_audit (§1 #1), suid_binary_audit (§4 #52),
                 sudo_misconfig_audit (§4 #48-50), kernel_exploit_check (§6 #69-77)
  - tier2_windows: winpeas_check (§2 #19)

Each probe ships REAL paramiko/pywinrm calls. Customer supplies SSH/WinRM
creds at scan time via ScanRequest.options.* — without creds the probe
returns INFO "credentials required" rather than fabricating data.

External data:
  - PEASS-ng (LinPEAS+WinPEAS) at /opt/peass-ng (cloned in backend image)
  - GTFOBins MD database at /opt/gtfobins/_gtfobins/
  - LOLBAS at /opt/lolbas

More scanners will be added per playbook section in subsequent commits.
"""
