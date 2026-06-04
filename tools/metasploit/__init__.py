"""metasploit module - Metasploit Framework lite wrapper (playbook 11_metasploit.md).

8 sections, 78 techniques. This package autoloads tier* subdirectories,
each containing real probes that wrap the host-installed `msfconsole`,
`msfvenom`, and `msfdb` binaries. Metasploit Framework itself is NOT
bundled inside the VulnusLab scanner image (~4 GB + a PostgreSQL
backend), so every probe first checks `shutil.which("msfconsole")` (or
the equivalent binary) and falls back to an INFO finding with installer
instructions when the binary is absent.

Scope:
  tier1_msf_core : module inventory + auxiliary scanner + msfdb health
  tier2_payloads : benign msfvenom test + post-exploitation catalog

ScanRequest.target = host being audited.
ScanRequest.options carries per-probe knobs:
  - options.module    auxiliary/* module to run for msf_auxiliary_scan
                      (default "auxiliary/scanner/smb/smb_version")
  - options.RHOSTS    target list passed to the auxiliary module
                      (defaults to ScanRequest.target)
  - options.RPORT     module RPORT override (optional)
  - options.module_options dict of extra "SET name value" pairs for
                      module-specific knobs (THREADS, TIMEOUT, etc.)
  - options.timeout_sec wall-clock cap per msfconsole/msfvenom run

Safety: every payload generation uses CMD=calc.exe (benign) and writes
to /dev/null. No exploit modules are ever executed - this LITE wrapper
runs auxiliary scanners + inventories only.
"""
