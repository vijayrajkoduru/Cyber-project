"""tier1_msf_core - Metasploit Framework health + auxiliary scanners.

Each probe wraps a Kali-installed msfconsole/msfdb binary. When the
binary is missing the probe returns an INFO finding (CWE-1006) with
installer instructions instead of failing the scan.
"""
