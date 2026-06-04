"""ad module - Active Directory attacks (per module_playbooks/19_ad.md).

11 sections, 132 techniques. This package autoloads tier* subdirectories,
each containing real Python probes that use impacket/ldap3/bloodhound/
certipy-ad/netexec. Customer provides domain creds at scan time via
ScanRequest.options (domain, username, password, dc_ip).
"""
