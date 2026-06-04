"""password module - online + offline password attack probes.

Per module_playbooks/08_password.md - 8 sections, 90 techniques.
Starter set (5 scanners) covers the highest-impact playbook items:
  - tier1_spray (online): hydra_ssh_spray, ncrack_rdp_spray,
                          medusa_smb_spray, patator_http_form_brute
  - tier2_crack (offline): john_hash_audit
More scanners will be added per playbook section in subsequent commits.

Customer input pattern: every scanner accepts ScanRequest.options.* —
userlist + passlist as newline-separated strings (online sprayers) or
hashes + hash_format (offline cracker). All wordlists/hashlists are
written to ephemeral tempfiles and deleted in a finally block.
"""
