"""tier2_crack - offline hash cracking probes.

Each probe wraps an offline cracking engine (john / hashcat in later
tiers) against a customer-supplied hash list. Cleartext passwords are
NEVER written to findings / logs / PDFs — only counts of cracked hashes
and the hash prefix are reported, per VulnusLab privacy policy.
"""
