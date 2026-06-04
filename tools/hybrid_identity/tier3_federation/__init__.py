"""hybrid_identity tier3_federation - ADFS federation audit
(playbook §2 #20-26 + §8 modern CVE/TTPs).

Probes customer-supplied ADFS endpoints for federation metadata, ADFS
version disclosure, CVE-2017-11774 (ADFS proxy auth bypass), and
AADInternals-style metadata enumeration. verify=False for customer ADFS
which often runs internal CA cert chains.
"""
