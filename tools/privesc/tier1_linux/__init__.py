"""tier1_linux - Linux privilege-escalation enumeration probes.

LinPEAS upload+exec, SUID/GTFOBins cross-reference, sudo misconfiguration
audit, and kernel-version CVE matching. Each probe SSHes to ctx.host with
customer-supplied creds (options.username/password OR options.ssh_key)
via paramiko and either uploads a PEASS script or runs targeted commands.
"""
