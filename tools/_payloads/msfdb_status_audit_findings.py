"""msfdb_status_audit - findings rules.

Severity model:
  MEDIUM    msfdb installed but DB not initialised (state will not persist)
  INFO      msfdb missing / status reported / probe error
  POSITIVE  msfdb running + msfconsole confirms it's connected
"""


def rule_binary_missing(s):
    if not s.get("msfdb_status_audit_binary_missing"):
        return None
    return {
        "name": "msfdb binary not installed on scanner host",
        "severity": "INFO",
        "evidence": ("shutil.which('msfdb') returned None. The msfdb "
                     "binary is shipped as part of metasploit-framework; "
                     "its absence usually means MSF itself is not installed."),
        "remediation": (
            "Install Metasploit Framework: "
            "apt install metasploit-framework + msfdb init. "
            "msfdb is bundled as part of that package."
        ),
        "cwe": "CWE-1006",
    }


def rule_db_not_initialised(s):
    if not s.get("msfdb_status_audit_db_not_initialised"):
        return None
    return {
        "name": "Metasploit msfdb installed but database not initialised",
        "severity": "MEDIUM",
        "cvss": "4.3",
        "cwe": "CWE-665",
        "evidence": (
            "msfdb status reported 'no configuration file found' - msfdb "
            "has never been initialised on this host. Without msfdb, "
            "msfconsole's hosts/services/vulns/creds tables are wiped at "
            "the end of every session, breaking multi-step engagements."
        ),
        "remediation": (
            "1. Run `msfdb init` as the user that owns the scanner "
            "(NOT root, unless the scanner runs as root). 2. Verify with "
            "`msfdb status` - expect 'Database started'. 3. Add `db_connect "
            "msf` to ~/.msf4/msfconsole.rc so future sessions auto-attach. "
            "4. Re-run this probe."
        ),
    }


def rule_db_stopped(s):
    if not s.get("msfdb_status_audit_db_stopped"):
        return None
    return {
        "name": "Metasploit msfdb database service is stopped",
        "severity": "MEDIUM",
        "cvss": "4.3",
        "cwe": "CWE-665",
        "evidence": (
            "msfdb status reported 'Database stopped'. The PostgreSQL "
            "backend exists but is not running, so msfconsole sessions "
            "will fall back to in-memory state only."
        ),
        "remediation": (
            "1. Start the database: `msfdb start` (or `systemctl start "
            "postgresql` if PostgreSQL is managed by systemd). 2. Verify "
            "with `msfdb status`. 3. If startup fails, check `journalctl "
            "-u postgresql` for the actual cause (full disk, wrong "
            "permissions, conflicting cluster). 4. Re-run this probe."
        ),
    }


def rule_db_not_connected_from_msfconsole(s):
    if not s.get("msfdb_status_audit_db_not_connected_from_msfconsole"):
        return None
    if s.get("msfdb_status_audit_db_not_initialised"):
        return None  # already covered
    return {
        "name": ("msfdb DB is running but msfconsole cannot connect to it"),
        "severity": "MEDIUM",
        "cvss": "4.3",
        "cwe": "CWE-1188",
        "evidence": (
            "msfdb status reports the DB is running, but msfconsole -q -x "
            "'db_status' emitted 'database not connected'. Likely cause: "
            "missing db_connect line in ~/.msf4/msfconsole.rc, or stale "
            "DB credentials after a hostname change."
        ),
        "remediation": (
            "1. Re-prime msfconsole's DB credentials: `msfdb reinit` (will "
            "regenerate ~/.msf4/database.yml). 2. Add `db_connect msf` to "
            "~/.msf4/msfconsole.rc. 3. Open msfconsole and confirm "
            "`db_status` prints 'Connected to msf'."
        ),
    }


def rule_audit_error(s):
    err = s.get("msfdb_status_audit_error")
    if not err:
        return None
    return {
        "name": "msfdb status audit failed",
        "severity": "INFO",
        "evidence": f"Probe error: {str(err)[:300]}",
        "remediation": (
            "1. Run `msfdb status` manually to confirm the binary works "
            "outside the scanner. 2. If it hangs, check for stale postgres "
            "lock files at /var/run/postgresql/. 3. Re-run this probe."
        ),
        "cwe": "CWE-754",
    }


def rule_positive_healthy(s):
    if s.get("msfdb_status_audit_binary_missing"):
        return None
    if s.get("msfdb_status_audit_db_not_initialised"):
        return None
    if s.get("msfdb_status_audit_db_stopped"):
        return None
    if s.get("msfdb_status_audit_db_not_connected_from_msfconsole"):
        return None
    if s.get("msfdb_status_audit_error"):
        return None
    if not s.get("msfdb_status_audit_db_running"):
        return None
    host_rows = s.get("msfdb_status_audit_host_rows") or 0
    svc_rows = s.get("msfdb_status_audit_service_rows") or 0
    return {
        "name": (f"Metasploit msfdb backend healthy "
                 f"({host_rows} host row(s), {svc_rows} service row(s))"),
        "severity": "POSITIVE",
        "evidence": (
            "msfdb status reports the DB is running and msfconsole "
            "successfully connected. Engagement state will persist across "
            "msfconsole sessions."
        ),
        "remediation": (
            "Keep the database healthy: 1. Back up ~/.msf4/database.yml "
            "after each major engagement. 2. Run `msfdb reinit` quarterly "
            "to flush stale schema migrations. 3. Re-run this audit on a "
            "monthly cadence."
        ),
        "cwe": "CWE-1357",
    }


MSFDB_STATUS_AUDIT_FINDING_RULES = [
    rule_binary_missing,
    rule_db_not_initialised,
    rule_db_stopped,
    rule_db_not_connected_from_msfconsole,
    rule_audit_error,
    rule_positive_healthy,
]
