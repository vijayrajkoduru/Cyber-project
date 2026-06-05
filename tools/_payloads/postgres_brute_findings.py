"""postgres_brute - finding rules (VL-METHOD aware).

Reads state keys populated by PostgresBrute's 7-stage flow:
  - methodology_findings  : list of verified credentials
  - port_reachable        : bool from pre_flight
  - psycopg2_lib_missing  : bool when driver isn't installed
  - fingerprint           : dict {server_version, auth_method, db_name, error_raw}
  - chain_next            : list of follow-up scanner names

Severity derives from CONFIRMED + privilege_level:
  CONFIRMED admin/superuser -> CRITICAL  CVSS 9.8
  CONFIRMED user/user_create -> MEDIUM   CVSS 6.5
  CONFIRMED guest            -> LOW      CVSS 4.3
  SUSPECTED any              -> LOW      CVSS 3.7

Special rule: rule_trust_auth fires HIGH when fingerprint exposes
trust auth method (any valid username = login, no password needed).
"""


INTEL_FIELDS = [
    ("PostgreSQL Version", "fingerprint"),
    ("Quick-probe attempts", "quick_probe_attempts"),
    ("Quick-probe hits", "quick_probe_hits"),
    ("Deep scan attempts", "pg_deep_attempts"),
    ("Stage timings (ms)", "stage_timings"),
    ("Stage errors", "stage_errors"),
    ("Chain ID", "chain_id"),
]


def rule_unreachable(s):
    if s.get("port_reachable") is not False:
        return None
    # If lib is missing AND port is unreachable, prefer the lib-missing rule.
    if s.get("psycopg2_lib_missing"):
        return None
    return {
        "name": "PostgreSQL port unreachable - cannot test credential security",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "Port 5432 closed or filtered",
        "remediation": (
            "If PostgreSQL is intentionally not exposed, this is good. "
            "If it should be reachable from the scan vantage, verify the "
            "firewall + that postgres is listening on the public interface. "
            "Re-run scan once port is reachable to test credential strength."
        ),
        "cwe": "CWE-1006",
    }


def rule_lib_missing(s):
    if not s.get("psycopg2_lib_missing"):
        return None
    return {
        "name": "psycopg2 driver missing - PostgreSQL credential check skipped",
        "severity": "INFO",
        "evidence": (
            "The PostgreSQL Python driver (psycopg2) is not installed on "
            "the scanner host, so no credential probe could be attempted. "
            "Install with: pip install psycopg2-binary"
        ),
        "remediation": (
            "Install psycopg2-binary (or psycopg2 + libpq-dev) in the "
            "scanner container, then re-run this scan."
        ),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    deep_skipped = s.get("deep_skipped") or ""
    if "userlist/passlist not supplied" not in deep_skipped:
        return None
    hits = s.get("methodology_total", 0)
    if hits > 0:
        return None
    return {
        "name": "Deep spray skipped - userlist/passlist not provided",
        "severity": "INFO",
        "evidence": (
            "Quick-probe ran 5 known-bad defaults (postgres/postgres, "
            "postgres/(empty), admin/admin, root/root, test/test) "
            "against databases 'postgres' and 'template1' - none worked. "
            "To run a full spray, provide options.userlist + options.passlist "
            "on the request body (newline-separated). Max 10 users x 25 pwds."
        ),
        "remediation": (
            "Supply options.userlist + options.passlist to test against "
            "your organization's password policy (or a known-leaked PG "
            "wordlist)."
        ),
        "cwe": "CWE-1006",
    }


def rule_trust_auth(s):
    fp = s.get("fingerprint") or {}
    if (fp.get("auth_method") or "").lower() != "trust":
        return None
    return {
        "name": "PostgreSQL allows trust authentication - no password required",
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-287",
        "owasp": "A07:2021",
        "evidence": (
            "PostgreSQL fingerprint stage detected 'trust' authentication "
            "in pg_hba.conf - any valid username can connect WITHOUT a "
            "password. Server response: " + (fp.get("error_raw") or "")[:200]
        ),
        "remediation": (
            "Replace 'trust' lines in pg_hba.conf with 'scram-sha-256' (or "
            "at minimum 'md5'). Reload PostgreSQL config (SELECT pg_reload_conf()). "
            "Trust auth should ONLY be used for local Unix-socket connections "
            "on developer machines, NEVER for network-reachable interfaces."
        ),
    }


def _pg_responded(s) -> bool:
    """True if PostgreSQL fingerprint stage extracted ANY signal from the
    server (version, auth method, or raw FATAL error). Used to gate
    rule_positive_quick so we don't falsely claim 'PG rejects defaults'
    when the service didn't respond like real PG at all."""
    fp = s.get("fingerprint") or {}
    return bool(
        fp.get("server_version")
        or fp.get("auth_method")
        or fp.get("error_raw")
    )


def rule_positive_quick(s):
    # Quick-probe ran, no hits, no real findings, fingerprint confirms PG -> GOOD signal.
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if not _pg_responded(s):
        return None  # no fingerprint -> rule_inconclusive
    fp = s.get("fingerprint") or {}
    return {
        "name": "PostgreSQL rejects all 5 known-bad default credentials",
        "severity": "POSITIVE",
        "evidence": (
            f"Tried {s.get('quick_probe_attempts', 0)} probes "
            "(postgres/postgres, postgres/empty, admin/admin, root/root, "
            "test/test) across 'postgres' and 'template1' databases; "
            "all rejected. PG fingerprint: server_version="
            f"{fp.get('server_version') or 'unknown'}, auth_method="
            f"{fp.get('auth_method') or 'unknown'}."
        ),
        "remediation": (
            "Continue blocking default credentials. Enforce scram-sha-256 "
            "in pg_hba.conf, require strong passwords for the 'postgres' "
            "superuser, and restrict listen_addresses to the minimum "
            "required interfaces."
        ),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


def rule_inconclusive(s):
    """Port accepts TCP SYN but PG didn't respond like real PostgreSQL.
    Could be a filtered-accept firewall or a non-PG service on 5432."""
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if _pg_responded(s):
        return None
    return {
        "name": "PostgreSQL port reachable but no PG response - credential security UNVERIFIED",
        "severity": "INFO",
        "evidence": (
            f"TCP/{(s.get('target_port') or 5432)} accepted the connection "
            "but the PostgreSQL fingerprint probe got no FATAL error / "
            "version / auth-method back. Either a stateful firewall is "
            "intercepting the connection or a non-PG service is bound to "
            "this port. We cannot claim PG credentials are strong - we "
            "never reached postgres."
        ),
        "remediation": (
            "If this host is supposed to expose PostgreSQL, verify the "
            "postgres process is listening and pg_hba.conf permits the "
            "scan vantage. Re-run scan from inside the VPC if appropriate. "
            "If PG is intentionally filtered at the perimeter, that is "
            "good hardening."
        ),
        "cwe": "CWE-1006",
    }


def _findings_by_severity(s):
    """Group methodology_findings by computed severity."""
    out = {"CRITICAL": [], "MEDIUM": [], "LOW": [], "SUSPECTED": []}
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "unknown")
        if conf == "CONFIRMED":
            if priv == "admin":
                out["CRITICAL"].append(f)
            elif priv in ("user", "user_create"):
                out["MEDIUM"].append(f)
            elif priv == "guest":
                out["LOW"].append(f)
            else:
                out["LOW"].append(f)
        else:
            out["SUSPECTED"].append(f)
    return out


def rule_confirmed_superuser(s):
    g = _findings_by_severity(s)
    if not g["CRITICAL"]:
        return None
    return {
        "name": f"CONFIRMED superuser PostgreSQL access via password ({len(g['CRITICAL'])} account)",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (
            "PostgreSQL superuser account(s) compromised via password "
            "spray. Verified by a fresh psycopg2 connection running "
            "SELECT version() + SELECT current_user, current_database() "
            "(verification_method=psycopg2_second_connect_select). "
            "Superuser unlocks COPY FROM PROGRAM (remote command exec) "
            "and pg_read_server_files (filesystem read). Compromised "
            "users: " + ", ".join(f["user"] for f in g["CRITICAL"][:5])
        ),
        "remediation": (
            "CRITICAL - rotate the affected superuser password immediately. "
            "Migrate pg_hba.conf to scram-sha-256. Restrict superuser "
            "accounts to localhost only (listen_addresses + host rules). "
            "Audit pg_stat_activity and PG logs for prior unauthorized "
            "sessions. Consider the host compromised - postgres superuser "
            "= RCE via COPY FROM PROGRAM."
        ),
    }


def rule_confirmed_user(s):
    g = _findings_by_severity(s)
    if not g["MEDIUM"]:
        return None
    return {
        "name": f"CONFIRMED regular PostgreSQL user access via password ({len(g['MEDIUM'])} account)",
        "severity": "MEDIUM",
        "cvss": "6.5",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (
            "Regular PostgreSQL user account(s) compromised. Privilege "
            "escalation to superuser required for RCE, but database "
            "contents accessible per the user's grants. Verified by "
            "psycopg2 second-connect SELECT. Compromised users: "
            + ", ".join(f["user"] for f in g["MEDIUM"][:5])
        ),
        "remediation": (
            "Force password reset on the affected account(s). Notify "
            "owners. Enforce strong-password policy and (ideally) "
            "scram-sha-256 in pg_hba.conf. Review GRANTs for over-broad "
            "privileges (REVOKE rolcreaterole where not needed)."
        ),
    }


def rule_confirmed_guest(s):
    g = _findings_by_severity(s)
    if not g["LOW"]:
        return None
    # rule_confirmed_guest only fires when the LOW bucket actually contains
    # CONFIRMED guest-level access (not SUSPECTED).
    guests = [f for f in g["LOW"] if f.get("confidence") == "CONFIRMED"]
    if not guests:
        return None
    return {
        "name": f"CONFIRMED guest-level PostgreSQL access via password ({len(guests)} account)",
        "severity": "LOW",
        "cvss": "4.3",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (
            "Account authenticates but can only see its own role in "
            "pg_roles - guest-equivalent visibility. Verified by "
            "psycopg2 second-connect SELECT. Users: "
            + ", ".join(f["user"] for f in guests[:5])
        ),
        "remediation": (
            "Even guest-level PG access can leak schema names and timing "
            "information. Disable or rename the account if not in use. "
            "Enforce strong-password policy."
        ),
    }


def rule_suspected(s):
    g = _findings_by_severity(s)
    suspected = g["SUSPECTED"]
    if not suspected:
        return None
    return {
        "name": f"SUSPECTED PostgreSQL credential ({len(suspected)} - needs manual verification)",
        "severity": "LOW",
        "cvss": "3.7",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (
            "Initial connect appeared to succeed but the verification "
            "reconnect or SELECT version()/current_user query failed. "
            "Could be false positive or an account with login allowed "
            "but no SELECT grant on system catalogs. Users: "
            + ", ".join(f.get("user", "?") for f in suspected[:5])
        ),
        "remediation": (
            "Manually verify with psql. If shell SELECT works, treat as "
            "CONFIRMED at the appropriate severity. If not, harden by "
            "rotating the password and reviewing pg_hba.conf rules."
        ),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": (
            "Confirmed PostgreSQL credentials enable downstream scanners: "
            + ", ".join(chain_next)
        ),
        "remediation": (
            "Re-run scan with chain_id propagation to automatically "
            "follow up with: " + ", ".join(chain_next) + ". "
            "These will inherit the captured credentials via the "
            "VL-METHOD chaining engine."
        ),
        "cwe": "CWE-1006",
    }


POSTGRES_BRUTE_FINDING_RULES = [
    rule_unreachable,
    rule_lib_missing,
    rule_input_missing,
    rule_trust_auth,
    rule_positive_quick,
    rule_inconclusive,
    rule_confirmed_superuser,
    rule_confirmed_user,
    rule_confirmed_guest,
    rule_suspected,
    rule_chain_handoff,
]
