"""mysql_brute - finding rules (VL-METHOD aware).

VL-METHOD methodology pattern. Reads state keys populated by MysqlBrute's
7-stage flow:
  - methodology_findings  : list of verified credentials (post verify+priv)
  - port_reachable        : bool from pre_flight
  - mysql_lib_missing     : bool (pymysql not installed)
  - fingerprint           : dict {server_version, protocol_version,
                                   connection_id, capabilities, raw_greeting_hex}
  - quick_probe_attempts  : int
  - quick_probe_hits      : int
  - mysql_deep_attempts   : int
  - deep_skipped          : str
  - chain_next            : list of follow-up scanner names

Severity matrix (confidence + privilege_level):
  CONFIRMED admin   -> CRITICAL  CVSS 9.8   (DBA - mysql.user readable)
  CONFIRMED user    -> MEDIUM    CVSS 6.5
  CONFIRMED guest   -> LOW       CVSS 4.3
  SUSPECTED any     -> LOW       CVSS 3.7

INDEPENDENT findings (fire regardless of credential outcome):
  Outdated MySQL/MariaDB version -> MEDIUM CVSS 5.3 CWE-1104
"""

import re


# Known EOL/outdated MySQL/MariaDB major versions. 5.6.x has been EOL
# since Feb 2021; 5.7.x EOL Oct 2023. MariaDB 10.2/10.3 EOL.
# 5.7 still gets emergency patches but is considered out-of-date for
# customer-facing audits.
_OUTDATED_PATTERNS = [
    (re.compile(r"^5\.5\."), "MySQL 5.5 - EOL since Dec 2018"),
    (re.compile(r"^5\.6\."), "MySQL 5.6 - EOL since Feb 2021"),
    (re.compile(r"^5\.7\."), "MySQL 5.7 - EOL since Oct 2023"),
    (re.compile(r"^10\.[0-3]\."), "MariaDB 10.0-10.3 - EOL"),
    (re.compile(r"^10\.4\."), "MariaDB 10.4 - EOL June 2024"),
]


# ═══════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════


def _findings_by_severity(s):
    """Bucket methodology_findings by computed severity."""
    out = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "unknown")
        if conf == "CONFIRMED":
            if priv == "admin":        out["CRITICAL"].append(f)
            elif priv == "user":       out["MEDIUM"].append(f)
            elif priv == "guest":      out["LOW"].append(f)
            else:                       out["LOW"].append(f)
        else:
            out["LOW"].append(f)
    return out


def _mysql_responded(s) -> bool:
    """True if MySQL greeting actually parsed bytes back from a real server.
    Stateful firewalls can accept TCP/3306 without MySQL running -> no
    server_version and no raw_greeting_hex. POSITIVE rule would be lying:
    we never spoke real MySQL, we just timed out N times."""
    fp = s.get("fingerprint") or {}
    return bool(fp.get("server_version") or fp.get("raw_greeting_hex"))


def _fp_blurb(s):
    fp = s.get("fingerprint") or {}
    parts = []
    if fp.get("server_version"):   parts.append(f"version={fp['server_version']}")
    if fp.get("protocol_version") is not None:
        parts.append(f"proto={fp['protocol_version']}")
    if fp.get("connection_id") is not None:
        parts.append(f"conn_id={fp['connection_id']}")
    return ", ".join(parts) or "fingerprint unavailable"


# ═══════════════════════════════════════════════════════════════════
#  Rules
# ═══════════════════════════════════════════════════════════════════


def rule_unreachable(s):
    if s.get("port_reachable") is not False:
        return None
    return {
        "name": "MySQL port unreachable - cannot test MySQL credential security",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "Port 3306 closed or filtered",
        "remediation": ("If MySQL is meant to be exposed, verify the bind-address "
                        "+ firewall + mysqld is running. If MySQL is intentionally "
                        "blocked from this scan origin, that is the recommended "
                        "posture - MySQL should NEVER be exposed to the public "
                        "internet. Re-run scan from an internal vantage point to "
                        "actually test MySQL credential strength."),
        "cwe": "CWE-1006",
    }


def rule_lib_missing(s):
    if not s.get("mysql_lib_missing"):
        return None
    return {
        "name": "pymysql client library missing - MySQL spray cannot run",
        "severity": "INFO",
        "evidence": ("The VulnusLab backend is missing the `pymysql` Python "
                     "package, so no quick-probe / deep-scan against MySQL "
                     "auth could be executed. The scanner short-circuits "
                     "and returns this INFO so the dashboard doesn't claim "
                     "credentials are strong without testing them."),
        "remediation": ("Install pymysql on the backend container: "
                        "`pip install pymysql`. Add it to the backend "
                        "Dockerfile so it ships in the image. Re-run "
                        "scan once the library is available."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    deep_skipped = s.get("deep_skipped") or ""
    if "userlist/passlist not supplied" not in deep_skipped:
        return None
    if s.get("methodology_total", 0) > 0:
        return None
    return {
        "name": "Deep MySQL spray skipped - userlist/passlist not provided",
        "severity": "INFO",
        "evidence": ("Quick-probe ran 5 known-bad MySQL defaults "
                     "(root/<empty>, root/root, admin/admin, mysql/mysql, "
                     "test/test) - none worked. To run a full spray, supply "
                     "options.userlist + options.passlist on the request body "
                     "(newline-separated). Max 10 users x 25 pwds."),
        "remediation": ("Supply options.userlist + options.passlist to test "
                        "against your DB password policy. Recommend SecLists "
                        "top MySQL usernames + breach top-25 passwords."),
        "cwe": "CWE-1006",
    }


def rule_outdated_version(s):
    """INDEPENDENT finding - fires when fingerprint shows an EOL MySQL/MariaDB.
    Regardless of credential outcome, running EOL software exposes the
    server to public CVEs that will never get patched."""
    if s.get("port_reachable") is not True:
        return None
    fp = s.get("fingerprint") or {}
    ver = (fp.get("server_version") or "").strip()
    if not ver:
        return None
    matched_label = None
    for pat, label in _OUTDATED_PATTERNS:
        if pat.match(ver):
            matched_label = label
            break
    if not matched_label:
        return None
    return {
        "name": f"MySQL/MariaDB out-of-date - {matched_label}",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-1104",
        "owasp": "A06:2021",
        "evidence": (f"Server greeting reports version `{ver}`. {matched_label}. "
                     "Running an end-of-life database means publicly disclosed "
                     "CVEs in this branch will never receive vendor patches. "
                     f"Fingerprint: {_fp_blurb(s)}."),
        "remediation": ("Upgrade to a currently-supported MySQL (8.0 LTS / 8.4) "
                        "or MariaDB (10.5+, ideally 10.11 LTS / 11.x) branch. "
                        "Plan the upgrade window with the application owners, "
                        "test app compatibility in staging (some 5.7 -> 8.0 "
                        "behavior changes around utf8mb4 + auth plugin), and "
                        "subscribe to the vendor security advisory list."),
    }


def rule_positive_quick(s):
    """Quick-probe ran, NO hits, NO real findings - GOOD signal.
    Guard: only fire POSITIVE if MySQL greeting actually parsed real
    server bytes. See rule_inconclusive for the 'port reachable but
    no MySQL service' branch."""
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if not _mysql_responded(s):
        return None  # filtered/no-service -> rule_inconclusive
    return {
        "name": "MySQL rejects all 5 known-bad default credentials",
        "severity": "POSITIVE",
        "evidence": (f"Tried {s.get('quick_probe_attempts', 5)} known-bad MySQL "
                     "defaults (root/<empty>, root/root, admin/admin, "
                     "mysql/mysql, test/test); all rejected. "
                     f"Fingerprint: {_fp_blurb(s)}."),
        "remediation": ("Continue blocking default credentials. Enforce a "
                        "strong DB password policy (16+ char random) for every "
                        "MySQL account. Remove the anonymous account "
                        "(`DROP USER ''@'localhost'`). Restrict root to "
                        "localhost only (`UPDATE mysql.user SET Host='localhost' "
                        "WHERE User='root'`). Never expose 3306 to the public "
                        "internet - put MySQL behind a VPN / private subnet."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


def rule_inconclusive(s):
    """Port accepts TCP SYN but MySQL greeting got no real server data -
    typical of stateful firewalls that 'accept-and-RST' filtered ports,
    or a non-MySQL service squatting on 3306. Emit INFO so PDF doesn't
    falsely claim "MySQL rejects defaults" when we never spoke MySQL."""
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if _mysql_responded(s):
        return None  # service responded -> rule_positive_quick handles it
    return {
        "name": "MySQL port reachable but service did not greet - credential security UNVERIFIED",
        "severity": "INFO",
        "evidence": (f"TCP/3306 accepted the connection but no MySQL server "
                     "greeting was parsed and "
                     f"{s.get('quick_probe_attempts', 5)} pymysql default-"
                     "credential attempts all errored/timed-out. This is "
                     "typical of stateful firewalls that 'accept-and-RST' "
                     "filtered ports, a non-MySQL service squatting on 3306, "
                     "or a MySQL instance hung at startup. We cannot claim "
                     "credentials are strong - we never reached the auth layer."),
        "remediation": ("If this host is supposed to expose MySQL, verify "
                        "mysqld is running and the firewall isn't intercepting "
                        "the connection. Re-run scan from an internal vantage "
                        "point. If MySQL is intentionally filtered at the "
                        "perimeter, that is excellent hardening - MySQL should "
                        "NEVER be exposed to the public internet."),
        "cwe": "CWE-1006",
    }


def rule_confirmed_dba(s):
    g = _findings_by_severity(s)
    if not g["CRITICAL"]:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in g["CRITICAL"]}))[:200]
    return {
        "name": f"CONFIRMED MySQL DBA access via password ({len(g['CRITICAL'])} account)",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("DBA-privileged account(s) compromised via MySQL password "
                     "spray. mysql.user table is readable - attacker can dump "
                     "every account's password hash for offline cracking and "
                     "lateral movement. With FILE privilege, attacker can also "
                     "write UDF/.so or read arbitrary files (/etc/passwd, "
                     "secrets). Verified by separate pymysql connection running "
                     "SELECT VERSION() + SELECT USER() "
                     "(verification_method=pymysql_second_connect_select). "
                     f"Compromised users: {users}. Fingerprint: {_fp_blurb(s)}."),
        "remediation": (
            "CRITICAL - treat the database as compromised until proven clean. "
            "1. Rotate the password for the compromised DBA account immediately on this server AND every server where the same credentials are reused. "
            "2. Audit mysql general / audit log for prior unauthorized queries; look for SELECT INTO OUTFILE, LOAD_FILE, CREATE FUNCTION, and dumps of mysql.user. "
            "3. Run `SHOW GRANTS` for every account; drop unnecessary GRANT ALL or WITH GRANT OPTION privileges. "
            "4. Enforce 16+ char random passwords for all mysql accounts; disable old_passwords; require caching_sha2_password (MySQL 8) or ed25519 (MariaDB). "
            "5. Bind-address = 127.0.0.1 if app + db are on the same host; otherwise put MySQL behind a VPN / private subnet. NEVER expose 3306 to the internet. "
            "6. Drop the anonymous account: DROP USER ''@'localhost'; and restrict root to localhost. "
            "7. Enable MySQL audit plugin (Percona Audit / MariaDB Audit / mysql_audit) and ship logs to the SIEM."
        ),
    }


def rule_confirmed_user(s):
    g = _findings_by_severity(s)
    if not g["MEDIUM"]:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in g["MEDIUM"]}))[:200]
    return {
        "name": f"CONFIRMED regular MySQL user access via password ({len(g['MEDIUM'])} account)",
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Regular MySQL user account(s) compromised via password "
                     "spray. mysql.user is NOT readable (no DBA), but the "
                     "account can list databases and likely access at least "
                     "one application schema - giving an attacker direct read "
                     "(and possibly write) on application data, PII, business "
                     "records. Verified by second pymysql connection "
                     "(verification_method=pymysql_second_connect_select). "
                     f"Compromised users: {users}. Fingerprint: {_fp_blurb(s)}."),
        "remediation": ("Force password reset on the affected MySQL accounts "
                        "and notify the application owner(s). Enforce strong "
                        "password policy (16+ char random) for every db user. "
                        "Apply least-privilege: drop SUPER / FILE / PROCESS "
                        "grants from app users; restrict to the specific "
                        "schemas they need. Bind-address = 127.0.0.1 when "
                        "possible; otherwise restrict by source IP via "
                        "`CREATE USER 'app'@'10.0.0.5'` rather than "
                        "`'app'@'%'`."),
    }


def rule_confirmed_guest(s):
    g = _findings_by_severity(s)
    guest_low = [f for f in g["LOW"]
                 if f.get("confidence") == "CONFIRMED"
                 and f.get("privilege_level") == "guest"]
    if not guest_low:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in guest_low}))[:200]
    return {
        "name": f"CONFIRMED limited-grant MySQL access ({len(guest_low)} account)",
        "severity": "LOW", "cvss": "4.3",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Limited-grant MySQL account(s) compromised. SHOW "
                     "DATABASES failed and only the account's own GRANTs are "
                     "visible. Useful intel for an attacker - the account "
                     "still exists with a weak/guessable password and may "
                     "have schema-level access not enumerable from this "
                     f"vantage. Verified by second pymysql connection. "
                     f"Compromised users: {users}. Fingerprint: {_fp_blurb(s)}."),
        "remediation": ("Even limited MySQL accounts must use strong unique "
                        "passwords. Rotate the password; audit what schemas "
                        "the account does have access to via `SHOW GRANTS FOR "
                        "<user>` from the DBA console. Disable any account "
                        "that no longer corresponds to an active app or "
                        "user (`DROP USER`)."),
    }


def rule_suspected(s):
    g = _findings_by_severity(s)
    suspected = [f for f in g["LOW"] if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in suspected}))[:200]
    return {
        "name": f"SUSPECTED MySQL credential ({len(suspected)} - needs manual verification)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("pymysql reported these credentials as valid at the auth "
                     "layer but the second-connection verification (SELECT "
                     "VERSION + SELECT USER) could not confirm. Could be a "
                     "transient network issue, account with login-but-no-"
                     "query-privilege, or a TLS handshake quirk on retry. "
                     f"Users: {users}."),
        "remediation": ("Manually verify with `mysql -h <host> -u <user> -p` "
                        "and run `SELECT VERSION();`. If auth + query DO work, "
                        "treat as CONFIRMED per privilege. If auth fails "
                        "manually, this was a false positive - safe to ignore "
                        "but file an issue for VulnusLab to tune pymysql "
                        "retry handling."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed MySQL credentials enable downstream scanners: "
                     + ", ".join(chain_next)),
        "remediation": ("Re-run scan with chain_id propagation to automatically "
                        "follow up with: " + ", ".join(chain_next) + ". These "
                        "will inherit the captured credentials via the VL-METHOD "
                        "chaining engine and pursue secrets dump / UDF lateral "
                        "movement / user enumeration."),
        "cwe": "CWE-1006",
    }


INTEL_FIELDS = [
    ("MySQL Server Version",   "fingerprint"),
    ("Quick-probe attempts",   "quick_probe_attempts"),
    ("Quick-probe hits",       "quick_probe_hits"),
    ("Deep scan attempts",     "mysql_deep_attempts"),
    ("Stage timings (ms)",     "stage_timings"),
    ("Stage errors",           "stage_errors"),
    ("Chain ID",               "chain_id"),
]


MYSQL_BRUTE_FINDING_RULES = [
    rule_unreachable,
    rule_lib_missing,
    rule_input_missing,
    rule_outdated_version,
    rule_positive_quick,
    rule_inconclusive,
    rule_confirmed_dba,
    rule_confirmed_user,
    rule_confirmed_guest,
    rule_suspected,
    rule_chain_handoff,
]
