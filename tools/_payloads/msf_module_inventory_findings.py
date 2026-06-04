"""msf_module_inventory - findings rules.

Severity model:
  INFO     msfconsole missing / inventory enumerated / db not connected /
           spawn or timeout error (transparency)
  POSITIVE inventory completed with a reasonable count (>= 800 modules)

Industry baseline (MSF 6.4.x, mid-2026 build) ships ~2,400 auxiliary
modules. We tag anything < 800 as a thin install (likely a stripped or
out-of-date framework), and emit a POSITIVE when the count meets that
floor.
"""


def rule_binary_missing(s):
    if not s.get("msf_module_inventory_binary_missing"):
        return None
    return {
        "name": "Metasploit Framework not installed on scanner host",
        "severity": "INFO",
        "evidence": ("shutil.which('msfconsole') returned None. The "
                     "module-inventory probe could not enumerate "
                     "auxiliary modules because msfconsole is absent."),
        "remediation": (
            "Install Metasploit Framework on the scanner host: "
            "1. apt update && apt install -y metasploit-framework "
            "(Debian/Kali); or curl -L https://raw.githubusercontent.com/"
            "rapid7/metasploit-omnibus/master/config/templates/"
            "metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && "
            "chmod +x /tmp/msfinstall && /tmp/msfinstall (other distros). "
            "2. Run `msfdb init` once after install to provision the "
            "PostgreSQL backend. 3. Re-run this scan."
        ),
        "cwe": "CWE-1006",
        "mitre": "T1595.002",
    }


def rule_inventory_low(s):
    if s.get("msf_module_inventory_binary_missing"):
        return None
    if s.get("msf_module_inventory_error"):
        return None
    total = s.get("msf_module_inventory_total")
    if total is None:
        return None
    if total >= 800:
        return None
    sample = ", ".join((s.get("msf_module_inventory_sample") or [])[:5]) or "n/a"
    return {
        "name": (f"Metasploit Framework auxiliary module count is "
                 f"unexpectedly low ({total})"),
        "severity": "MEDIUM",
        "cvss": "4.3",
        "cwe": "CWE-1357",  # CWE-1357 Reliance on Insufficiently Trustworthy Component
        "evidence": (
            f"msfconsole reported only {total} auxiliary module(s); a "
            "current MSF 6.4.x install ships ~2,400. Sampled module "
            f"names: {sample}. Probable causes: out-of-date framework, "
            "stripped distribution package, or msfdb cache rebuild needed."
        ),
        "remediation": (
            "1. Update Metasploit Framework: `apt update && apt install "
            "--only-upgrade metasploit-framework` or `msfupdate`. "
            "2. Verify the module tree with `ls /usr/share/metasploit-framework/"
            "modules/auxiliary | wc -l` (expect 4 OS subdirs + ~2,400 .rb files). "
            "3. Re-run `msfdb reinit` if the count remains low; the cached "
            "module index may be corrupt."
        ),
        "mitre": "T1595.002",
    }


def rule_db_not_connected(s):
    if not s.get("msf_module_inventory_db_not_connected"):
        return None
    return {
        "name": "Metasploit Framework loaded without database connection",
        "severity": "INFO",
        "evidence": ("msfconsole emitted 'database not connected' during the "
                     "inventory probe. Searches still work but results are "
                     "not cached, slowing repeated runs."),
        "remediation": (
            "1. Run `msfdb init` once to provision the local PostgreSQL "
            "service + Metasploit DB user. 2. Add `db_connect msf` to "
            "`~/.msf4/msfconsole.rc` so future sessions auto-connect. "
            "3. Re-run this probe; the inventory should be ~10x faster "
            "with a connected DB."
        ),
        "cwe": "CWE-1188",
    }


def rule_error(s):
    err = s.get("msf_module_inventory_error")
    if not err:
        return None
    return {
        "name": "msfconsole inventory probe failed",
        "severity": "INFO",
        "evidence": f"Probe error: {str(err)[:300]}",
        "remediation": (
            "1. Run `msfconsole -q -x 'version; exit'` manually as the same "
            "user that runs the scanner; confirm it returns within 60s. "
            "2. If msfconsole hangs on boot, check for stuck Ruby bundler "
            "lock at `~/.bundle` and remove it. 3. Re-run this scan."
        ),
        "cwe": "CWE-754",
    }


def rule_positive_inventory(s):
    if s.get("msf_module_inventory_binary_missing"):
        return None
    if s.get("msf_module_inventory_error"):
        return None
    total = s.get("msf_module_inventory_total") or 0
    if total < 800:
        return None
    return {
        "name": (f"Metasploit Framework auxiliary inventory healthy "
                 f"({total} modules)"),
        "severity": "POSITIVE",
        "evidence": (
            f"msfconsole search type:auxiliary returned {total} module(s), "
            "within the expected band for a current MSF 6.4.x install."
        ),
        "remediation": (
            "Keep Metasploit Framework up to date via `apt update && apt "
            "install --only-upgrade metasploit-framework` weekly, and run "
            "`msfdb reinit` quarterly to refresh the module cache."
        ),
        "cwe": "CWE-1357",
    }


MSF_MODULE_INVENTORY_FINDING_RULES = [
    rule_binary_missing,
    rule_inventory_low,
    rule_db_not_connected,
    rule_error,
    rule_positive_inventory,
]
