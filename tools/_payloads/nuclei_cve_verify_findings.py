"""nuclei_cve_verify - findings rules.

Severity model:
  CRITICAL/HIGH/MEDIUM/LOW - mirror nuclei's info.severity per template hit
  INFO     - nuclei binary missing / target unreachable / timeout
  POSITIVE - sweep ran, 0 template hits (good patching posture)

Each CVE hit finding carries:
  - CVE-ID (from classification.cve-id)
  - CVSS score (from classification.cvss-score)
  - EPSS percentile (looked up from embedded high-impact CVE map)
  - CISA KEV flag (looked up from embedded KEV catalog snapshot)
  - CWE (from classification.cwe-id)
  - Patch version remediation (from embedded vendor advisory map)
"""

# Embedded snapshot of high-impact CVEs likely to fire on customer targets.
# Maintained from EPSS public CSV + CISA KEV catalog (2026-Q2).
# When nuclei reports a CVE not in this map, we still emit the finding with
# generic remediation pointing the customer to MITRE + vendor advisory.
_HIGH_IMPACT_CVES = {
    "CVE-2021-44228": {
        "name":  "Log4Shell (Apache Log4j2 JNDI lookup RCE)",
        "epss":  "99.6%",
        "kev":   True,
        "patch": "log4j-core >= 2.17.1 (2.16 mitigates, 2.17.1 is the audited fix).",
    },
    "CVE-2021-45046": {
        "name":  "Log4j2 Thread Context Map DoS / partial RCE",
        "epss":  "97.8%",
        "kev":   True,
        "patch": "log4j-core >= 2.16.0.",
    },
    "CVE-2022-22965": {
        "name":  "Spring4Shell (Spring Framework Class.module.classLoader RCE)",
        "epss":  "97.4%",
        "kev":   True,
        "patch": "Spring Framework >= 5.3.18 or 5.2.20.",
    },
    "CVE-2022-22963": {
        "name":  "Spring Cloud Function SpEL injection RCE",
        "epss":  "97.1%",
        "kev":   True,
        "patch": "Spring Cloud Function >= 3.1.7 / 3.2.3.",
    },
    "CVE-2021-26855": {
        "name":  "ProxyLogon (Microsoft Exchange SSRF)",
        "epss":  "97.5%",
        "kev":   True,
        "patch": "Apply Exchange CU + March 2021 security update KB5000871.",
    },
    "CVE-2021-34473": {
        "name":  "ProxyShell (Exchange Autodiscover path confusion RCE)",
        "epss":  "97.4%",
        "kev":   True,
        "patch": "Apply Exchange CU + May 2021 security update KB5003435.",
    },
    "CVE-2021-26084": {
        "name":  "Atlassian Confluence OGNL injection RCE",
        "epss":  "97.6%",
        "kev":   True,
        "patch": "Confluence Server/Data Center >= 7.13.0.",
    },
    "CVE-2022-26134": {
        "name":  "Atlassian Confluence Server OGNL injection RCE (in-the-wild)",
        "epss":  "97.5%",
        "kev":   True,
        "patch": "Confluence Server >= 7.18.1 (per Atlassian advisory).",
    },
    "CVE-2022-1388": {
        "name":  "F5 BIG-IP iControl REST auth bypass RCE",
        "epss":  "97.6%",
        "kev":   True,
        "patch": "BIG-IP TMOS >= 17.0.0 / 16.1.2.2 / 15.1.5.1 / 14.1.4.6.",
    },
    "CVE-2023-3519": {
        "name":  "Citrix NetScaler ADC/Gateway unauth stack overflow RCE",
        "epss":  "96.8%",
        "kev":   True,
        "patch": "NetScaler 13.1-49.13 / 13.0-91.13 / 14.1-8.50 or later.",
    },
    "CVE-2023-4966": {
        "name":  "Citrix Bleed (NetScaler session token leak)",
        "epss":  "97.5%",
        "kev":   True,
        "patch": "NetScaler 14.1-8.50 / 13.1-49.15 / 13.0-92.19 or later.",
    },
    "CVE-2024-3400": {
        "name":  "Palo Alto PAN-OS GlobalProtect command injection",
        "epss":  "97.7%",
        "kev":   True,
        "patch": "PAN-OS 10.2.9-h1, 11.0.4-h1, 11.1.2-h3 or later hotfixes.",
    },
    "CVE-2024-21887": {
        "name":  "Ivanti Connect Secure command injection",
        "epss":  "97.5%",
        "kev":   True,
        "patch": "Ivanti CS 22.5R2.2+ / 9.1R18.3+ per official advisory.",
    },
    "CVE-2024-1709": {
        "name":  "ConnectWise ScreenConnect auth bypass",
        "epss":  "97.4%",
        "kev":   True,
        "patch": "ScreenConnect >= 23.9.8.",
    },
    "CVE-2023-46805": {
        "name":  "Ivanti Connect Secure auth bypass",
        "epss":  "96.9%",
        "kev":   True,
        "patch": "Ivanti CS 22.5R2.2+ / 9.1R18.3+ per official advisory.",
    },
    "CVE-2023-48795": {
        "name":  "Terrapin SSH prefix-truncation downgrade attack",
        "epss":  "55.4%",
        "kev":   False,
        "patch": "OpenSSH >= 9.6p1; PuTTY >= 0.80; libssh >= 0.10.6 / 0.9.8.",
    },
    "CVE-2024-6387": {
        "name":  "regreSSHion (OpenSSH sshd race-condition RCE)",
        "epss":  "67.2%",
        "kev":   False,
        "patch": "OpenSSH >= 9.8p1 (or backport patch on 9.7 / 9.6).",
    },
}


def _lookup_meta(cve_ids: list[str]) -> dict:
    """Best-effort metadata for the first CVE-ID that we recognize."""
    for cid in cve_ids:
        meta = _HIGH_IMPACT_CVES.get(cid.upper())
        if meta:
            return {"cve": cid.upper(), **meta}
    if cve_ids:
        return {"cve": cve_ids[0].upper(), "name": "", "epss": "unknown",
                "kev": False, "patch": "Apply vendor advisory; verify upstream patch is on running version."}
    return {"cve": "N/A", "name": "", "epss": "unknown", "kev": False,
            "patch": "Apply vendor advisory."}


_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}


def rule_cve_template_hits(s):
    hits = s.get("nuclei_hits") or []
    if not hits:
        return None
    out = []
    for h in hits:
        sev = (h.get("severity") or "").upper() or "MEDIUM"
        if _SEV_RANK.get(sev, 0) < _SEV_RANK["LOW"]:
            continue
        meta = _lookup_meta(h.get("cve_ids") or [])
        cwe = (h.get("cwe_ids") or ["CWE-1395"])[0]
        epss = meta["epss"]
        kev_flag = " | CISA KEV: YES" if meta["kev"] else " | CISA KEV: no"
        cvss = str(h.get("cvss_score") or "0.0")
        title = h.get("name") or meta.get("name") or h.get("template_id") or "Nuclei CVE template hit"
        out.append({
            "name": f"{title} verified at {h.get('matched_at', '?')} ({meta['cve']})",
            "severity": sev,
            "cvss": cvss,
            "cve":  meta["cve"],
            "cwe":  cwe,
            "owasp": "A06:2021",
            "evidence": (
                f"Nuclei template '{h.get('template_id')}' matched on {h.get('matched_at')}. "
                f"Severity: {sev}. CVSS: {cvss}. EPSS: {epss}{kev_flag}. "
                f"Description: {h.get('description', '')[:200]}"
            ),
            "remediation": (
                f"{meta['patch']} "
                f"After patching, re-run nuclei_cve_verify to confirm zero hits. "
                f"Reference advisories: {', '.join((h.get('reference') or [])[:3])}"
            ),
        })
    return out or None


def rule_binary_missing(s):
    err = s.get("nuclei_error")
    if not err or "binary not installed" not in str(err):
        return None
    return {
        "name": "Nuclei binary not installed on scanner host",
        "severity": "INFO",
        "evidence": "shutil.which('nuclei') returned None. CVE sweep could not execute.",
        "remediation": ("Install projectdiscovery/nuclei: "
                        "https://github.com/projectdiscovery/nuclei/releases — and run "
                        "`nuclei -update-templates` once during image build."),
        "cwe": "CWE-1006",
    }


def rule_timeout(s):
    err = s.get("nuclei_error") or ""
    if "wall-clock cap" not in str(err):
        return None
    return {
        "name": "Nuclei sweep hit wall-clock cap",
        "severity": "INFO",
        "evidence": str(err),
        "remediation": ("Increase options.timeout_sec or narrow options.tags / "
                        "options.severity to reduce the template load."),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("nuclei_total"):
        return None
    if not s.get("nuclei_ran"):
        return None
    if s.get("nuclei_error"):
        return None
    return {
        "name": "Target passed nuclei critical/high CVE sweep",
        "severity": "POSITIVE",
        "evidence": (
            f"Nuclei ran with severity={s.get('nuclei_severity', 'critical,high')}, "
            f"tags={s.get('nuclei_tags', 'cve')} against {s.get('nuclei_target', '?')} — "
            "0 template hits."
        ),
        "remediation": ("Maintain a monthly cadence for nuclei -update-templates + "
                        "re-run this scan. New CVE templates land weekly."),
        "cwe": "CWE-1006",
    }


NUCLEI_CVE_VERIFY_FINDING_RULES = [
    rule_cve_template_hits,
    rule_binary_missing,
    rule_timeout,
    rule_positive,
]
