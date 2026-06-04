"""spring4shell_verify - findings rules.

Severity model:
  HIGH     - status-shift + Spring/Tomcat banner present (vulnerable)
  MEDIUM   - status-shift OR Spring banner only (suspected, needs follow-up)
  INFO     - probe could not run (no target, network error)
  POSITIVE - probe ran with no vulnerability indicators (patched OR not Spring)
"""


def rule_vulnerable(s):
    if not s.get("spring4shell_vulnerable"):
        return None
    indicators = s.get("spring4shell_indicators") or []
    return {
        "name": "Spring4Shell EXPLOITABLE - Spring DataBinder accepts classLoader mutation",
        "severity": "HIGH",
        "cvss": "9.8",
        "cve":  "CVE-2022-22965",
        "cwe":  "CWE-470",
        "owasp": "A03:2021",
        "evidence": (
            f"Probe against {s.get('spring4shell_target_url', '?')} produced "
            f"{len(indicators)} vulnerability indicator(s): {'; '.join(indicators)}. "
            f"Baseline {s.get('spring4shell_baseline_status')} -> POST "
            f"{s.get('spring4shell_post_status')} -> follow-up "
            f"{s.get('spring4shell_follow_status')}. Server banner: "
            f"{s.get('spring4shell_baseline_server', 'unknown')}. "
            "EPSS: 97.4% | CISA KEV: YES."
        ),
        "remediation": (
            "1. Upgrade Spring Framework to >= 5.3.18 OR 5.2.20 (the audited fix). "
            "Spring Boot >= 2.5.12 / 2.6.6 ships these. "
            "2. Until you can patch: add a ControllerAdvice that calls "
            "@InitBinder dataBinder.setDisallowedFields(\"class.*\",\"Class.*\","
            "\"*.class.*\",\"*.Class.*\") on every controller. "
            "3. Run Tomcat with the latest 9.0.x / 10.0.x — even with Spring patched, "
            "Tomcat 9.0.62+ also hardens the AccessLogValve mutation path. "
            "4. Re-run this scan after the patch; vulnerable indicators should drop to 0."
        ),
    }


def rule_suspected(s):
    if s.get("spring4shell_vulnerable"):
        return None
    indicators = s.get("spring4shell_indicators") or []
    if not indicators:
        return None
    # MEDIUM tier: at least one indicator but not full vulnerable pattern.
    has_shift = any("POST returned" in i or "hash drifted" in i for i in indicators)
    has_banner = any("Spring banner" in i or "Tomcat banner" in i for i in indicators)
    if not (has_shift or has_banner):
        return None
    return {
        "name": "Spring4Shell partial indicators - manual confirmation recommended",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cve":  "CVE-2022-22965",
        "cwe":  "CWE-470",
        "owasp": "A03:2021",
        "evidence": (
            f"Probe against {s.get('spring4shell_target_url', '?')} produced "
            f"partial indicators: {'; '.join(indicators)}. Target is either "
            "running Spring without an exposed @InitBinder OR the pipeline "
            "mutation was rejected (rate limit / WAF / not vulnerable)."
        ),
        "remediation": (
            "Manually test the probe path with a real PoC against a staging clone. "
            "If exploitable, follow CVE-2022-22965 remediation: upgrade to "
            "Spring Framework >= 5.3.18 OR 5.2.20."
        ),
    }


def rule_network_error(s):
    if s.get("spring4shell_ran"):
        return None
    return {
        "name": "Spring4Shell probe could not run",
        "severity": "INFO",
        "evidence": (
            f"Errors: baseline={s.get('spring4shell_baseline_error', '-')}; "
            f"post={s.get('spring4shell_post_error', '-')}; "
            f"follow={s.get('spring4shell_follow_error', '-')}; "
            f"no_target={s.get('spring4shell_no_target', False)}."
        ),
        "remediation": ("Confirm the target HTTP service is reachable and re-run "
                        "with options.path pointed at a real Spring controller."),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if not s.get("spring4shell_ran"):
        return None
    if s.get("spring4shell_vulnerable"):
        return None
    indicators = s.get("spring4shell_indicators") or []
    if indicators:
        return None
    return {
        "name": "Target passed Spring4Shell verification",
        "severity": "POSITIVE",
        "cve":  "CVE-2022-22965",
        "cwe":  "CWE-470",
        "owasp": "A03:2021",
        "evidence": (
            f"Canonical AccessLogValve mutation POST against "
            f"{s.get('spring4shell_target_url', '?')} produced no Spring/Tomcat "
            "indicators and no status drift. Likely patched or not running Spring."
        ),
        "remediation": ("Pin Spring Framework >= 5.3.18 / 5.2.20 in your dependency "
                        "manifest + re-run quarterly + after every dependency bump."),
    }


SPRING4SHELL_VERIFY_FINDING_RULES = [
    rule_vulnerable,
    rule_suspected,
    rule_network_error,
    rule_positive,
]
