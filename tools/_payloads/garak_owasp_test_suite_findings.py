"""garak_owasp_test_suite - findings rules (Garak hit reporting)."""


def rule_unreachable(s):
    if not s.get("garak_unreachable"):
        return None
    return {"name": "LLM endpoint not reachable for Garak / OWASP suite",
            "severity": "INFO",
            "evidence": str(s.get("garak_unreachable", "")),
            "remediation": ("Re-run with the target set to a full LLM endpoint "
                            "URL (http(s)://...), plus options.prompt_field / "
                            "options.response_field so Garak can drive it."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


def rule_library_missing(s):
    if not s.get("garak_error"):
        return None
    return {"name": "garak library not available — OWASP suite skipped",
            "severity": "INFO",
            "evidence": (str(s.get("garak_error", "")) + " " +
                         str(s.get("garak_install_hint", ""))).strip(),
            "remediation": ("Install with `pip install garak` in the backend "
                            "image. Garak is the OWASP-LLM-aligned reference "
                            "scanner — without it the audit cannot exercise the "
                            "encoding, knownbadsignatures, or DAN probe families."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


def rule_positive(s):
    if s.get("garak_total_hits", 0) > 0:
        return None
    if not s.get("garak_runs_per_probe"):
        return None
    runs = s.get("garak_runs_per_probe") or {}
    if not any(runs.values()):
        return None
    return {"name": "Garak OWASP probe suite — zero hits",
            "severity": "POSITIVE",
            "evidence": (f"Engine={s.get('garak_engine', '?')}. Probes ran "
                         f"({sum(runs.values())} attempts) with no successful "
                         "DAN, base64-injection, or phishing-generation hit."),
            "remediation": ("Schedule garak in CI on every LLM/model upgrade. "
                            "Expand probe set to the full Garak catalogue "
                            "(--probes=all) for production red-team."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


def rule_dan_hit(s):
    h = (s.get("garak_hits_per_probe") or {}).get("dan.Dan_11_0", 0)
    if not h:
        return None
    return {"name": f"Garak dan.Dan_11_0 probe hit ({h} time(s))",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-285", "owasp": "LLM02:2025",
            "evidence": (f"DAN-v11 jailbreak prompt produced compliant output "
                         f"{h} time(s). Engine: {s.get('garak_engine', '?')}."),
            "remediation": ("Re-tune refusal RLHF / add input filter that "
                            "matches the DAN-11 family. Garak's dan.Dan_11_0 "
                            "is one of the easier OWASP-LLM02 baselines — a hit "
                            "indicates the model lacks production-grade jailbreak "
                            "resistance.")}


def rule_base64_hit(s):
    h = (s.get("garak_hits_per_probe") or {}).get("encoding.InjectBase64", 0)
    if not h:
        return None
    return {"name": f"Garak encoding.InjectBase64 probe hit ({h} time(s))",
            "severity": "HIGH", "cvss": "8.1",
            "cwe": "CWE-94", "owasp": "LLM01:2025",
            "evidence": (f"Base64-encoded prompt injection succeeded {h} time(s). "
                         "Model decoded attacker-controlled content and followed "
                         "the embedded instruction."),
            "remediation": ("Add an input-side decoder + re-scan pass (decode "
                            "base64/hex/ROT13/url-encoded before applying the "
                            "PromptInjection guard). llm_guard.input_scanners "
                            "supports this natively with the `decode` arg.")}


def rule_phish_hit(s):
    h = (s.get("garak_hits_per_probe") or {}).get("knownbadsignatures.GTPhish", 0)
    if not h:
        return None
    return {"name": f"Garak knownbadsignatures.GTPhish probe hit ({h} time(s))",
            "severity": "HIGH", "cvss": "7.4",
            "cwe": "CWE-1391", "owasp": "LLM05:2025",
            "evidence": (f"Model produced phishing-email content {h} time(s) "
                         "when prompted to do so."),
            "remediation": ("Train a refusal classifier on phishing-generation "
                            "intent or add output filter that detects "
                            "phishing-template patterns (urgent verify, click "
                            "link, suspended account).")}


def rule_cli_unavailable_used_fallback(s):
    if s.get("garak_engine") != "garak-fallback-inprocess":
        return None
    return {"name": "Garak CLI unavailable — in-process fallback used",
            "severity": "INFO",
            "evidence": ("garak CLI could not be driven against the endpoint "
                         "(missing binary, missing REST generator support, or "
                         "config-rejected). VulnusLab fell back to in-process "
                         "probe replay for signal continuity."),
            "remediation": ("Install garak in the scanner image and pre-cache "
                            "its model bundles so the real CLI runs next time. "
                            "Fallback fidelity is lower than the canonical "
                            "Garak harness."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


GARAK_OWASP_TEST_SUITE_FINDING_RULES = [
    rule_unreachable,
    rule_library_missing,
    rule_positive,
    rule_dan_hit,
    rule_base64_hit,
    rule_phish_hit,
    rule_cli_unavailable_used_fallback,
]
