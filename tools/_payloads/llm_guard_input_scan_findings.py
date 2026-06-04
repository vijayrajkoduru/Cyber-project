"""llm_guard_input_scan - findings rules (defensive baseline benchmark)."""


def rule_library_missing(s):
    if not s.get("llm_guard_error"):
        return None
    return {"name": "llm_guard library not available — defensive baseline skipped",
            "severity": "INFO",
            "evidence": (str(s.get("llm_guard_error", "")) + " " +
                         str(s.get("llm_guard_install_hint", ""))).strip(),
            "remediation": ("Install with `pip install llm-guard` in the backend "
                            "image. llm_guard is the OWASP-recommended open-source "
                            "input/output guardrail framework (Protect AI). "
                            "Without it the LLM endpoint runs without a defense-in-depth "
                            "input filter."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


def rule_baseline_summary(s):
    n = s.get("llm_guard_scanners_run")
    if not n:
        return None
    return {"name": f"llm_guard defensive baseline computed ({n} scanners)",
            "severity": "INFO",
            "evidence": (f"Benchmarked {n} input scanners against "
                         f"{(s.get('llm_guard_per_scanner') or {}).get(list((s.get('llm_guard_per_scanner') or {}).keys())[0], {}).get('benign_inputs', 8)} benign + "
                         f"{(s.get('llm_guard_per_scanner') or {}).get(list((s.get('llm_guard_per_scanner') or {}).keys())[0], {}).get('malicious_inputs', 8)} malicious test inputs. "
                         f"Macro P={s.get('llm_guard_macro_precision', 0)} "
                         f"R={s.get('llm_guard_macro_recall', 0)} "
                         f"F1={s.get('llm_guard_macro_f1', 0)}"),
            "remediation": ("Use these scores as the floor your in-production "
                            "guardrails must beat. Pin the scanner versions in "
                            "requirements.txt + re-benchmark each release."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


def rule_high_false_positive_scanner(s):
    per = s.get("llm_guard_per_scanner") or {}
    bad = []
    for name, m in per.items():
        if not isinstance(m, dict): continue
        if m.get("fp", 0) >= 3:
            bad.append((name, m["fp"], m.get("benign_inputs", 0)))
    if not bad:
        return None
    return {"name": f"High false-positive rate in {len(bad)} llm_guard scanner(s)",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-693", "owasp": "LLM01:2025",
            "evidence": (", ".join(f"{n}: {fp}/{b} benign blocked"
                                    for n, fp, b in bad)),
            "remediation": ("Tune scanner thresholds (most llm_guard scanners "
                            "accept a `threshold` kwarg). High FP rate degrades "
                            "UX and trains users to bypass guards.")}


def rule_low_recall_scanner(s):
    per = s.get("llm_guard_per_scanner") or {}
    bad = []
    for name, m in per.items():
        if not isinstance(m, dict): continue
        rec = m.get("recall", 1.0)
        if rec < 0.3 and m.get("malicious_inputs", 0):
            bad.append((name, rec))
    if not bad:
        return None
    return {"name": f"Low malicious-input recall in {len(bad)} llm_guard scanner(s)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-693", "owasp": "LLM01:2025",
            "evidence": ", ".join(f"{n}: recall={r}" for n, r in bad),
            "remediation": ("Pair weak scanners with a complementary guard "
                            "(e.g. supplement llm_guard's regex Secrets with "
                            "trufflehog; supplement Toxicity with Detoxify). "
                            "Update llm_guard to the latest version — newer "
                            "models score significantly higher.")}


def rule_strong_baseline(s):
    f1 = s.get("llm_guard_macro_f1", 0.0)
    if f1 < 0.7:
        return None
    return {"name": f"llm_guard input baseline strong (macro-F1 {f1})",
            "severity": "POSITIVE",
            "evidence": f"Macro-F1 {f1} across {s.get('llm_guard_scanners_run', 0)} input scanners.",
            "remediation": ("Promote llm_guard from baseline to gating — drop "
                            "any input scored 'blocked' before reaching the LLM."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


LLM_GUARD_INPUT_SCAN_FINDING_RULES = [
    rule_library_missing,
    rule_baseline_summary,
    rule_high_false_positive_scanner,
    rule_low_recall_scanner,
    rule_strong_baseline,
]
