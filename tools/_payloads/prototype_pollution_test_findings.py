"""prototype_pollution_test - findings rules (advisory-by-design).

VulnusLab does NOT send prototype-pollution payloads — that is active
exploitation (it mutates the target's shared runtime state and can crash the
process), which is out of Vulnerability-Assessment scope. This probe is
read-only: it reports the technique as an advisory and notes any
prototype-pollution-prone libraries observed in the page, for manual
verification. Every finding here is INFO — never a graded severity, because
nothing was actively exploited or confirmed.
"""


def rule_probe_failed(s):
    err = s.get("proto_pollution_error")
    if not err:
        return None
    return {
        "name": "Prototype pollution advisory could not complete",
        "severity": "INFO",
        "evidence": str(err)[:300],
        "remediation": ("Confirm httpx is installed in the runtime image and the "
                        "target URL is reachable from the scanner."),
        "cwe": "CWE-1006",
    }


def rule_advisory(s):
    if s.get("proto_pollution_error"):
        return None
    if not s.get("proto_pollution_page_loaded"):
        return None
    libs = s.get("proto_pollution_prone_libs") or []
    if libs:
        lib_note = (f" Prototype-pollution-prone libraries were fingerprinted in the "
                    f"page: {', '.join(libs)}. Their presence is NOT itself a "
                    f"vulnerability — it only marks where to focus manual testing.")
    else:
        lib_note = (" No common prototype-pollution-prone libraries were "
                    "fingerprinted in the page.")
    return {
        "name": "[ADVISORY-BY-DESIGN] Prototype pollution requires manual active testing",
        "severity": "INFO",
        "cwe": "CWE-1321",
        "owasp": "A03:2021",
        "evidence": (
            "Confirming prototype pollution requires SENDING __proto__/constructor "
            "payloads and observing runtime contamination across requests — active "
            "exploitation that mutates the target and can crash the process or affect "
            "other users. VulnusLab is a Vulnerability Assessment platform and does NOT "
            "send those payloads, so this is a read-only advisory (informational, NOT a "
            "confirmed exposure on this target)." + lib_note
        ),
        "remediation": (
            "Manually test for prototype pollution with Burp / ppmap / PPScan under an "
            "authorized engagement. Defensively: upgrade lodash / Hoek / minimist to "
            "patched versions; validate JSON keys and reject __proto__ / constructor / "
            "prototype at every request boundary; add Object.freeze(Object.prototype) at "
            "process startup."
        ),
    }


PROTOTYPE_POLLUTION_TEST_FINDING_RULES = [
    rule_probe_failed,
    rule_advisory,
]
