"""fuzzing_crash_triage_advisory - findings rules.

ADVISORY-BY-DESIGN: a single INFO finding. §1 fuzzing + crash triage requires
running the target under a harness and reproducing crashes against a live
process (dynamic / DoS-adjacent), which a detection-only SaaS does not do.
Never graded.
"""


def rule_advisory(s):
    if not s.get("fuzz_advisory"):
        return None
    techniques = s.get("fuzz_techniques") or []
    return {
        "name": "[ADVISORY-BY-DESIGN] Fuzzing & crash-discovery / triage",
        "severity": "INFO",
        "evidence": (
            f"{len(techniques)} §1 techniques (boofuzz / AFL++ / honggfuzz / LibAFL "
            "coverage-guided fuzzing, plus exploitable / casr crash dedup + triage) "
            "require running the target under a harness and reproducing crashes "
            "against a live process. That is dynamic execution / load generation, not "
            "static detection against an uploaded file, and is out of scope for a "
            "detection-only SaaS."
        ),
        "remediation": (
            "Endpoint is advisory-by-design, NOT a forge gap. Manual workflow: "
            "(1) build a harness - for a parser, link the entry point against AFL++ / "
            "libFuzzer with ASan+UBSan; for a network service use boofuzz with a "
            "protocol grammar. (2) Run coverage-guided fuzzing (afl-fuzz / honggfuzz) "
            "until crashes appear, persisting corefiles. (3) Deduplicate with casr "
            "(casr-cluster) and score exploitability with `exploitable` / casr-gdb. "
            "(4) Triage the top unique crashes by hand in gdb (pwndbg). "
            "Defensively: compile fuzz targets with ASan in CI, gate merges on a "
            "minimum coverage corpus, and fix every reproducible crash. See playbook §1."
        ),
        "cwe": "CWE-1287",
        "owasp": "A06:2021",
    }


FUZZING_CRASH_TRIAGE_ADVISORY_FINDING_RULES = [rule_advisory]
