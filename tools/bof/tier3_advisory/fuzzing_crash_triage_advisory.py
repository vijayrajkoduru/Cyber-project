"""fuzzing_crash_triage_advisory - §1 Fuzzing & Crash Discovery (advisory).

ADVISORY-BY-DESIGN. The §1 techniques - network/file/argument fuzzing
(boofuzz, AFL++, honggfuzz, LibAFL, radamsa), coverage-/grammar-guided
fuzzing, crash deduplication and exploitability triage (exploitable, casr,
gdb) - all require RUNNING the target under a fuzzing harness, reproducing
crashes against a live process, and (for stateful/network fuzzing) repeatedly
hammering a service. That is dynamic execution / DoS-adjacent load, not static
detection against an uploaded file, and is out of scope for a detection-only
SaaS. VulnusLab is VA, not PT.

This scanner emits one honest INFO with the manual fuzzing + triage workflow.
It never fabricates a graded finding.

Customer input: ScanRequest.target = path to a binary (used only to label the
advisory; no fuzzing is executed).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools.bof.tier3_advisory.fuzzing_crash_triage_advisory_findings import (
    FUZZING_CRASH_TRIAGE_ADVISORY_FINDING_RULES,
)

router = APIRouter()

TECHNIQUES = [
    "Network protocol fuzzing (boofuzz)",
    "File-format fuzzing (AFL++, honggfuzz)",
    "Command-line argument fuzzing (radamsa)",
    "Stateful fuzzing (LibAFL)",
    "Coverage-guided fuzzing (AFL++)",
    "Grammar-based fuzzing (Grammarinator)",
    "Crash deduplication (exploitable / casr)",
    "Crash triage / exploitability scoring (casr, gdb)",
    "Auto crash analysis (gdb + corefiles)",
    "Generic crash collector",
]


async def gather(ctx: ScanContext):
    ctx.state["fuzz_techniques"] = TECHNIQUES
    ctx.state["fuzz_advisory"] = True
    ctx.source("advisory-by-design (dynamic fuzzing + live crash reproduction required)")


INTEL_FIELDS = [("§1 Fuzzing & crash-triage techniques (dynamic)", "fuzz_techniques")]


@router.post("/api/bof/fuzzing_crash_triage_advisory")
async def bof_fuzzing_crash_triage_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target,
        tool="fuzzing_crash_triage_advisory",
        gather_func=gather,
        finding_rules=FUZZING_CRASH_TRIAGE_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
