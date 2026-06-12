"""ai_redteam_advisory - honest advisory-by-design coverage for the AI/LLM
playbook techniques that cannot be detected from an external SaaS scanner
(module_playbooks/23_ai_llm.md).

This scanner performs NO network I/O. It emits one INFO finding per group of
techniques that genuinely require capabilities outside a black-box remote
scan: model-weight / training-data access, host or cloud credentials, white-
box gradient access, multi-turn human red-teaming, or a post-compromise
foothold. Every finding is INFO with an [ADVISORY-BY-DESIGN] marker and
vulnerable:false, so the report never shows a fabricated graded severity for
a technique we did not actually verify.

The active, externally-detectable techniques (prompt injection, jailbreak,
PII leak, serving/vector-DB/gateway/observability exposure, inference auth,
output-handling headers) are covered by the live-probe scanners in
tier1_owasp_llm / tier2_defenses / tier3_infra.

Customer input:
  - ScanRequest.target = informational label only (no requests are sent)
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


_ADV_PREFIX = "[ADVISORY-BY-DESIGN] "

# Each entry => one INFO finding. (key, title, playbook_refs, reason, cwe, owasp)
ADVISORY_TECHNIQUES = [
    ("model_theft",
     "Model theft / extraction (black-box clone, distillation, watermark, "
     "hyperparameter leak)",
     "§5 #55-#62",
     "Cloning or distilling a model requires issuing very high request volumes "
     "(extraction) and offline training — an active, cost-incurring attack that "
     "VulnusLab (VA, not PT) does not perform. Architecture/timing side-channels "
     "and watermark recovery need white-box or research-grade measurement.",
     "CWE-1300", "LLM10:2025"),
    ("data_extraction_research",
     "Membership inference, model inversion, training-data reconstruction",
     "§4 #48-#49",
     "These attacks require many shadow-model queries and statistical inference "
     "or gradient access — research-grade, active, and out of scope for a "
     "black-box reachability scan. The reachable verbatim-leak / PII surface IS "
     "tested live by tier1 pii_leak_test.",
     "CWE-200", "LLM02:2025"),
    ("supply_chain_artifacts",
     "Model provenance, pickle-RCE in checkpoints, safetensors migration, "
     "weight-tamper, LoRA/adapter + dataset-poisoning audit",
     "§8 #85-#94",
     "Inspecting model artifacts (Hugging Face repos, .pt/.bin pickles, "
     "safetensors, LoRA adapters) requires read access to the model registry / "
     "filesystem and is a supply-chain audit, not a remote endpoint probe. Use "
     "sigstore/trivy/picklescan + model-card review on the actual artifacts.",
     "CWE-502", "LLM03:2025"),
    ("agent_toolchain",
     "Agent / tool-use abuse, confused-deputy, MCP server abuse, agent memory "
     "poisoning, OAuth-in-agent, multi-agent collusion",
     "§7 #73-#84",
     "Exercising agent tool-calls / excessive agency requires an authenticated "
     "agent session with real tool bindings and side-effecting actions — testing "
     "it would mean performing the abusive actions (PT), which VulnusLab does "
     "not do. Review tool allowlists, scopes, and human-in-the-loop gates "
     "manually.",
     "CWE-285", "LLM06:2025"),
    ("rag_corpus_internal",
     "RAG document/embedding poisoning, retrieval bypass, cross-tenant RAG leak, "
     "embedding-space adversarial confusion",
     "§6 #63-#72",
     "Poisoning or auditing the RAG corpus requires write/read access to the "
     "vector store's documents and the ability to insert malicious content — an "
     "active, data-mutating operation. The reachable surface (unauthenticated "
     "vector-DB control plane) IS tested live by tier3 vector_db_exposure.",
     "CWE-94", "LLM08:2025"),
    ("infra_host_local",
     "GPU side-channel (rowhammer/glitching), inference-cache cross-tenant leak, "
     "context-window/truncation abuse, token-DoS / unbounded consumption",
     "§9 #98-#102, #106 + §1 #10",
     "Hardware side-channels need physical/host adjacency; cache cross-tenant "
     "leaks need a co-tenant foothold; token-DoS is a flooding attack VulnusLab "
     "will not perform. Inference-endpoint AUTH and exposure (the safe, "
     "reachable parts) ARE tested live by tier3 inference_endpoint_auth_audit + "
     "model_serving_fingerprint.",
     "CWE-400", "LLM10:2025"),
    ("multimodal_whitebox",
     "Image/audio/steganographic prompt injection, adversarial suffix (GCG), "
     "multi-modal jailbreak",
     "§2 #21-#22 + §3 #40, #42",
     "GCG adversarial-suffix generation needs white-box gradient access; "
     "multi-modal injection needs the customer's image/audio ingestion pipeline "
     "and crafted media. Text-channel injection + jailbreak ARE tested live by "
     "tier1 prompt_injection_audit + jailbreak_resistance_test.",
     "CWE-1039", "LLM01:2025"),
    ("compliance_governance",
     "NIST AI RMF / EU AI Act / MITRE ATLAS mapping, bias & fairness eval, "
     "hallucination/accuracy benchmark, ethical-impact review, board brief",
     "§10 #107-#114 + §1 #13-#14",
     "Compliance mapping and fairness/hallucination benchmarking are governance "
     "and evaluation exercises requiring the customer's intended-use context, "
     "labeled datasets, and human review — not a remote vulnerability probe.",
     "CWE-1395", "LLM09:2025"),
    ("manual_redteam",
     "Manual creative prompt design, adaptive/iterative red-team loops, "
     "human-driven jailbreak chains",
     "§2 #29-#30 + §3 #41",
     "Iterative human red-teaming is by definition analyst-driven and "
     "multi-turn; it is delivered as a manual engagement, not an automated "
     "single-shot scan.",
     "CWE-1395", "LLM01:2025"),
]


async def gather(ctx: ScanContext):
    # No network I/O — purely informational advisory coverage.
    ctx.state["advisory_target"] = (ctx.host or "").strip() or "(no target)"
    ctx.state["advisory_count"] = len(ADVISORY_TECHNIQUES)
    ctx.state["advisory_groups"] = [t[0] for t in ADVISORY_TECHNIQUES]
    ctx.source(f"{len(ADVISORY_TECHNIQUES)} advisory-by-design technique groups "
               "documented (no live scan performed — these cannot be SaaS-probed)")


def _make_advisory_rule(key, title, refs, reason, cwe, owasp):
    def _rule(s):
        return {
            "name": _ADV_PREFIX + title,
            "severity": "INFO",
            "cvss": "0.0",
            "cwe": cwe,
            "owasp": owasp,
            "evidence": (f"Playbook {refs}. This technique cannot be detected "
                         "from an external black-box scan and is intentionally "
                         "advisory (NOT a forge gap). " + reason),
            "remediation": ("Covered via manual / red-team engagement or "
                            "artifact/host-side audit — see "
                            "module_playbooks/23_ai_llm.md " + refs + ". "
                            "VulnusLab performs vulnerability assessment (VA), "
                            "not active exploitation (PT)."),
        }
    _rule.__name__ = f"rule_advisory_{key}"
    return _rule


AI_REDTEAM_ADVISORY_FINDING_RULES = [
    _make_advisory_rule(*t) for t in ADVISORY_TECHNIQUES
]


INTEL_FIELDS = [
    ("Target", "advisory_target"),
    ("Advisory technique groups", "advisory_count"),
    ("Groups", "advisory_groups"),
]


@router.post("/api/ai_llm/ai_redteam_advisory")
async def ai_llm_ai_redteam_advisory(req: ScanRequest,
                                     _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="ai_redteam_advisory",
        gather_func=gather,
        finding_rules=AI_REDTEAM_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
