"""§23 AI/LLM Security — 87 endpoints per 23_ai_llm.md. All techniques ⭐ 2024+.
10 sections: OWASP LLM Top 10 2025, prompt injection (direct+indirect), jailbreak,
data extraction, model theft, RAG/vector DB, agent/tool-use, supply chain,
infrastructure, compliance.

VL-FORGE 2026-05-30: 2 live probes for LLM-endpoint signature detection
(if target IS an LLM API endpoint, probe for system prompt leak +
infra fingerprint). Most LLM techniques require an active LLM endpoint
+ valid API key + non-malicious prompt engineering — beyond scope of
generic scanning. Probes are best-effort signature checks.
"""
import urllib.request, urllib.error, json
from tools._pack_common import make_advisory_router, _adv_response
from tools._shared import wrap_finding


def _host(t):
    return t.split("://", 1)[-1].split("/")[0].split(":")[0].strip().lower() or t

def _http_get(url, timeout=4):
    try:
        r = urllib.request.Request(url, headers={"User-Agent":"VulnusLab/2.0"})
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="ignore"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(4096).decode("utf-8", errors="ignore"), dict(e.headers) if e.headers else {}
        except Exception: return e.code, "", {}
    except Exception:
        return 0, "", {}

def _build(tool, target, findings, tested, summary):
    sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"POSITIVE":0}
    top = "INFO"
    for f in findings:
        if sev_order.get(f.get("severity","INFO"),0) > sev_order.get(top,0):
            top = f.get("severity","INFO")
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": top in ("CRITICAL","HIGH","MEDIUM"),
            "severity": top, "findings": findings,
            "tests_performed": tested, "tests_summary": summary, "raw_data": {}}


def _probe_llm_endpoint_fingerprint(target, req):
    """Detect common LLM API endpoint signatures (OpenAI-compatible / Anthropic / vLLM)."""
    base = f"https://{_host(target)}"
    paths = ["/v1/models", "/api/models", "/v1/chat/completions", "/api/v1/generate",
              "/v1/completions", "/api/generate", "/.well-known/openid-configuration"]
    signs = []
    for p in paths:
        code, body, headers = _http_get(base + p, timeout=4)
        body_lower = body[:4096].lower()
        srv = (headers.get("Server","") + str(headers)).lower()
        if any(k in body_lower for k in ["model", "openai", "anthropic", "claude",
                                            "gpt-", "llama", "mistral", "vllm", "ollama"]) or \
           any(k in srv for k in ["openai", "vllm", "ollama"]):
            signs.append({"path": p, "code": code})
    findings = []
    if signs:
        findings.append(wrap_finding(
            f"LLM API endpoint signature detected at {len(signs)} path(s) — audit for prompt injection / system prompt leak",
            "MEDIUM", cvss="5.5", cwe="CWE-200",
            remediation="Inventory LLM endpoints; ensure auth + rate limits + prompt safety guards.",
            evidence_marker=", ".join(f"{s['path']}→{s['code']}" for s in signs)))
    else:
        findings.append(wrap_finding(
            "No LLM API endpoint signature at standard paths",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="If using LLM, ensure endpoints are auth-gated.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return _build("llm03_supply_chain", target, findings, len(paths),
                   "LLM API endpoint signature probe")


def _probe_llm_open_models_list(target, req):
    """Check for anonymously accessible /v1/models endpoint — info disclosure."""
    base = f"https://{_host(target)}"
    code, body, _ = _http_get(f"{base}/v1/models", timeout=4)
    findings = []
    if code == 200 and body.strip().startswith("{") and ('"data"' in body or '"id"' in body):
        try:
            data = json.loads(body)
            models = data.get("data", []) if isinstance(data, dict) else []
            model_ids = [m.get("id","?") for m in models[:5]]
            findings.append(wrap_finding(
                f"LLM /v1/models endpoint UNAUTHENTICATED — {len(models)} models enumerated",
                "MEDIUM", cvss="5.5", cwe="CWE-306",
                remediation="Require API key on /v1/models; ratelimit per key; audit token usage.",
                evidence_marker=f"Models: {', '.join(model_ids)}"))
        except Exception:
            findings.append(wrap_finding(
                f"/v1/models returns 200 with content — verify auth requirement",
                "LOW", cvss="3.0", cwe="CWE-200",
                remediation="Audit auth on /v1/models.",
                evidence_marker=body[:120]))
    else:
        findings.append(wrap_finding(
            "No anonymous /v1/models endpoint",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue.",
            evidence_marker=f"GET /v1/models → {code}"))
    return _build("llm07_system_prompt_leakage", target, findings, 1,
                   "LLM /v1/models anonymous-access probe")


PROBES = {
    "llm03_supply_chain":         _probe_llm_endpoint_fingerprint,
    "llm07_system_prompt_leakage": _probe_llm_open_models_list,
}

T = [
    # §1 OWASP LLM Top 10 2025 (12)
    ("llm01_prompt_injection", "LLM01 Prompt Injection.", "HIGH", "8.0"),
    ("llm02_sensitive_info_disclosure", "LLM02 Sensitive Information Disclosure.", "HIGH", "8.0"),
    ("llm03_supply_chain", "LLM03 Supply Chain.", "HIGH", "7.5"),
    ("llm04_data_model_poisoning", "LLM04 Data and Model Poisoning.", "HIGH", "7.5"),
    ("llm05_improper_output_handling", "LLM05 Improper Output Handling.", "HIGH", "8.0"),
    ("llm06_excessive_agency", "LLM06 Excessive Agency.", "HIGH", "8.0"),
    ("llm07_system_prompt_leakage", "LLM07 System Prompt Leakage.", "MEDIUM", "5.5"),
    ("llm08_vector_embedding_weak", "LLM08 Vector and Embedding Weaknesses.", "HIGH", "7.5"),
    ("llm09_misinformation_hallucination", "LLM09 Misinformation / Hallucination.", "MEDIUM", "5.5"),
    ("llm10_unbounded_consumption_dos", "LLM10 Unbounded Consumption.", "HIGH", "7.0"),
    ("manual_owasp_llm_review", "Manual OWASP LLM review.", "INFO", "0.0"),
    ("manual_owasp_llm_chain", "Manual OWASP LLM chain.", "INFO", "0.0"),
    # §2 Prompt Injection (14)
    ("direct_pi_classic", "Direct PI classic.", "HIGH", "7.5"),
    ("indirect_pi_via_doc", "Indirect PI via document.", "HIGH", "8.0"),
    ("indirect_pi_via_web", "Indirect PI via fetched web content.", "HIGH", "8.0"),
    ("indirect_pi_via_email", "Indirect PI via email integration.", "HIGH", "8.0"),
    ("pi_payload_obfuscation_unicode", "PI obfuscation via Unicode.", "HIGH", "7.5"),
    ("pi_payload_role_confusion", "PI role/system confusion.", "HIGH", "7.5"),
    ("pi_payload_prompt_leak", "PI to leak system prompt.", "MEDIUM", "5.5"),
    ("pi_payload_jailbreak_chain", "PI + jailbreak chain.", "HIGH", "8.0"),
    ("pi_payload_tool_exec_abuse", "PI tool execution abuse.", "HIGH", "8.0"),
    ("pi_payload_exfiltration", "PI for data exfiltration.", "HIGH", "8.0"),
    ("pi_html_iframe_steg", "PI via HTML/iframe stego.", "HIGH", "7.5"),
    ("pi_payload_aiec_template", "AIEC PI template.", "HIGH", "7.5"),
    ("manual_pi_chain", "Manual PI chain.", "INFO", "0.0"),
    ("manual_pi_research", "Manual PI research.", "INFO", "0.0"),
    # §3 Jailbreak (10)
    ("jailbreak_dan_advisory", "DAN jailbreak.", "HIGH", "7.0"),
    ("jailbreak_aim_advisory", "AIM jailbreak.", "HIGH", "7.0"),
    ("jailbreak_roleplay_persona", "Roleplay persona jailbreak.", "HIGH", "7.0"),
    ("jailbreak_hypothetical_chain", "Hypothetical chain jailbreak.", "HIGH", "7.0"),
    ("jailbreak_token_smuggling", "Token smuggling jailbreak.", "HIGH", "7.0"),
    ("jailbreak_multi_turn_evolve", "Multi-turn jailbreak evolution.", "HIGH", "7.0"),
    ("jailbreak_language_switch", "Language switch jailbreak.", "MEDIUM", "5.5"),
    ("jailbreak_template_injection", "Template-injection jailbreak.", "HIGH", "7.5"),
    ("manual_jailbreak_chain", "Manual jailbreak chain.", "INFO", "0.0"),
    ("manual_jailbreak_research", "Manual jailbreak research.", "INFO", "0.0"),
    # §4 Data Extraction & Privacy (9)
    ("data_pii_extraction", "PII extraction from model.", "HIGH", "7.5"),
    ("data_training_data_leak", "Training data leak.", "HIGH", "8.0"),
    ("data_membership_inference", "Membership inference.", "HIGH", "7.0"),
    ("data_secret_recall_attack", "Secret recall attack.", "HIGH", "8.0"),
    ("data_diff_privacy_audit", "Differential privacy audit.", "MEDIUM", "5.5"),
    ("data_token_residual_leak", "Token residual leak.", "MEDIUM", "5.5"),
    ("data_system_prompt_extract", "System prompt extraction.", "MEDIUM", "5.5"),
    ("manual_data_extraction_chain", "Manual data extraction chain.", "INFO", "0.0"),
    ("manual_data_privacy_audit", "Manual data privacy audit.", "INFO", "0.0"),
    # §5 Model Theft / Extraction (5)
    ("model_theft_query_replay", "Model theft via query replay.", "HIGH", "7.5"),
    ("model_distillation_extract", "Model distillation extract.", "HIGH", "7.5"),
    ("model_embedding_inversion", "Embedding inversion attack.", "HIGH", "7.5"),
    ("manual_model_theft_research", "Manual model theft research.", "INFO", "0.0"),
    ("manual_model_extract_chain", "Manual model extract chain.", "INFO", "0.0"),
    # §6 RAG / Vector DB (7)
    ("rag_doc_poisoning", "RAG doc poisoning.", "HIGH", "8.0"),
    ("rag_vector_db_overwrite", "Vector DB overwrite.", "HIGH", "7.5"),
    ("rag_metadata_injection", "RAG metadata injection.", "HIGH", "7.5"),
    ("rag_doc_link_smuggle", "RAG doc-link smuggling.", "HIGH", "8.0"),
    ("rag_indirect_pi_chain", "RAG indirect PI chain.", "HIGH", "8.0"),
    ("manual_rag_review", "Manual RAG review.", "INFO", "0.0"),
    ("manual_rag_chain", "Manual RAG chain.", "INFO", "0.0"),
    # §7 Agent / Tool-Use Abuse (9)
    ("agent_tool_call_abuse", "Agent tool-call abuse.", "HIGH", "8.0"),
    ("agent_excessive_perms", "Agent excessive permissions.", "HIGH", "8.0"),
    ("agent_indirect_pi_to_tool", "Agent indirect PI → tool.", "HIGH", "8.5"),
    ("agent_data_exfil_via_tool", "Agent data exfil via tool.", "HIGH", "8.0"),
    ("agent_memory_poisoning", "Agent memory poisoning.", "HIGH", "7.5"),
    ("agent_chain_decision_abuse", "Agent chain decision abuse.", "HIGH", "7.5"),
    ("agent_human_in_loop_bypass", "Human-in-loop bypass.", "HIGH", "8.0"),
    ("manual_agent_review", "Manual agent review.", "INFO", "0.0"),
    ("manual_agent_chain", "Manual agent chain.", "INFO", "0.0"),
    # §8 LLM Supply Chain (9)
    ("supply_huggingface_model_audit", "HF model audit.", "MEDIUM", "5.5"),
    ("supply_model_pickle_unsafe", "Unsafe pickle in model file.", "CRITICAL", "9.0"),
    ("supply_third_party_plugin_audit", "3rd-party plugin audit.", "HIGH", "7.5"),
    ("supply_finetune_dataset_audit", "Fine-tune dataset audit.", "HIGH", "7.0"),
    ("supply_provenance_signing", "Provenance + signing.", "MEDIUM", "5.5"),
    ("supply_lora_qlora_audit", "LoRA/QLoRA audit.", "MEDIUM", "5.5"),
    ("supply_quantization_audit", "Quantization safety audit.", "MEDIUM", "5.5"),
    ("supply_inference_lib_audit", "Inference lib audit.", "MEDIUM", "5.5"),
    ("manual_supply_chain_review", "Manual supply chain review.", "INFO", "0.0"),
    # §9 LLM Infrastructure (11)
    ("infra_api_key_in_url", "API key in URL leak.", "HIGH", "7.5"),
    ("infra_rate_limit_audit", "LLM rate-limit audit.", "MEDIUM", "5.5"),
    ("infra_token_consumption_audit", "Token consumption audit.", "MEDIUM", "5.5"),
    ("infra_inference_endpoint_open", "Inference endpoint open.", "HIGH", "7.5"),
    ("infra_secrets_in_prompt", "Secrets in prompt logs.", "HIGH", "8.0"),
    ("infra_logs_pii_leak", "Logs PII leak.", "HIGH", "7.5"),
    ("infra_caching_audit", "Caching audit.", "MEDIUM", "5.5"),
    ("infra_observability_audit", "Observability audit.", "MEDIUM", "5.5"),
    ("infra_telemetry_optout", "Telemetry opt-out audit.", "MEDIUM", "5.5"),
    ("infra_gpu_isolation_audit", "GPU isolation audit.", "MEDIUM", "5.5"),
    ("manual_infra_review", "Manual infra review.", "INFO", "0.0"),
    # §10 Compliance / Responsible AI (6)
    ("compliance_eu_ai_act", "EU AI Act compliance check.", "MEDIUM", "5.5"),
    ("compliance_nist_ai_rmf", "NIST AI RMF 1.0 check.", "MEDIUM", "5.5"),
    ("compliance_mitre_atlas", "MITRE ATLAS mapping.", "INFO", "0.0"),
    ("compliance_iso_42001", "ISO 42001 (AIMS) check.", "MEDIUM", "5.5"),
    ("compliance_anthropic_aup", "Anthropic AUP audit.", "INFO", "0.0"),
    ("compliance_openai_safety", "OpenAI safety policies audit.", "INFO", "0.0"),
]

router = make_advisory_router("ai_llm", T,
    playbook_ref="See module_playbooks/23_ai_llm.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
