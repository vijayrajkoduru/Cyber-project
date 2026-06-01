# AI / LLM Security Testing — Master Reference (`ai_llm_ruff`)

**100% Full Industry Standard catalogue** — aligned with OWASP LLM Top 10 (2025) + NIST AI RMF 1.0 + MITRE ATLAS + Microsoft AI Red Team methodology + Anthropic / OpenAI / Google Responsible AI guidelines + 2024–2026 industry additions.

10 sections, 130 techniques.

**Legend:** auto · (probe) · manual · all entries NEW (2024+) — entire module is 2024+

---

## Summary

| § | Section | Techniques | Auto | Probe | Manual |
|---|---|---|---|---|---|
| 1 | OWASP LLM Top 10 (2025) | 14 | 11 | 1 | 2 |
| 2 | Prompt Injection (direct + indirect) | 16 | 13 | 1 | 2 |
| 3 | Jailbreak Techniques | 12 | 10 | 0 | 2 |
| 4 | Data Extraction & Privacy | 12 | 8 | 1 | 3 |
| 5 | Model Theft / Extraction | 8 | 4 | 1 | 3 |
| 6 | RAG / Vector DB Attacks | 10 | 7 | 0 | 3 |
| 7 | Agent / Tool-Use Abuse | 12 | 8 | 1 | 3 |
| 8 | LLM Supply Chain | 10 | 9 | 0 | 1 |
| 9 | LLM Infrastructure & Deployment | 12 | 11 | 0 | 1 |
| 10 | Compliance / Responsible AI | 8 | 6 | 0 | 2 |
| **TOTAL** | | **114** | **87** | **4** | **23** |

---

## §1 — OWASP LLM Top 10 (2025)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | LLM01: Prompt Injection (direct + indirect) | Garak, PyRIT, custom | |
| 2 | LLM02: Sensitive Information Disclosure | Garak data-leak probes | |
| 3 | LLM03: Supply Chain (model provenance, dataset poisoning) | model-card audit | |
| 4 | LLM04: Data and Model Poisoning | manual + provenance | |
| 5 | LLM05: Improper Output Handling (XSS via LLM) | Burp + custom | |
| 6 | LLM06: Excessive Agency (tool-call abuse) | PyRIT + manual | (probe) |
| 7 | LLM07: System Prompt Leakage | Garak system-leak | |
| 8 | LLM08: Vector / Embedding Weakness (RAG poisoning) | custom + manual | |
| 9 | LLM09: Misinformation / Hallucination | custom eval | |
| 10 | LLM10: Unbounded Consumption (token DoS) | locust + token cost | |
| 11 | Mapped to OWASP LLM Top 10 — automated test suite | promptfoo, Garak | |
| 12 | OWASP LLM Top 10 — coverage report | custom + Garak | |
| 13 | NIST AI RMF mapping | custom + manual | |
| 14 | MITRE ATLAS technique mapping | manual + custom | |

---

## §2 — Prompt Injection (direct + indirect)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 15 | Direct user prompt injection (role override) | Garak, PyRIT | |
| 16 | Indirect prompt injection (web page content) | custom + Garak | |
| 17 | Indirect prompt injection (uploaded document) | custom | |
| 18 | Indirect prompt injection (email body to LLM agent) | custom | |
| 19 | Multi-step prompt injection (delayed payload) | custom + manual | |
| 20 | Hidden text injection (white-on-white, zero-width) | custom | |
| 21 | Image-based prompt injection (steganographic) | custom + LLaVA | |
| 22 | Audio prompt injection (voice transcripts) | custom + Whisper | |
| 23 | Prompt injection via cell content (Excel/Sheets) | custom | |
| 24 | RAG document poisoning | custom + vector DB | |
| 25 | Cross-tenant prompt injection (shared model) | manual | (probe) |
| 26 | Prompt-injection-as-a-service (chained AaaS) | custom | |
| 27 | XPIA (cross-prompt injection attack) | custom + research | |
| 28 | LLM-to-LLM injection (agent chains) | PyRIT + custom | |
| 29 | Manual creative prompt design | analyst | |
| 30 | Adaptive / iterative injection (red-team loop) | PyRIT + manual | |

---

## §3 — Jailbreak Techniques

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 31 | DAN (Do Anything Now) family | jailbreakbench, custom | |
| 32 | AIM (Always Intelligent Machine) | jailbreakbench | |
| 33 | Roleplay jailbreak (grandma, story) | jailbreakbench | |
| 34 | Encoding bypass (Base64, ROT13, Pig Latin) | custom | |
| 35 | Many-shot jailbreak | custom | |
| 36 | Crescendo (multi-turn) | PyRIT crescendo | |
| 37 | Skeleton Key (Microsoft research) | custom | |
| 38 | Token smuggling (Unicode confusable) | custom | |
| 39 | Prompt obfuscation (typos, leet) | custom | |
| 40 | Adversarial suffix (GCG attack) | nanoGCG | |
| 41 | Manual creative jailbreak chains | analyst | |
| 42 | Multi-modal jailbreak (image + text) | manual + research | |

---

## §4 — Data Extraction & Privacy

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 43 | Training data extraction (verbatim leak) | custom + Garak | |
| 44 | PII extraction (names, emails, SSN) | Garak PII probes | |
| 45 | Credential leak (API keys, secrets in training) | custom + regex | |
| 46 | System prompt extraction | Garak system-leak | |
| 47 | Conversation history leak (cross-session) | custom | |
| 48 | Membership inference (was X in training data?) | manual + research | |
| 49 | Model inversion (reconstruct training samples) | manual + research | |
| 50 | RAG source-document extraction | custom + queries | |
| 51 | Vector embedding extraction | custom | |
| 52 | Tool-call argument leak (logs / telemetry) | custom | |
| 53 | GDPR right-to-explanation audit | manual | |
| 54 | LLM forgets / unlearning verification | custom + research | (probe) |

---

## §5 — Model Theft / Extraction

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 55 | Black-box model querying (clone via API) | custom + research | |
| 56 | Behavior cloning (distillation attack) | custom + research | |
| 57 | Knowledge distillation theft | manual + research | |
| 58 | API rate-limit + cost analysis (extraction cost) | custom | |
| 59 | Model fingerprinting (response signatures) | custom | |
| 60 | Architecture leakage via timing | custom + research | (probe) |
| 61 | Watermark detection | custom + research | |
| 62 | Hyperparameter leak | custom + manual | |

---

## §6 — RAG / Vector DB Attacks

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 63 | RAG document poisoning (insert malicious doc) | custom + Pinecone/Chroma | |
| 64 | Vector embedding poisoning | custom + research | |
| 65 | Retrieval bypass (force LLM to ignore RAG) | custom prompt | |
| 66 | RAG source-citation injection | custom | |
| 67 | Cross-tenant RAG leak | custom + manual | (probe) |
| 68 | Vector DB enumeration (unauth API) | custom + nuclei | |
| 69 | Embedding-space confusion (adversarial embed) | custom | |
| 70 | RAG-injection-via-document-upload | custom + Burp | |
| 71 | Manual RAG corpus audit | analyst | |
| 72 | Manual vector-store backup exfil | analyst | |

---

## §7 — Agent / Tool-Use Abuse

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 73 | Excessive agency (LLM agent over-perm) | PyRIT + manual | (probe) |
| 74 | Tool call injection (steer wrong tool) | custom + PyRIT | |
| 75 | Confused deputy (agent runs as user) | manual + custom | |
| 76 | Tool input sanitization bypass (RCE via tool args) | custom + Burp | |
| 77 | Function-calling JSON tamper | custom | |
| 78 | Agent loop abuse (infinite recursion) | custom + load | |
| 79 | Multi-agent collusion exploit | manual + custom | |
| 80 | MCP (Model Context Protocol) server abuse | custom + manual | |
| 81 | Agent memory poisoning (long-term store) | custom + RAG | |
| 82 | OAuth flow inside agent abuse | custom + Burp | |
| 83 | Manual agent business-logic chain | analyst | |
| 84 | Manual agent privilege escalation | analyst | |

---

## §8 — LLM Supply Chain

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 85 | Model provenance verification (Hugging Face) | sigstore + custom | |
| 86 | Model card audit (training data sources) | custom + manual | |
| 87 | Pickle deserialization RCE (PyTorch checkpoints) | trivy + custom | |
| 88 | Safetensors vs pickle migration audit | custom | |
| 89 | Dataset poisoning detection | manual + research | |
| 90 | Model weight tamper detection | hash + sigstore | |
| 91 | LoRA / adapter supply-chain risk | custom + audit | |
| 92 | Model registry CVE (Hugging Face, OctoML) | nuclei + NVD | |
| 93 | Backdoored model detection | custom + research | |
| 94 | Manual training pipeline integrity | analyst | |

---

## §9 — LLM Infrastructure & Deployment

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 95 | LLM API key / credential leak | trufflehog + custom | |
| 96 | Inference endpoint authentication audit | custom + Burp | |
| 97 | Streaming response abuse (chunked timing) | custom | |
| 98 | Context window overflow / truncation abuse | custom | |
| 99 | Rate-limit / cost / token-DoS | locust + custom | |
| 100 | Inference cache cross-tenant leak | manual + custom | |
| 101 | Model serving platform CVE (vLLM, TGI, Triton) | nuclei + NVD | |
| 102 | GPU side-channel (rowhammer, glitching) | manual + research | |
| 103 | LLM gateway audit (LiteLLM, Portkey) | custom + Burp | |
| 104 | Multi-model routing abuse | custom | |
| 105 | LLM observability platform info leak (Langfuse, Helicone) | custom + Burp | |
| 106 | Embedding API cost abuse | custom + load | |

---

## §10 — Compliance / Responsible AI

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 107 | NIST AI RMF mapping | custom + manual | |
| 108 | EU AI Act compliance (high-risk system audit) | custom | |
| 109 | Model bias / fairness eval | fairlearn, AIF360 | |
| 110 | Hallucination / accuracy benchmark | promptfoo, custom | |
| 111 | Toxicity / harmful content eval | Garak, Detoxify | |
| 112 | Watermark + provenance compliance | custom | |
| 113 | Manual ethical-impact review | analyst | |
| 114 | Red-team report → board-ready brief | analyst | |

---

## Compliance Mapping
- **OWASP LLM Top 10 (2025)** · **NIST AI RMF 1.0** · **MITRE ATLAS** · **EU AI Act (Aug 2024+)** · **ISO/IEC 42001:2023 (AI MSS)** · **NIST SP 800-218A (Secure Software Development for AI)** · **GDPR Art. 22 (automated decision-making)** · **DPDP Act 2023**

## VulnusLab AI/LLM Status
- Status: MISSING (per modules_2026_inventory.md #23)
- Priority: **P0 — #1 enterprise RFP item 2025–2026**

## Roadmap to 100%
1. Phase L-1: Build §1 OWASP LLM Top 10 pack (14 scanners)
2. Phase L-2: Build §2–§3 prompt injection + jailbreak (28 scanners)
3. Phase L-3: Build §4 data extraction (12 scanners)
4. Phase L-4: Build §6 RAG attacks + §7 agent abuse (22 scanners)
5. Phase L-5: Build §8 supply chain + §9 infrastructure (22 scanners)
6. Phase L-6: Build §10 compliance + §5 model theft (16 scanners)

## References
- OWASP LLM Top 10 (2025): https://genai.owasp.org/llm-top-10/
- NIST AI RMF 1.0: https://www.nist.gov/itl/ai-risk-management-framework
- MITRE ATLAS: https://atlas.mitre.org/
- Garak (LLM vuln scanner): https://github.com/leondz/garak
- PyRIT (Microsoft AI red team): https://github.com/Azure/PyRIT
- promptfoo: https://github.com/promptfoo/promptfoo
- jailbreakbench: https://github.com/JailbreakBench/jailbreakbench
- EU AI Act: https://artificialintelligenceact.eu/
- Anthropic Responsible Scaling: https://www.anthropic.com/news/anthropics-responsible-scaling-policy
