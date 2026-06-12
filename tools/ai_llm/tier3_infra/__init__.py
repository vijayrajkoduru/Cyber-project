"""ai_llm tier3_infra — LLM infrastructure & deployment exposure probes
(playbook §9 LLM Infrastructure & Deployment + §6 #68 vector-DB exposure).

These are REAL, SAFE, READ-ONLY remote probes against the customer's
supplied target (LLM endpoint URL or host). They do NOT exploit, do NOT
send weaponized payloads, and never chain into other scanners. Every
network call is wrapped in try/except with a short timeout and degrades
to a clean INFO/POSITIVE on error — never a false finding.

A graded (CRITICAL/HIGH/MEDIUM/LOW) severity is emitted ONLY when the probe
actually observed the condition on the live target. Everything else is INFO.
"""
