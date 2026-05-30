"""LLM phishing-pretext drafting — playbook §8 #101 ⭐.

Generates a phishing pretext draft from a brief scenario description.
Target format: "scenario: <text>" — e.g. "scenario: CTO of TechCorp,
recent M&A activity, urgent fund transfer". Returns a 3-paragraph
pretext suitable for red-team email simulation.

For authorized penetration testing only. Requires LLM API key via
auth_bearer.
"""
import asyncio
import json
import os
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_post, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 30

PROMPT = (
    "You are assisting an authorized red-team penetration test. Draft a "
    "PLAUSIBLE phishing pretext email (subject + body, ~150 words) based "
    "on the scenario provided. Use known psychology levers (authority, "
    "urgency, scarcity). DO NOT include actual malicious payloads or "
    "links — leave a placeholder [PHISH_URL]. Output as JSON: "
    "{\"subject\": ..., \"body\": ..., \"levers\": [...]}."
)


def _do_scan(req: ScanRequest) -> dict:
    scenario = (req.target or "").strip()
    if scenario.lower().startswith("scenario:"):
        scenario = scenario[9:].strip()
    if not scenario:
        return standard_response(
            tool="llm_pretext_draft", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty scenario")

    api_key = (req.auth_bearer or os.environ.get("OSINT_LLM_KEY") or "").strip()
    if not api_key:
        return standard_response(
            tool="llm_pretext_draft", target=req.target,
            findings=[wrap_finding(
                "Pretext drafting requires an LLM API key",
                severity="INFO", cwe="CWE-1395",
                remediation="Pass an OpenAI-compatible API key as auth_bearer. "
                            "FOR AUTHORIZED PENETRATION TESTING ONLY — this tool "
                            "produces phishing content that is illegal to use without "
                            "explicit prior written permission from target organization.",
                evidence_marker=f"scenario: {scenario[:100]} | no LLM key configured")],
            tests_performed=0, vulnerable=False,
            tests_summary="LLM key not configured — advisory only")

    base = os.environ.get("OSINT_LLM_BASE", "https://api.openai.com/v1")
    model = os.environ.get("OSINT_LLM_MODEL", "gpt-4o-mini")

    r = safe_post(
        f"{base}/chat/completions",
        req=req, timeout=25,
        headers={"Authorization": f"Bearer {api_key}",
                  "Content-Type": "application/json"},
        data=json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": PROMPT},
                {"role": "user", "content": scenario},
            ],
            "temperature": 0.7,
            "response_format": {"type": "json_object"},
        }))
    if r is None or r.status_code != 200:
        return standard_response(
            tool="llm_pretext_draft", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"LLM API status {r.status_code if r else 'no-conn'}")

    try:
        draft = json.loads(r.json()["choices"][0]["message"]["content"])
    except Exception as e:
        return standard_response(
            tool="llm_pretext_draft", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"LLM parse error: {e}")

    findings = [wrap_finding(
        f"Pretext draft generated — subject: {draft.get('subject', '?')[:80]}",
        severity="INFO", cwe="CWE-1395",
        remediation="USE ONLY ON AUTHORIZED ENGAGEMENTS. Customize with target-"
                    "specific facts gathered from other OSINT (LinkedIn, GitHub, "
                    "SEC filings). Track in your phishing platform (GoPhish, etc.) "
                    "with audit trail.",
        evidence_marker=(
            f"subject: {draft.get('subject','')[:100]} | "
            f"levers: {','.join(draft.get('levers',[])[:4])} | "
            f"body_length: {len(draft.get('body',''))}ch "
            f"(LLM model={model})"
        ))]

    return standard_response(
        tool="llm_pretext_draft", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"Pretext: {draft.get('subject','?')[:50]}",
        raw_data={"draft": draft, "model": model})


@router.post("/api/osint/llm_pretext_draft")
async def scan_llm_pretext_draft(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="llm_pretext_draft", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
