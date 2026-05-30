"""LLM-driven disinformation/coordinated-inauthentic-behavior detect — playbook §8 #102 ⭐.

Analyzes a text blob (or fetched URL) for disinformation markers: emotional
manipulation, unverifiable claims, source-laundering patterns, bot-style
phrasing, foreign influence signals. Returns severity-ranked findings.

Real probe when LLM key set. Customer provides OpenAI/Anthropic key via
auth_bearer.
"""
import asyncio
import json
import os
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, safe_post, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 30

PROMPT = (
    "Analyze the text for disinformation indicators. Score 0-100 each of: "
    "emotional_manipulation, unverified_claims, source_laundering, "
    "bot_style_phrasing, foreign_influence_markers. Return JSON: "
    "{\"scores\": {...}, \"overall_risk\": 0-100, \"top_indicators\": [list], "
    "\"verdict\": \"clean\" | \"suspicious\" | \"likely_disinfo\"}. "
    "Be conservative — only flag with clear textual evidence."
)


def _get_text(target, req) -> tuple[str, str]:
    if target.startswith(("http://", "https://")):
        r = safe_get(target, req=req, timeout=12,
                      headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
        if r is None or r.status_code != 200:
            return ("", f"URL fetch failed")
        import re
        text = re.sub(r"<[^>]+>", " ", r.text)
        text = re.sub(r"\s+", " ", text).strip()
        return (text[:6000], f"fetched from {target}")
    return (target[:6000], "input text")


def _do_scan(req: ScanRequest) -> dict:
    text, src = _get_text((req.target or "").strip(), req)
    if not text:
        return standard_response(
            tool="llm_disinfo_detect", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=f"no text: {src}")

    api_key = (req.auth_bearer or os.environ.get("OSINT_LLM_KEY") or "").strip()
    if not api_key:
        return standard_response(
            tool="llm_disinfo_detect", target=req.target,
            findings=[wrap_finding(
                "Disinformation detect requires an LLM API key",
                severity="INFO", cwe="CWE-1395",
                remediation="Pass an OpenAI-compatible API key as auth_bearer "
                            "(or set OSINT_LLM_KEY env var on the backend).",
                evidence_marker=f"text ready ({len(text)} chars from {src}) | no LLM key")],
            tests_performed=0, vulnerable=False,
            tests_summary="LLM key not configured")

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
                {"role": "user", "content": text},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }))
    if r is None or r.status_code != 200:
        return standard_response(
            tool="llm_disinfo_detect", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"LLM status {r.status_code if r else 'no-conn'}")

    try:
        result = json.loads(r.json()["choices"][0]["message"]["content"])
    except Exception as e:
        return standard_response(
            tool="llm_disinfo_detect", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"LLM parse error: {e}")

    overall = result.get("overall_risk", 0)
    verdict = result.get("verdict", "unknown")
    scores = result.get("scores", {})
    indicators = result.get("top_indicators", [])

    if verdict == "clean" or overall < 25:
        sev, cwe = "POSITIVE", "CWE-200"
    elif verdict == "likely_disinfo" or overall >= 70:
        sev, cwe = "HIGH", "CWE-451"
    else:
        sev, cwe = "MEDIUM", "CWE-451"

    findings = [wrap_finding(
        f"Disinfo analysis — verdict: {verdict} (risk score: {overall}/100)",
        severity=sev, cwe=cwe,
        remediation="If suspicious/likely_disinfo: corroborate with two independent "
                    "primary sources, identify amplification network on social media, "
                    "report to platform trust-and-safety + relevant CERT/election integrity body.",
        evidence_marker=(
            f"scores: {scores} | indicators: {','.join(indicators[:5])} "
            f"(LLM model={model})"
        ))]

    return standard_response(
        tool="llm_disinfo_detect", target=req.target, findings=findings,
        tests_performed=1, vulnerable=(sev in ("MEDIUM", "HIGH")),
        tests_summary=f"verdict={verdict} risk={overall}",
        raw_data={"result": result, "model": model, "source": src})


@router.post("/api/osint/llm_disinfo_detect")
async def scan_llm_disinfo_detect(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="llm_disinfo_detect", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
