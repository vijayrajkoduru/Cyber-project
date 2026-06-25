"""LLM-driven entity extraction from any text — playbook §8 #99 .

Takes a text blob as `target` (or fetches it from a URL prefixed with
http://). Sends to an LLM (OpenAI-compatible) to extract: people, orgs,
emails, phones, locations, dates, products. Customer provides their
OpenAI/Anthropic key via auth_bearer.

Real probe when LLM key is set. Without key, returns an actionable
how-to advisory (not a fake finding).
"""
import asyncio
import json
import os
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, safe_post, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 30

PROMPT = (
    "Extract structured entities from the input text. Return JSON with keys: "
    "people (list of names), orgs (list of company/org names), emails, phones, "
    "locations (city/country), dates (ISO), products (named tools/services). "
    "Be conservative — only include entities EXPLICITLY mentioned. Return "
    "valid JSON ONLY, no commentary."
)


def _get_text(target: str, req) -> tuple[str, str]:
    """Returns (text, source_note)."""
    if target.startswith(("http://", "https://")):
        r = safe_get(target, req=req, timeout=12,
                      headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
        if r is None or r.status_code != 200:
            return ("", f"URL fetch failed (status={r.status_code if r else 'no-conn'})")
        # Strip HTML tags crudely
        import re
        text = re.sub(r"<[^>]+>", " ", r.text)
        text = re.sub(r"\s+", " ", text).strip()
        return (text[:6000], f"fetched from {target} ({len(text)} chars)")
    return (target[:6000], "input text")


def _do_scan(req: ScanRequest) -> dict:
    text, src = _get_text((req.target or "").strip(), req)
    if not text:
        return standard_response(
            tool="llm_entity_extraction", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=f"no text to process: {src}")

    api_key = (req.auth_bearer or os.environ.get("OSINT_LLM_KEY") or "").strip()
    if not api_key:
        return standard_response(
            tool="llm_entity_extraction", target=req.target,
            findings=[wrap_finding(
                "LLM entity extraction requires an LLM API key",
                severity=grade.advisory(), cwe="CWE-1395",
                remediation=(
                    "Pass an OpenAI-compatible API key as auth_bearer in the scan "
                    "request (or set OSINT_LLM_KEY env var on the backend). Supported: "
                    "OpenAI (api.openai.com), Anthropic via OpenAI-compatible proxy, "
                    "Groq, Together.ai, or any local llama.cpp server."),
                evidence_marker=f"text ready ({len(text)} chars from {src}) but no LLM key configured")],
            tests_performed=0, vulnerable=False,
            tests_summary="LLM key not configured — advisory only")

    # Default to OpenAI; customer can point at any compatible base via OSINT_LLM_BASE
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
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
        }))
    if r is None or r.status_code != 200:
        return standard_response(
            tool="llm_entity_extraction", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"LLM API status {r.status_code if r else 'no-conn'} "
                            f"(check key + base URL)")

    try:
        resp = r.json()
        content = resp["choices"][0]["message"]["content"]
        entities = json.loads(content)
    except Exception as e:
        return standard_response(
            tool="llm_entity_extraction", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"LLM response parse error: {e}")

    counts = {k: len(v) if isinstance(v, list) else 0 for k, v in entities.items()}
    total = sum(counts.values())

    if total == 0:
        return standard_response(
            tool="llm_entity_extraction", target=req.target,
            findings=[wrap_finding(
                "LLM extracted 0 entities from input",
                severity=grade.protective(), cwe="CWE-200",
                remediation="Text contains no recognizable PII / corporate / "
                            "infrastructure entities.",
                evidence_marker=f"LLM model={model} returned empty extraction (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No entities found")

    findings = [wrap_finding(
        f"LLM extracted {total} entit{'y' if total == 1 else 'ies'} from input",
        severity=(sev := grade.inventory(total, low_at=10)), cvss=grade.cvss_for(sev),
        cwe="CWE-200",
        owasp="A05:2021",
        remediation="Each extracted entity is a recon pivot. Cross-reference "
                    "emails with HIBP + Hudson Rock, people with LinkedIn / Sherlock, "
                    "orgs with OpenCorporates + SEC EDGAR.",
        evidence_marker=(
            f"people={counts.get('people',0)} | orgs={counts.get('orgs',0)} | "
            f"emails={counts.get('emails',0)} | phones={counts.get('phones',0)} | "
            f"locations={counts.get('locations',0)} | products={counts.get('products',0)} "
            f"(CONFIRMED via LLM extraction, model={model})"
        ))]

    return standard_response(
        tool="llm_entity_extraction", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(counts.get("emails") or counts.get("phones")),
        tests_summary=f"LLM extracted {total} entities",
        raw_data={"entities": entities, "counts": counts, "model": model, "source": src})


@router.post("/api/osint/llm_entity_extraction")
@vl_verify()
async def scan_llm_entity_extraction(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="llm_entity_extraction", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
