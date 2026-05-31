"""LLM vision image-to-text OSINT — playbook §8 #103 + §6 #85.

Sends an image URL to a vision-capable LLM (GPT-4o / Claude-Sonnet) and
extracts: visible text (OCR), objects, locations (signs/license plates/
landmarks), people-features (count, posture — no identification), exposed
PII in the image. For geolocation, security camera audit, and image-based
OSINT pivots.

Target = HTTPS URL to the image. Requires vision-capable LLM key.
"""
import asyncio
import json
import os
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_post, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 35

PROMPT = (
    "Analyze the image for OSINT-relevant content. Return JSON: "
    "{\"visible_text\": [list of text strings seen], \"objects\": [list of "
    "key objects], \"location_hints\": [signs/landmarks/license-plate clues], "
    "\"exposed_pii\": [emails/phones/IDs/names visible], \"geolocation_guess\": "
    "{\"country\": str|null, \"city\": str|null, \"confidence\": 0-100}, "
    "\"people_count\": int}. Do NOT identify specific individuals. Be conservative."
)


def _do_scan(req: ScanRequest) -> dict:
    img_url = (req.target or "").strip()
    if not img_url.startswith(("http://", "https://")):
        return standard_response(
            tool="llm_image_to_text", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be image URL (http:// or https://)")

    api_key = (req.auth_bearer or os.environ.get("OSINT_LLM_KEY") or "").strip()
    if not api_key:
        return standard_response(
            tool="llm_image_to_text", target=req.target,
            findings=[wrap_finding(
                "Image-to-text OSINT requires a vision-capable LLM API key",
                severity="INFO", cwe="CWE-1395",
                remediation="Pass an OpenAI-compatible API key as auth_bearer "
                            "with access to a vision model. Set OSINT_LLM_MODEL to "
                            "a vision model (default gpt-4o-mini supports vision).",
                evidence_marker=f"image: {img_url} | no LLM key configured")],
            tests_performed=0, vulnerable=False,
            tests_summary="LLM key not configured")

    base = os.environ.get("OSINT_LLM_BASE", "https://api.openai.com/v1")
    model = os.environ.get("OSINT_LLM_MODEL", "gpt-4o-mini")

    r = safe_post(
        f"{base}/chat/completions",
        req=req, timeout=30,
        headers={"Authorization": f"Bearer {api_key}",
                  "Content-Type": "application/json"},
        data=json.dumps({
            "model": model,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": PROMPT},
                    {"type": "image_url", "image_url": {"url": img_url}},
                ],
            }],
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
        }))
    if r is None or r.status_code != 200:
        return standard_response(
            tool="llm_image_to_text", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"LLM status {r.status_code if r else 'no-conn'} "
                            f"(image may not be reachable from LLM provider)")

    try:
        result = json.loads(r.json()["choices"][0]["message"]["content"])
    except Exception as e:
        return standard_response(
            tool="llm_image_to_text", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"LLM parse error: {e}")

    pii = result.get("exposed_pii", []) or []
    text_seen = result.get("visible_text", []) or []
    location = result.get("geolocation_guess", {}) or {}

    findings = []
    if pii:
        findings.append(wrap_finding(
            f"EXPOSED PII in image: {len(pii)} item(s)",
            severity="HIGH", cvss="7.5", cwe="CWE-359",
            owasp="A05:2021",
            remediation="If this is YOUR image (e.g. on your website / social): "
                        "remove, blur, or replace. PII in images is indexed by Google "
                        "Image Search + reverse-image-search and is often missed "
                        "during text-based privacy reviews.",
            evidence_marker=f"pii_visible: {', '.join(pii[:5])} (CONFIRMED via vision LLM)"))

    if location.get("country") and location.get("confidence", 0) >= 50:
        findings.append(wrap_finding(
            f"Image geolocated: {location.get('city','?')}, {location.get('country','?')} "
            f"(confidence {location.get('confidence',0)}%)",
            severity="MEDIUM" if location.get("confidence", 0) >= 75 else "LOW",
            cwe="CWE-359", cvss="4.3",
            remediation="If this image is from a private location and you don't "
                        "want it geolocated, strip EXIF metadata and blur any landmarks / "
                        "signs / license plates before sharing.",
            evidence_marker=f"location={location} (CONFIRMED via vision LLM, model={model})"))

    findings.append(wrap_finding(
        f"Image OSINT — {len(text_seen)} text, {result.get('people_count', 0)} people, "
        f"{len(result.get('objects', []))} objects",
        severity="POSITIVE" if not pii else "INFO",
        cwe="CWE-200",
        remediation="Reverse-search the image (Yandex / TinEye / Google Lens) "
                    "for additional context / earlier appearances.",
        evidence_marker=(
            f"text_sample: {', '.join(text_seen[:3])} | "
            f"objects: {', '.join((result.get('objects') or [])[:5])} "
            f"(LLM model={model})"
        )))

    return standard_response(
        tool="llm_image_to_text", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(pii),
        tests_summary=f"image: {len(text_seen)} text / {len(pii)} pii / loc={location.get('country','?')}",
        raw_data={"result": result, "model": model})


@router.post("/api/osint/llm_image_to_text")
async def scan_llm_image_to_text(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="llm_image_to_text", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
