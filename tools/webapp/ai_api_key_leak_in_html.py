"""ai_api_key_leak_in_html — scan homepage + linked JS for embedded LLM API keys.

Modern frontend mistake: bundling OpenAI/Anthropic/Google AI Studio API
keys in client-side JS to call LLMs directly from browser. Anyone with
DevTools can extract + spend. Often costs thousands in hours.

Patterns:
  - OpenAI: sk-... (51 chars), sk-proj-... (longer project keys)
  - Anthropic: sk-ant-... (~100 chars)
  - Google AI Studio: AIza... (39 chars — overlap with Maps but in AI context = leak)
  - Cohere: hex strings near 'cohere' / 'co.embed'
  - Hugging Face: hf_... (37 chars)
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

PATTERNS = [
    ("OpenAI key",         re.compile(rb"\bsk-[A-Za-z0-9]{20,}\b")),
    ("OpenAI project key", re.compile(rb"\bsk-proj-[A-Za-z0-9_-]{40,}\b")),
    ("Anthropic key",      re.compile(rb"\bsk-ant-[A-Za-z0-9_-]{40,}\b")),
    ("Hugging Face token", re.compile(rb"\bhf_[A-Za-z0-9]{30,}\b")),
    ("Replicate token",    re.compile(rb"\br8_[A-Za-z0-9]{36,}\b")),
    ("Mistral API key",    re.compile(rb"\b[A-Za-z0-9]{32}\b(?=.{0,80}mistral)")),
    ("Cohere key",         re.compile(rb"\b[A-Za-z0-9]{40}\b(?=.{0,80}cohere)")),
    ("OpenAI org",         re.compile(rb"\borg-[A-Za-z0-9]{24}\b")),
]
SCRIPT_SRC_RE = re.compile(r'<script[^>]*\bsrc=["\']([^"\']+\.js)["\']', re.IGNORECASE)


def _fetch(url, req):
    return safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=True)


@router.post("/api/webapp/scan/ai_api_key_leak_in_html")
@vl_turbo()
@vl_verify(check_spa=True)
def scan_ai_api_key_leak_in_html(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    root = _fetch(base + "/", req)
    if root is None or root.status_code >= 400:
        return standard_response(
            tool="ai_api_key_leak_in_html", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not fetch homepage")

    sources = {"inline": root.content}
    fetched = 0
    for m in SCRIPT_SRC_RE.finditer(root.text):
        if fetched >= 10: break
        src = m.group(1)
        if src.startswith("//"): src = "https:" + src
        if src.startswith("/"):  src = base + src
        elif not src.startswith("http"): src = base + "/" + src
        if not src.startswith(base): continue
        r = _fetch(src, req)
        if r is None or r.status_code != 200: continue
        sources[src] = r.content[:500_000]
        fetched += 1

    hits = []
    for src_name, content in sources.items():
        for name, pat in PATTERNS:
            for m in pat.finditer(content):
                val = m.group(0).decode(errors="ignore")
                # Skip obvious dummies
                if "your-key" in val.lower() or "example" in val.lower() or val.endswith("XXX"):
                    continue
                hits.append({
                    "type": name,
                    "source": src_name[:80],
                    "preview": val[:20] + "…" + val[-4:],
                })
                if len(hits) >= 15: break
            if len(hits) >= 15: break

    findings = []
    if hits:
        findings.append(wrap_finding(
            f"AI API KEY LEAK in client-side bundle ({len(hits)} hit(s))",
            "CRITICAL", cvss="9.8", cwe="CWE-798", owasp="A07:2021",
            remediation="ROTATE every leaked key IMMEDIATELY at the provider "
                        "(OpenAI / Anthropic / etc.) — anyone with the APK/JS "
                        "bundle has them forever. Migrate to a server-side proxy: "
                        "browser calls YOUR API → your server calls LLM with key. "
                        "Add rate limits + per-user usage caps server-side. Tools "
                        "like LiteLLM proxy + Vercel AI SDK make this trivial.",
            evidence_marker=" | ".join(
                f"{h['type']} ({h['preview']}) in {h['source']}" for h in hits[:5]
            )))
    else:
        findings.append(wrap_finding(
            f"No AI API keys in homepage + {fetched} linked scripts",
            "POSITIVE", cwe="CWE-798",
            remediation="Maintain. CI: gitleaks/trufflehog pre-commit + post-deploy "
                        "scan to catch regressions.",
            evidence_marker=f"scanned {1+fetched} JS sources × {len(PATTERNS)} patterns"))

    return standard_response(
        tool="ai_api_key_leak_in_html", target=req.target, findings=findings,
        tests_performed=1+fetched, vulnerable=bool(hits),
        tests_summary=f"{len(hits)} key leaks across {1+fetched} sources",
        raw_data={"hits": hits[:20]})


def register(app):
    app.include_router(router)
