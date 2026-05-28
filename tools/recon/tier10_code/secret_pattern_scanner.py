"""Secret Pattern Scanner — Route: /api/recon/secret_pattern_scanner
Scans homepage + linked JS bundles for leaked secrets via regex in secret_patterns.json."""
import asyncio, re, json
from pathlib import Path
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner

router = APIRouter()
_PAYLOAD = Path(__file__).resolve().parent.parent.parent / "_payloads" / "recon" / "secret_patterns.json"
_MAX_JS, _TO = 5, 8

_FALLBACK = [
    {"name":"AWS Access Key","regex":r"AKIA[0-9A-Z]{16}","severity":"CRITICAL"},
    {"name":"GitHub Token","regex":r"gh[pousr]_[0-9a-zA-Z]{36,255}","severity":"CRITICAL"},
    {"name":"Slack Token","regex":r"xox[baprs]-[0-9a-zA-Z-]{10,}","severity":"HIGH"},
    {"name":"Generic API Key","regex":r"api[_-]?key['\"]\s*[:=]\s*['\"][0-9a-zA-Z]{32,}['\"]","severity":"HIGH"},
]

def _load():
    try:
        if _PAYLOAD.exists():
            data = json.loads(_PAYLOAD.read_text(encoding="utf-8"))
            if isinstance(data, list): return data
            if isinstance(data, dict) and "patterns" in data: return data["patterns"]
    except Exception: pass
    return _FALLBACK

def _get(url):
    try:
        return requests.get(url, timeout=_TO, verify=False,
                            headers={"User-Agent":"VulnusLab/1.0"}, allow_redirects=True)
    except Exception: return None

async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    r = await asyncio.to_thread(_get, base + "/")
    if not r:
        ctx.state["target_reachable"] = False; return
    ctx.state["target_reachable"] = True
    ctx.source("homepage")
    bodies = [("homepage", r.text or "")]
    js_urls = re.findall(r'<script[^>]+src="([^"]+\.js)"', r.text or "")
    js_urls = [u if u.startswith("http") else base + (u if u.startswith("/") else "/"+u) for u in js_urls[:_MAX_JS]]
    if js_urls:
        ctx.state["js_count"] = len(js_urls)
        ctx.source(f"js-bundles ({len(js_urls)})")
        for u in js_urls:
            jr = await asyncio.to_thread(_get, u)
            if jr and jr.status_code == 200:
                bodies.append((u.split("/")[-1][:50], (jr.text or "")[:500000]))
    patterns = _load()
    ctx.state["patterns_count"] = len(patterns)
    hits = []
    for src_name, body in bodies:
        for p in patterns:
            try:
                rx = p.get("regex") or p.get("pattern")
                if not rx: continue
                m = re.search(rx, body)
                if m:
                    hits.append({"name": p.get("name","unknown"),
                                 "severity": p.get("severity","MEDIUM"),
                                 "source": src_name, "match": m.group(0)[:80]})
            except re.error: continue
    ctx.state["hits"] = hits
    ctx.state["hits_count"] = len(hits)
    if hits: ctx.source(f"secrets ({len(hits)})")

def r_critical(s):
    c = [h for h in (s.get("hits") or []) if h.get("severity","").upper() == "CRITICAL"]
    if not c: return None
    return {"name": f"CRITICAL secrets leaked in client code ({len(c)})",
            "severity": "CRITICAL", "cvss": 9.5, "cwe": "CWE-798",
            "cwe_name": "Use of Hard-coded Credentials",
            "owasp": "A07:2021 — Identification and Authentication Failures",
            "evidence": "; ".join(f"{h['name']} in {h['source']}: {h['match']}" for h in c[:3]),
            "remediation": "Rotate ALL leaked credentials immediately. Audit git history. Move secrets to server-side env vars / vault. Never bundle into client JS."}

def r_high(s):
    h = [x for x in (s.get("hits") or []) if x.get("severity","").upper() == "HIGH"]
    if not h: return None
    return {"name": f"HIGH-severity secrets in client code ({len(h)})",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-200",
            "evidence": "; ".join(f"{x['name']} in {x['source']}" for x in h[:3]),
            "remediation": "Treat as compromised. Rotate tokens, move to server-side, scan git history."}

def r_clean(s):
    if not s.get("target_reachable"): return None
    if s.get("hits"): return None
    return {"name": "No secret patterns matched in client code",
            "severity": "POSITIVE",
            "evidence": f"Scanned homepage + {s.get('js_count',0)} JS bundles against {s.get('patterns_count',0)} patterns."}

def r_unreach(s):
    if s.get("target_reachable"): return None
    return {"name": "Target unreachable", "severity":"INFO","evidence":"HTTP fetch failed"}

FINDING_RULES = [r_critical, r_high, r_clean, r_unreach]
INTEL_FIELDS = [("Target reachable","target_reachable"),("JS bundles scanned","js_count"),
                ("Patterns tested","patterns_count"),("Secrets found","hits_count")]

@router.post("/api/recon/secret_pattern_scanner")
async def recon_secret_pattern_scanner(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="secret_pattern_scanner",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["hits","hits_count"])

def register(app): app.include_router(router)
