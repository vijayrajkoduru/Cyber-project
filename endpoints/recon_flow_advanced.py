"""VL-FLOW Sessions 7-13: Advanced workflow features."""
import asyncio, json, os, hashlib, hmac, time, uuid, base64, requests
from pathlib import Path
from typing import Optional, List, Dict
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from tools._shared import verify_scan_quota, writable_base

router = APIRouter()
_BASE = writable_base("VL_FLOW_DIR", "/app/vl_flow_data")
for sub in ["screenshots","signatures","brands","collab","templates","rules"]:
    (_BASE/sub).mkdir(parents=True, exist_ok=True)

_SIGN_KEY = os.environ.get("VL_FLOW_SIGN_KEY","vulnuslab-default-key-change-me").encode()

def _safe(s):
    """Strip path-traversal / separator chars from user-supplied path segments."""
    return "".join(c for c in str(s) if c.isalnum() or c in ".-_")

# ═════════════════════════════════════════════════════════════
# SESSION 7: Per-finding screenshot (headless capture)
# ═════════════════════════════════════════════════════════════

class ScreenshotReq(BaseModel):
    url: str
    finding_id: Optional[str] = None
    full_page: Optional[bool] = False

@router.post("/api/recon/finding/screenshot")
async def capture_screenshot(req: ScreenshotReq, _=Depends(verify_scan_quota)):
    """Capture URL screenshot. Tries Playwright → screenshotapi.io fallback → error."""
    fid = req.finding_id or uuid.uuid4().hex[:12]
    out = _BASE/"screenshots"/f"{fid}.png"
    # Try Playwright (if installed in container)
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width":1280,"height":800})
            await page.goto(req.url, timeout=15000, wait_until="domcontentloaded")
            png = await page.screenshot(full_page=req.full_page)
            await browser.close()
            out.write_bytes(png)
            return {"ok":True,"finding_id":fid,"path":str(out),"size":len(png),"backend":"playwright"}
    except ImportError:
        pass
    # Fallback: screenshotapi.io (key-gated)
    api_key=os.environ.get("SCREENSHOTAPI_KEY","")
    if api_key:
        try:
            r=requests.get("https://shot.screenshotapi.net/screenshot",
                params={"token":api_key,"url":req.url,"output":"image","file_type":"png",
                        "width":1280,"height":800},timeout=20)
            if r.status_code==200:
                out.write_bytes(r.content)
                return {"ok":True,"finding_id":fid,"path":str(out),"backend":"screenshotapi.io"}
        except Exception as e:
            return {"ok":False,"error":str(e)[:200]}
    return {"ok":False,"error":"No screenshot backend available",
            "remediation":"Install playwright: pip install playwright && playwright install chromium  | OR set SCREENSHOTAPI_KEY env var"}

@router.get("/api/recon/finding/screenshot/{finding_id}")
async def get_screenshot(finding_id: str, _=Depends(verify_scan_quota)):
    f = _BASE/"screenshots"/f"{finding_id}.png"
    if not f.exists(): raise HTTPException(404)
    return {"finding_id":finding_id,"base64":base64.b64encode(f.read_bytes()).decode("ascii"),
            "size":f.stat().st_size}

# ═════════════════════════════════════════════════════════════
# SESSION 8: Signed PDF reports (HMAC-SHA256 signature)
# ═════════════════════════════════════════════════════════════

class SignReq(BaseModel):
    report_id: str
    content_hash: str   # SHA-256 of PDF bytes (from frontend)

@router.post("/api/recon/pdf/sign")
async def sign_pdf(req: SignReq, _=Depends(verify_scan_quota)):
    """Sign a report — returns HMAC-SHA256 + timestamp. Use to verify integrity."""
    ts = int(time.time())
    payload = f"{req.report_id}|{req.content_hash}|{ts}"
    sig = hmac.new(_SIGN_KEY, payload.encode(), hashlib.sha256).hexdigest()
    rec = {"report_id":req.report_id,"content_hash":req.content_hash,
           "signed_at":ts,"signature":sig,"algorithm":"HMAC-SHA256"}
    (_BASE/"signatures"/f"{req.report_id}.json").write_text(json.dumps(rec), encoding="utf-8")
    return rec

class VerifyReq(BaseModel):
    report_id: str
    content_hash: str
    signature: str
    signed_at: int

@router.post("/api/recon/pdf/verify")
async def verify_pdf(req: VerifyReq, _=Depends(verify_scan_quota)):
    payload = f"{req.report_id}|{req.content_hash}|{req.signed_at}"
    expected = hmac.new(_SIGN_KEY, payload.encode(), hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(expected, req.signature)
    return {"valid":valid,"report_id":req.report_id,"signed_at":req.signed_at,
            "age_seconds":int(time.time())-req.signed_at,
            "verification":"HMAC-SHA256 match" if valid else "TAMPERED — signatures don't match"}

# ═════════════════════════════════════════════════════════════
# SESSION 9: White-label branding
# ═════════════════════════════════════════════════════════════

class BrandConfig(BaseModel):
    customer_id: str
    company_name: str
    logo_url: Optional[str] = None
    primary_color: Optional[str] = "#1e40af"
    accent_color: Optional[str] = "#3b82f6"
    footer_text: Optional[str] = None

def _brand_dir(uid):
    # Per-user namespace — branding is tenant-private (was a global store any
    # user could read/overwrite/enumerate by customer_id: cross-tenant IDOR).
    d = _BASE/"brands"/_safe(uid); d.mkdir(parents=True, exist_ok=True); return d

@router.post("/api/recon/brand/configure")
async def brand_configure(cfg: BrandConfig, payload=Depends(verify_scan_quota)):
    (_brand_dir(payload["sub"])/f"{_safe(cfg.customer_id)}.json").write_text(
        json.dumps(cfg.dict()), encoding="utf-8")
    return {"ok":True,"customer_id":cfg.customer_id}

@router.get("/api/recon/brand/{customer_id}")
async def brand_get(customer_id: str, payload=Depends(verify_scan_quota)):
    f = _brand_dir(payload["sub"])/f"{_safe(customer_id)}.json"
    if not f.exists():
        return {"customer_id":customer_id,"company_name":"VulnusLab",
                "logo_url":None,"primary_color":"#1e40af","accent_color":"#3b82f6"}
    return json.loads(f.read_text(encoding="utf-8"))

@router.get("/api/recon/brand")
async def brand_list(payload=Depends(verify_scan_quota)):
    out = []
    for f in _brand_dir(payload["sub"]).glob("*.json"):
        try: out.append(json.loads(f.read_text(encoding="utf-8")))
        except: pass
    return {"count":len(out),"brands":out}

# ═════════════════════════════════════════════════════════════
# SESSION 10: Bug bounty export (HackerOne / Bugcrowd format)
# ═════════════════════════════════════════════════════════════

@router.get("/api/recon/scan/export_bb")
async def export_bb(target: str = Query(...), scan_id: str = Query(...),
                     platform: str = Query("hackerone"),
                     payload=Depends(verify_scan_quota)):
    """Export findings as HackerOne / Bugcrowd submission format."""
    # Read from the caller's own history namespace (matches recon_flow.save_scan)
    # so one user can't export another user's scan by guessing target/scan_id.
    f = _BASE/"history"/_safe(payload["sub"])/_safe(target)/f"{_safe(scan_id)}.json"
    if not f.exists(): raise HTTPException(404)
    rec = json.loads(f.read_text(encoding="utf-8"))
    findings = []
    for tool, data in (rec.get("results") or {}).items():
        if isinstance(data, dict):
            for fn in (data.get("findings") or []):
                sev = (fn.get("severity") or "INFO").upper()
                if sev not in ("CRITICAL","HIGH","MEDIUM"): continue
                findings.append({"tool":tool,"finding":fn})
    if platform=="hackerone":
        out = [{"title":f["finding"].get("name") or f["finding"].get("detail",""),
                "vulnerability_information":f["finding"].get("evidence","")[:500],
                "severity_rating":f["finding"].get("severity","").lower(),
                "weakness":f["finding"].get("cwe",""),
                "structured_scope":{"asset_identifier":target,"asset_type":"DOMAIN"}}
               for f in findings]
    elif platform=="bugcrowd":
        out = [{"submission":{"title":f["finding"].get("name",""),
                "description":f["finding"].get("evidence",""),
                "priority":{"CRITICAL":"p1","HIGH":"p2","MEDIUM":"p3"}.get(f["finding"].get("severity","").upper(),"p4"),
                "vrt_id":"server_security_misconfiguration","target_url":target}}
               for f in findings]
    else:
        raise HTTPException(400,"platform must be hackerone or bugcrowd")
    return {"platform":platform,"target":target,"scan_id":scan_id,
            "submission_count":len(out),"submissions":out}

# ═════════════════════════════════════════════════════════════
# SESSION 11: Pentester collaboration (per-finding workflow state)
# ═════════════════════════════════════════════════════════════

_VALID_STATES = ["NEW","TRIAGING","CONFIRMED","FALSE_POSITIVE","PATCHED","VERIFIED","WONT_FIX"]

class FindingStatusReq(BaseModel):
    target: str
    scan_id: str
    finding_hash: str   # unique fingerprint of the finding
    new_state: str
    note: Optional[str] = None
    assigned_to: Optional[str] = None

@router.post("/api/recon/finding/status")
async def set_finding_status(req: FindingStatusReq, payload=Depends(verify_scan_quota)):
    if req.new_state not in _VALID_STATES:
        raise HTTPException(400,f"state must be one of {_VALID_STATES}")
    collab_dir = _BASE/"collab"/_safe(payload["sub"])/_safe(req.target)
    collab_dir.mkdir(parents=True, exist_ok=True)
    f = collab_dir/f"{_safe(req.finding_hash)}.json"
    history = []
    if f.exists():
        history = json.loads(f.read_text(encoding="utf-8")).get("history",[])
    history.append({"state":req.new_state,"timestamp":int(time.time()),
        "note":req.note,"assigned_to":req.assigned_to})
    rec = {"finding_hash":req.finding_hash,"target":req.target,"scan_id":req.scan_id,
        "current_state":req.new_state,"history":history,
        "last_update":int(time.time())}
    f.write_text(json.dumps(rec), encoding="utf-8")
    return {"ok":True,"current_state":req.new_state,"history_length":len(history)}

@router.get("/api/recon/finding/history/{target}/{finding_hash}")
async def get_finding_history(target: str, finding_hash: str, payload=Depends(verify_scan_quota)):
    f = _BASE/"collab"/_safe(payload["sub"])/_safe(target)/f"{_safe(finding_hash)}.json"
    if not f.exists(): return {"current_state":"NEW","history":[]}
    return json.loads(f.read_text(encoding="utf-8"))

# ═════════════════════════════════════════════════════════════
# SESSION 12: Per-industry report templates
# ═════════════════════════════════════════════════════════════

_TEMPLATES = {
    "hipaa": {"focus":["Email Security","Privacy","Encryption"],
        "compliance_frameworks":["HIPAA 164.308","HIPAA 164.310","HIPAA 164.312"],
        "ignore_low_findings":False,"emphasize":"data_exposure"},
    "pci": {"focus":["Network Security","TLS","Authentication","Logging"],
        "compliance_frameworks":["PCI-DSS 2","PCI-DSS 4","PCI-DSS 6","PCI-DSS 11"],
        "ignore_low_findings":False,"emphasize":"cardholder_data"},
    "soc2": {"focus":["Access Control","Monitoring","Change Management"],
        "compliance_frameworks":["SOC 2 CC6","SOC 2 CC7","SOC 2 CC8"],
        "ignore_low_findings":True,"emphasize":"availability"},
    "iso27001": {"focus":["Risk Management","Access Control","Cryptography"],
        "compliance_frameworks":["ISO 27001 A.5","A.8","A.9","A.10","A.12"],
        "ignore_low_findings":False,"emphasize":"isms"},
    "generic": {"focus":[],"compliance_frameworks":[],"ignore_low_findings":False,"emphasize":"all"},
}

@router.get("/api/recon/template/list")
async def template_list(_=Depends(verify_scan_quota)):
    return {"count":len(_TEMPLATES),"templates":list(_TEMPLATES.keys()),
            "details":_TEMPLATES}

@router.get("/api/recon/template/{template_id}")
async def template_get(template_id: str, _=Depends(verify_scan_quota)):
    if template_id not in _TEMPLATES:
        raise HTTPException(404,f"unknown template; valid: {list(_TEMPLATES)}")
    return {"template_id":template_id, **_TEMPLATES[template_id]}

# ═════════════════════════════════════════════════════════════
# SESSION 13: Custom rule engine (YAML upload + JSON eval)
# ═════════════════════════════════════════════════════════════

class CustomRule(BaseModel):
    rule_id: Optional[str] = None
    name: str
    condition: str    # simple expression e.g. "scan.ports contains 23"
    severity: str = "MEDIUM"
    cwe: Optional[str] = None
    remediation: Optional[str] = None
    enabled: bool = True

@router.post("/api/recon/rules/upload")
async def rule_upload(rule: CustomRule, _=Depends(verify_scan_quota)):
    rid = rule.rule_id or uuid.uuid4().hex[:12]
    rec = rule.dict()
    rec["rule_id"]=rid
    rec["created"]=int(time.time())
    (_BASE/"rules"/f"{rid}.json").write_text(json.dumps(rec), encoding="utf-8")
    return {"ok":True,"rule_id":rid}

@router.get("/api/recon/rules/list")
async def rule_list(_=Depends(verify_scan_quota)):
    out=[]
    for f in (_BASE/"rules").glob("*.json"):
        try: out.append(json.loads(f.read_text(encoding="utf-8")))
        except: pass
    return {"count":len(out),"rules":out}

@router.delete("/api/recon/rules/{rule_id}")
async def rule_delete(rule_id: str, _=Depends(verify_scan_quota)):
    f = _BASE/"rules"/f"{rule_id}.json"
    if not f.exists(): raise HTTPException(404)
    f.unlink()
    return {"ok":True}

class EvalReq(BaseModel):
    scan_data: dict   # the r{} object


def _traverse(data, dotted: str):
    """Safely resolve a dotted path (e.g. 'http.headers.server') into nested
    dict/list scan data. Pure structural lookup — NO eval, so a stored rule
    condition can never execute code (was a 2-request RCE, audit)."""
    cur = data
    for part in dotted.strip().split("."):
        part = part.strip()
        if not part:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, (list, tuple)):
            if not part.lstrip("-").isdigit():
                return None
            i = int(part)
            cur = cur[i] if -len(cur) <= i < len(cur) else None
        else:
            return None
        if cur is None:
            return None
    return cur


@router.post("/api/recon/rules/evaluate")
async def rules_evaluate(req: EvalReq, _=Depends(verify_scan_quota)):
    """Evaluate all enabled rules against scan data. Returns matching findings."""
    matches=[]
    for f in (_BASE/"rules").glob("*.json"):
        try:
            rule=json.loads(f.read_text(encoding="utf-8"))
            if not rule.get("enabled",True): continue
            # Simple eval: split "X contains Y" or "X == Y"
            cond=rule.get("condition","")
            tokens=cond.split()
            if "contains" in tokens:
                idx=tokens.index("contains")
                lhs=" ".join(tokens[:idx])
                rhs=" ".join(tokens[idx+1:]).strip('"\'')
                val=_traverse(req.scan_data, lhs) if "." in lhs else None
                if val and rhs in str(val):
                    matches.append({"rule_id":rule["rule_id"],"name":rule["name"],
                        "severity":rule["severity"],"cwe":rule.get("cwe"),
                        "evidence":f"Condition matched: {cond}",
                        "remediation":rule.get("remediation","")})
        except Exception: continue
    return {"match_count":len(matches),"matches":matches}

def register(app):
    app.include_router(router)
