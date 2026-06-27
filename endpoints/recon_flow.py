"""VL-FLOW — Full customer workflow features for Recon module.

Sessions 1-5 in one file:
  1. Scan history + diff
  2. Compare-to-last shortcut (no frontend dep)
  3. Webhooks (Slack/Jira/SIEM/generic)
  4. Scheduled recurring scans (in-process asyncio loop)
  5. Multi-target batch + CSV/JSON export
"""
import asyncio, json, os, hashlib, time, csv, io, uuid, hmac, requests
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from fastapi.responses import StreamingResponse, PlainTextResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota, writable_base, is_safe_external_url

router = APIRouter()

# ─────────────────────── Storage ───────────────────────
_BASE = writable_base("VL_FLOW_DIR", "/app/vl_flow_data")
_HIST = _BASE / "history";    _HIST.mkdir(parents=True, exist_ok=True)
_HOOKS = _BASE / "webhooks";  _HOOKS.mkdir(parents=True, exist_ok=True)
_SCHED = _BASE / "schedules"; _SCHED.mkdir(parents=True, exist_ok=True)
_BATCH = _BASE / "batches";   _BATCH.mkdir(parents=True, exist_ok=True)

def _safe(s): return "".join(c for c in s if c.isalnum() or c in ".-_")
def _target_dir(t):
    d = _HIST / _safe(t); d.mkdir(parents=True, exist_ok=True); return d
def _scan_id(target, ts): return hashlib.sha1(f"{target}-{ts}".encode()).hexdigest()[:12]

# ═════════════════════════════════════════════════════════════
# SESSION 1: Scan history + diff
# ═════════════════════════════════════════════════════════════

class SaveScanReq(BaseModel):
    target: str
    scan_results: dict
    metadata: Optional[dict] = None

def _extract_findings(rec):
    out = []
    for tool, data in (rec.get("results") or rec.get("scan_results") or {}).items():
        if isinstance(data, dict):
            for f in (data.get("findings") or []):
                out.append({
                    "tool": tool,
                    "name": f.get("name") or f.get("detail") or "",
                    "severity": (f.get("severity") or "INFO").upper(),
                    "evidence": (f.get("evidence") or "")[:200],
                    "cwe": f.get("cwe", ""),
                    "remediation": (f.get("remediation") or "")[:300],
                })
    return out

@router.post("/api/recon/scan/save")
async def save_scan(req: SaveScanReq, _=Depends(verify_scan_quota)):
    ts = int(time.time())
    sid = _scan_id(req.target, ts)
    record = {"scan_id": sid, "target": req.target, "timestamp": ts,
              "results": req.scan_results, "metadata": req.metadata or {}}
    out = _target_dir(req.target) / f"{sid}.json"
    out.write_text(json.dumps(record, default=str), encoding="utf-8")
    # Trigger webhooks
    asyncio.create_task(_fire_webhooks(req.target, record))
    return {"ok": True, "scan_id": sid}

@router.get("/api/recon/scan/history")
async def list_history(target: str = Query(...), _=Depends(verify_scan_quota)):
    items = []
    for f in sorted(_target_dir(target).glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
            findings = _extract_findings(rec)
            sev_count = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
            for fn in findings:
                sev_count[fn["severity"]] = sev_count.get(fn["severity"], 0) + 1
            items.append({"scan_id":rec["scan_id"],"timestamp":rec["timestamp"],
                "date":time.strftime("%Y-%m-%d %H:%M", time.gmtime(rec["timestamp"])),
                "total_findings":len(findings),"severity_counts":sev_count})
        except Exception: continue
    return {"target":target,"scan_count":len(items),"scans":items}

@router.get("/api/recon/scan/diff")
async def diff_scans(target: str = Query(...), a: str = Query(...), b: str = Query(...),
                      _=Depends(verify_scan_quota)):
    d = _target_dir(target)
    fa, fb = d / f"{a}.json", d / f"{b}.json"
    if not fa.exists() or not fb.exists():
        raise HTTPException(404, "scan_id not found")
    ra = json.loads(fa.read_text(encoding="utf-8"))
    rb = json.loads(fb.read_text(encoding="utf-8"))
    findings_a = _extract_findings(ra); findings_b = _extract_findings(rb)
    def fh(f): return hashlib.md5(f"{f['tool']}|{f['name']}|{f['severity']}".encode()).hexdigest()
    set_a = {fh(f):f for f in findings_a}
    set_b = {fh(f):f for f in findings_b}
    new = [set_b[k] for k in set_b if k not in set_a]
    resolved = [set_a[k] for k in set_a if k not in set_b]
    unchanged = [k for k in set_b if k in set_a]
    return {"scan_a":{"id":a,"timestamp":ra["timestamp"],"total":len(findings_a)},
            "scan_b":{"id":b,"timestamp":rb["timestamp"],"total":len(findings_b)},
            "new_findings":new,"resolved_findings":resolved,
            "unchanged_count":len(unchanged),
            "delta":{"new":len(new),"resolved":len(resolved),"net":len(new)-len(resolved)}}

# ═════════════════════════════════════════════════════════════
# SESSION 2: Compare-to-last shortcut (auto-finds previous scan)
# ═════════════════════════════════════════════════════════════

@router.get("/api/recon/scan/diff_to_last")
async def diff_to_last(target: str = Query(...), current_scan_id: str = Query(...),
                        _=Depends(verify_scan_quota)):
    """Find the scan immediately before current_scan_id and diff against it."""
    d = _target_dir(target)
    scans = sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    current_idx = None
    for i, f in enumerate(scans):
        if f.stem == current_scan_id: current_idx = i; break
    if current_idx is None: raise HTTPException(404, "current scan not found")
    if current_idx + 1 >= len(scans):
        return {"first_scan": True, "message": "No previous scan to compare against"}
    return await diff_scans(target=target, a=scans[current_idx+1].stem, b=current_scan_id)

# ═════════════════════════════════════════════════════════════
# SESSION 3: Webhooks (Slack / Jira / SIEM / generic POST)
# ═════════════════════════════════════════════════════════════

class WebhookConfig(BaseModel):
    url: str
    name: Optional[str] = "webhook"
    secret: Optional[str] = None      # for HMAC signature
    min_severity: Optional[str] = "MEDIUM"  # only fire for >= this severity
    target_filter: Optional[str] = None     # only fire for matching target (substring)
    format: Optional[str] = "generic"  # generic | slack | jira

_SEV_ORDER = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"POSITIVE":0}

@router.post("/api/recon/webhook/configure")
async def webhook_configure(cfg: WebhookConfig, _=Depends(verify_scan_quota)):
    # Anti-SSRF: reject webhook URLs that point at internal/metadata hosts
    # (audit #12). Re-checked at send time too (DNS-rebinding).
    ok, reason = is_safe_external_url(cfg.url)
    if not ok:
        raise HTTPException(400, f"Refusing webhook URL: {reason}")
    wid = uuid.uuid4().hex[:12]
    rec = cfg.dict()
    rec["webhook_id"] = wid
    rec["created"] = int(time.time())
    (_HOOKS / f"{wid}.json").write_text(json.dumps(rec), encoding="utf-8")
    return {"ok": True, "webhook_id": wid}

@router.get("/api/recon/webhook/list")
async def webhook_list(_=Depends(verify_scan_quota)):
    out = []
    for f in _HOOKS.glob("*.json"):
        try: out.append(json.loads(f.read_text(encoding="utf-8")))
        except: pass
    return {"count": len(out), "webhooks": out}

@router.delete("/api/recon/webhook/{webhook_id}")
async def webhook_delete(webhook_id: str, _=Depends(verify_scan_quota)):
    f = _HOOKS / f"{webhook_id}.json"
    if not f.exists(): raise HTTPException(404)
    f.unlink()
    return {"ok": True}

async def _fire_webhooks(target: str, scan_record: dict):
    """Called after scan saves. Fires all matching webhooks."""
    findings = _extract_findings(scan_record)
    if not findings: return
    for hf in _HOOKS.glob("*.json"):
        try:
            cfg = json.loads(hf.read_text(encoding="utf-8"))
            # Anti-SSRF re-check at send time (defends DNS-rebinding) — audit #12
            ok, reason = is_safe_external_url(cfg.get("url", ""))
            if not ok:
                print(f"[webhook] {hf.name} skipped: unsafe url ({reason})")
                continue
            # Target filter
            if cfg.get("target_filter") and cfg["target_filter"] not in target: continue
            # Severity filter
            min_sev = _SEV_ORDER.get((cfg.get("min_severity") or "MEDIUM").upper(), 2)
            filtered = [f for f in findings if _SEV_ORDER.get(f["severity"], 0) >= min_sev]
            if not filtered: continue
            # Format
            payload = _format_webhook(cfg.get("format", "generic"), target,
                                      scan_record["scan_id"], filtered)
            # HMAC signature if secret set
            headers = {"Content-Type":"application/json","User-Agent":"VulnusLab-Webhook/1.0"}
            if cfg.get("secret"):
                sig = hmac.new(cfg["secret"].encode(), json.dumps(payload).encode(), hashlib.sha256).hexdigest()
                headers["X-VulnusLab-Signature"] = f"sha256={sig}"
            await asyncio.to_thread(requests.post, cfg["url"], json=payload,
                                     headers=headers, timeout=8)
        except Exception as e:
            print(f"[webhook] {hf.name} failed: {e}")

def _format_webhook(fmt, target, scan_id, findings):
    if fmt == "slack":
        return {"text": f"VulnusLab scan: {target}",
                "blocks": [{"type":"section","text":{"type":"mrkdwn",
                    "text":f"*{len(findings)} findings ≥ MEDIUM* on `{target}`\nScan ID: `{scan_id}`"}}]
                + [{"type":"section","text":{"type":"mrkdwn",
                    "text":f"• *{f['severity']}* — {f['name']}\n  _{f['evidence'][:100]}_"}}
                   for f in findings[:10]]}
    elif fmt == "jira":
        return {"fields":{"summary":f"VulnusLab: {len(findings)} findings on {target}",
            "description":"\n".join(f"[{f['severity']}] {f['name']}: {f['evidence'][:80]}"
                                     for f in findings[:20]),
            "issuetype":{"name":"Bug"}, "labels":["vulnuslab","recon"]}}
    return {"target":target,"scan_id":scan_id,"finding_count":len(findings),
            "findings":findings[:50],"timestamp":int(time.time())}

# ═════════════════════════════════════════════════════════════
# SESSION 4: Scheduled recurring scans (in-process asyncio loop)
# ═════════════════════════════════════════════════════════════

class ScheduleReq(BaseModel):
    target: str
    interval_hours: int   # 1 = hourly, 24 = daily, 168 = weekly
    tiers: Optional[List[str]] = None  # subset of tier subdirs to scan

@router.post("/api/recon/schedule/create")
async def schedule_create(req: ScheduleReq, _=Depends(verify_scan_quota)):
    sid = uuid.uuid4().hex[:12]
    rec = req.dict()
    rec["schedule_id"] = sid
    rec["created"] = int(time.time())
    rec["next_run"] = int(time.time()) + req.interval_hours * 3600
    rec["last_run"] = None
    rec["last_scan_id"] = None
    (_SCHED / f"{sid}.json").write_text(json.dumps(rec), encoding="utf-8")
    return {"ok": True, "schedule_id": sid, "next_run": rec["next_run"]}

@router.get("/api/recon/schedule/list")
async def schedule_list(_=Depends(verify_scan_quota)):
    out = []
    for f in _SCHED.glob("*.json"):
        try: out.append(json.loads(f.read_text(encoding="utf-8")))
        except: pass
    return {"count":len(out), "schedules":out}

@router.delete("/api/recon/schedule/{schedule_id}")
async def schedule_delete(schedule_id: str, _=Depends(verify_scan_quota)):
    f = _SCHED / f"{schedule_id}.json"
    if not f.exists(): raise HTTPException(404)
    f.unlink()
    return {"ok": True}

async def _schedule_worker():
    """Background task — checks every 60s for due scans."""
    while True:
        try:
            now = int(time.time())
            for sf in _SCHED.glob("*.json"):
                try:
                    rec = json.loads(sf.read_text(encoding="utf-8"))
                    if rec.get("next_run", 0) > now: continue
                    # Trigger scan via internal HTTP call
                    print(f"[schedule] firing {rec['target']} (schedule {rec['schedule_id']})")
                    try:
                        r = await asyncio.to_thread(requests.post,
                            "http://localhost:8000/api/recon/run_all",
                            json={"target":rec["target"], "tiers":rec.get("tiers")},
                            timeout=300)
                        if r.status_code == 200:
                            rec["last_run"] = now
                            rec["next_run"] = now + rec["interval_hours"]*3600
                            sf.write_text(json.dumps(rec), encoding="utf-8")
                    except Exception as e:
                        print(f"[schedule] fire failed: {e}")
                except Exception: continue
            await asyncio.sleep(60)
        except Exception as e:
            print(f"[schedule worker] {e}")
            await asyncio.sleep(60)

# ═════════════════════════════════════════════════════════════
# SESSION 5: Batch + Export
# ═════════════════════════════════════════════════════════════

class BatchReq(BaseModel):
    targets: List[str]
    tiers: Optional[List[str]] = None

@router.post("/api/recon/scan/batch")
async def batch_scan(req: BatchReq, _=Depends(verify_scan_quota)):
    """Queue a batch of targets to scan. Returns batch_id."""
    if not req.targets: raise HTTPException(400, "no targets")
    if len(req.targets) > 50: raise HTTPException(400, "max 50 targets per batch")
    bid = uuid.uuid4().hex[:12]
    rec = {"batch_id":bid,"targets":req.targets,"tiers":req.tiers,
           "created":int(time.time()),"status":"queued",
           "results":{}}
    (_BATCH / f"{bid}.json").write_text(json.dumps(rec), encoding="utf-8")
    asyncio.create_task(_run_batch(bid))
    return {"ok":True,"batch_id":bid,"target_count":len(req.targets)}

@router.get("/api/recon/scan/batch/{batch_id}")
async def batch_status(batch_id: str, _=Depends(verify_scan_quota)):
    f = _BATCH / f"{batch_id}.json"
    if not f.exists(): raise HTTPException(404)
    return json.loads(f.read_text(encoding="utf-8"))

async def _run_batch(bid: str):
    f = _BATCH / f"{bid}.json"
    try:
        rec = json.loads(f.read_text(encoding="utf-8"))
        rec["status"]="running"; f.write_text(json.dumps(rec), encoding="utf-8")
        # Run up to 5 in parallel
        sem = asyncio.Semaphore(5)
        async def one(target):
            async with sem:
                try:
                    r = await asyncio.to_thread(requests.post,
                        "http://localhost:8000/api/recon/run_all",
                        json={"target":target,"tiers":rec.get("tiers")}, timeout=600)
                    return target, r.status_code, len(r.content) if r.content else 0
                except Exception as e: return target, 0, str(e)[:100]
        results = await asyncio.gather(*[one(t) for t in rec["targets"]])
        rec["results"] = {t:{"status":s,"size":sz} for t,s,sz in results}
        rec["status"]="complete"
        rec["completed"]=int(time.time())
        f.write_text(json.dumps(rec), encoding="utf-8")
    except Exception as e:
        rec = json.loads(f.read_text(encoding="utf-8"))
        rec["status"]="error"; rec["error"]=str(e)[:200]
        f.write_text(json.dumps(rec), encoding="utf-8")

@router.get("/api/recon/scan/export")
async def export_scan(target: str = Query(...), scan_id: str = Query(...),
                       format: str = Query("json"), _=Depends(verify_scan_quota)):
    f = _target_dir(target) / f"{scan_id}.json"
    if not f.exists(): raise HTTPException(404)
    rec = json.loads(f.read_text(encoding="utf-8"))
    findings = _extract_findings(rec)
    if format == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=["tool","severity","name","cwe","evidence","remediation"])
        w.writeheader()
        for f_ in findings: w.writerow(f_)
        return PlainTextResponse(buf.getvalue(),
            headers={"Content-Disposition": f'attachment; filename="vlrecon-{target}-{scan_id}.csv"'})
    elif format == "json":
        return rec
    else:
        raise HTTPException(400, "format must be csv or json")

# ═════════════════════════════════════════════════════════════
# Register router + start background worker on import
# ═════════════════════════════════════════════════════════════

_worker_started = False

def register(app):
    global _worker_started
    app.include_router(router)

    @app.on_event("startup")
    async def _start_scheduler():
        global _worker_started
        if not _worker_started:
            asyncio.create_task(_schedule_worker())
            _worker_started = True
            print("[VL-FLOW] schedule worker started (60s tick)")
