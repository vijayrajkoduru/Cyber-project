"""VL-FLOW — Full customer workflow features for Recon module.

Sessions 1-5 in one file:
  1. Scan history + diff
  2. Compare-to-last shortcut (no frontend dep)
  3. Webhooks (Slack/Jira/SIEM/generic)
  4. Scheduled recurring scans (in-process asyncio loop)
  5. Multi-target batch + CSV/JSON export
"""
import asyncio, json, os, hashlib, time, csv, io, uuid, hmac, re, socket, ipaddress, requests
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from fastapi.responses import StreamingResponse, PlainTextResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota

router = APIRouter()

# ─────────────────────── Storage ───────────────────────
_BASE = Path(os.environ.get("VL_FLOW_DIR", "/app/vl_flow_data"))
_HIST = _BASE / "history";    _HIST.mkdir(parents=True, exist_ok=True)
_HOOKS = _BASE / "webhooks";  _HOOKS.mkdir(parents=True, exist_ok=True)
_SCHED = _BASE / "schedules"; _SCHED.mkdir(parents=True, exist_ok=True)
_BATCH = _BASE / "batches";   _BATCH.mkdir(parents=True, exist_ok=True)

def _safe(s): return "".join(c for c in s if c.isalnum() or c in ".-_")
def _target_dir(t):
    d = _HIST / _safe(t); d.mkdir(parents=True, exist_ok=True); return d
def _scan_id(target, ts, salt=""): return hashlib.sha1(f"{target}-{ts}-{salt}".encode()).hexdigest()[:12]

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
def _valid_id(s): return bool(_ID_RE.match(s or ""))

# ───────────────── Org scoping (Phase 2.1 Step 3) ─────────────────
# Scan history lives in a flat per-target dir shared by all tenants, so each
# record is TAGGED with org_id and FILTERED on read. Records written before
# org tagging (no org_id) are grandfathered as visible so existing data is
# never orphaned. Result: cross-tenant isolation (org A can't read org B's
# scans) while everyone in one org shares results.
def _caller_org(payload):
    """Resolve the caller's org id from the JWT claim, else a DB lookup.
    None only if RBAC is unavailable -> caller falls back to legacy visibility."""
    if isinstance(payload, dict):
        oid = payload.get("org_id")
        if oid:
            return oid
        sub = payload.get("sub")
        if sub:
            try:
                from tools.auth._orgs import get_user_org_role
                oid, _ = get_user_org_role(sub)
                return oid
            except Exception:
                return None
    return None

def _org_can_see(rec, oid):
    """A record is visible if it belongs to the caller's org, or it predates
    org tagging (legacy, no org_id -> grandfathered)."""
    rec_oid = (rec or {}).get("org_id")
    return (not rec_oid) or (oid is not None and rec_oid == oid)

def _load_rec(target, sid):
    if not _valid_id(sid):
        return None
    f = _target_dir(target) / f"{sid}.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return None

def _url_is_safe(url):
    """Return (ok, reason). Blocks non-http(s) schemes and any URL that
    resolves to a private / loopback / link-local / reserved / multicast IP.
    Stops the webhook + scheduler fire paths from being used as an SSRF
    primitive against cloud metadata (169.254.169.254), localhost, or RFC1918
    hosts. Re-checked at fire time for DNS-rebind safety."""
    try:
        p = urlparse(url or "")
    except Exception:
        return False, "unparseable URL"
    if p.scheme not in ("http", "https"):
        return False, f"scheme '{p.scheme or ''}' not allowed (use http/https)"
    host = p.hostname
    if not host:
        return False, "URL has no host"
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except Exception as e:
        return False, f"DNS resolution failed: {e}"
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except Exception:
            return False, "unresolvable address"
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False, f"host resolves to non-public IP {ip}"
    return True, "ok"

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
async def save_scan(req: SaveScanReq, payload=Depends(verify_scan_quota)):
    oid = _caller_org(payload)
    sub = str(payload.get("sub", "")) if isinstance(payload, dict) else ""
    ts = int(time.time())
    sid = _scan_id(req.target, ts, sub)
    record = {"scan_id": sid, "target": req.target, "timestamp": ts,
              "org_id": oid, "owner_id": sub,
              "results": req.scan_results, "metadata": req.metadata or {}}
    out = _target_dir(req.target) / f"{sid}.json"
    out.write_text(json.dumps(record, default=str), encoding="utf-8")
    # Trigger webhooks (org-scoped inside _fire_webhooks)
    asyncio.create_task(_fire_webhooks(req.target, record))
    return {"ok": True, "scan_id": sid}

@router.get("/api/recon/scan/history")
async def list_history(target: str = Query(...), payload=Depends(verify_scan_quota)):
    oid = _caller_org(payload)
    items = []
    for f in sorted(_target_dir(target).glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
            if not _org_can_see(rec, oid):
                continue
            findings = _extract_findings(rec)
            sev_count = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
            for fn in findings:
                sev_count[fn["severity"]] = sev_count.get(fn["severity"], 0) + 1
            items.append({"scan_id":rec["scan_id"],"timestamp":rec["timestamp"],
                "date":time.strftime("%Y-%m-%d %H:%M", time.gmtime(rec["timestamp"])),
                "total_findings":len(findings),"severity_counts":sev_count})
        except Exception: continue
    return {"target":target,"scan_count":len(items),"scans":items}

def _diff_records(ra, rb, a, b):
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

@router.get("/api/recon/scan/diff")
async def diff_scans(target: str = Query(...), a: str = Query(...), b: str = Query(...),
                      payload=Depends(verify_scan_quota)):
    oid = _caller_org(payload)
    ra = _load_rec(target, a); rb = _load_rec(target, b)
    if ra is None or rb is None or not _org_can_see(ra, oid) or not _org_can_see(rb, oid):
        raise HTTPException(404, "scan_id not found")
    return _diff_records(ra, rb, a, b)

# ═════════════════════════════════════════════════════════════
# SESSION 2: Compare-to-last shortcut (auto-finds previous scan)
# ═════════════════════════════════════════════════════════════

@router.get("/api/recon/scan/diff_to_last")
async def diff_to_last(target: str = Query(...), current_scan_id: str = Query(...),
                        payload=Depends(verify_scan_quota)):
    """Find the scan immediately before current_scan_id and diff against it."""
    oid = _caller_org(payload)
    d = _target_dir(target)
    # Only consider scans this org may see, so 'previous' never crosses tenants.
    visible = []
    for f in sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        rec = _load_rec(target, f.stem)
        if rec and _org_can_see(rec, oid):
            visible.append(f.stem)
    if current_scan_id not in visible:
        raise HTTPException(404, "current scan not found")
    idx = visible.index(current_scan_id)
    if idx + 1 >= len(visible):
        return {"first_scan": True, "message": "No previous scan to compare against"}
    prev = visible[idx + 1]
    ra = _load_rec(target, prev); rb = _load_rec(target, current_scan_id)
    return _diff_records(ra, rb, prev, current_scan_id)

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
async def webhook_configure(cfg: WebhookConfig, payload=Depends(verify_scan_quota)):
    ok, reason = _url_is_safe(cfg.url)
    if not ok:
        raise HTTPException(400, f"Webhook URL rejected: {reason}")
    wid = uuid.uuid4().hex[:12]
    rec = cfg.dict()
    rec["webhook_id"] = wid
    rec["owner"] = str(payload.get("sub", ""))
    rec["org_id"] = _caller_org(payload)
    rec["created"] = int(time.time())
    (_HOOKS / f"{wid}.json").write_text(json.dumps(rec), encoding="utf-8")
    return {"ok": True, "webhook_id": wid}

@router.get("/api/recon/webhook/list")
async def webhook_list(payload=Depends(verify_scan_quota)):
    sub = str(payload.get("sub", ""))
    out = []
    for f in _HOOKS.glob("*.json"):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if str(rec.get("owner", "")) != sub:        # only the owner's webhooks
            continue
        rec.pop("secret", None)                      # never expose the HMAC secret
        out.append(rec)
    return {"count": len(out), "webhooks": out}

@router.delete("/api/recon/webhook/{webhook_id}")
async def webhook_delete(webhook_id: str, payload=Depends(verify_scan_quota)):
    if not _valid_id(webhook_id): raise HTTPException(400, "invalid webhook_id")
    f = _HOOKS / f"{webhook_id}.json"
    if not f.exists(): raise HTTPException(404)
    try:
        rec = json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        rec = {}
    if str(rec.get("owner", "")) != str(payload.get("sub", "")):
        raise HTTPException(403, "not your webhook")
    f.unlink()
    return {"ok": True}

async def _fire_webhooks(target: str, scan_record: dict):
    """Called after scan saves. Fires all matching webhooks (org-scoped)."""
    findings = _extract_findings(scan_record)
    if not findings: return
    scan_oid = scan_record.get("org_id")
    for hf in _HOOKS.glob("*.json"):
        try:
            cfg = json.loads(hf.read_text(encoding="utf-8"))
            # Org isolation: a scan only fires its own org's webhooks. Legacy
            # untagged hooks/scans (no org_id) are grandfathered so existing
            # integrations keep working.
            hook_oid = cfg.get("org_id")
            if scan_oid and hook_oid and hook_oid != scan_oid:
                continue
            # Target filter
            if cfg.get("target_filter") and cfg["target_filter"] not in target: continue
            # Severity filter
            min_sev = _SEV_ORDER.get((cfg.get("min_severity") or "MEDIUM").upper(), 2)
            filtered = [f for f in findings if _SEV_ORDER.get(f["severity"], 0) >= min_sev]
            if not filtered: continue
            # SSRF guard — re-validate the destination at fire time (DNS-rebind safe).
            ok, reason = _url_is_safe(cfg.get("url", ""))
            if not ok:
                print(f"[webhook] {hf.name} skipped: unsafe URL ({reason})")
                continue
            # Format
            payload = _format_webhook(cfg.get("format", "generic"), target,
                                      scan_record["scan_id"], filtered)
            # Sign the EXACT bytes we transmit so the receiver's HMAC verifies.
            body = json.dumps(payload, separators=(",", ":")).encode()
            headers = {"Content-Type":"application/json","User-Agent":"VulnusLab-Webhook/1.0"}
            if cfg.get("secret"):
                sig = hmac.new(cfg["secret"].encode(), body, hashlib.sha256).hexdigest()
                headers["X-VulnusLab-Signature"] = f"sha256={sig}"
            await asyncio.to_thread(requests.post, cfg["url"], data=body,
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

_MAX_SCHEDULES_PER_USER = 20

@router.post("/api/recon/schedule/create")
async def schedule_create(req: ScheduleReq, payload=Depends(verify_scan_quota)):
    if req.interval_hours < 1:
        raise HTTPException(400, "interval_hours must be >= 1")
    sub = str(payload.get("sub", ""))
    # Per-user cap — stops one account registering unbounded recurring fan-out.
    mine = 0
    for f in _SCHED.glob("*.json"):
        try:
            if str(json.loads(f.read_text(encoding="utf-8")).get("owner", "")) == sub:
                mine += 1
        except Exception:
            continue
    if mine >= _MAX_SCHEDULES_PER_USER:
        raise HTTPException(429, f"schedule limit reached ({_MAX_SCHEDULES_PER_USER})")
    sid = uuid.uuid4().hex[:12]
    rec = req.dict()
    rec["schedule_id"] = sid
    rec["owner"] = sub
    rec["org_id"] = _caller_org(payload)
    rec["created"] = int(time.time())
    rec["next_run"] = int(time.time()) + req.interval_hours * 3600
    rec["last_run"] = None
    rec["last_scan_id"] = None
    (_SCHED / f"{sid}.json").write_text(json.dumps(rec), encoding="utf-8")
    return {"ok": True, "schedule_id": sid, "next_run": rec["next_run"]}

@router.get("/api/recon/schedule/list")
async def schedule_list(payload=Depends(verify_scan_quota)):
    sub = str(payload.get("sub", ""))
    out = []
    for f in _SCHED.glob("*.json"):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if str(rec.get("owner", "")) == sub:
            out.append(rec)
    return {"count":len(out), "schedules":out}

@router.delete("/api/recon/schedule/{schedule_id}")
async def schedule_delete(schedule_id: str, payload=Depends(verify_scan_quota)):
    if not _valid_id(schedule_id): raise HTTPException(400, "invalid schedule_id")
    f = _SCHED / f"{schedule_id}.json"
    if not f.exists(): raise HTTPException(404)
    try:
        rec = json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        rec = {}
    if str(rec.get("owner", "")) != str(payload.get("sub", "")):
        raise HTTPException(403, "not your schedule")
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
                       format: str = Query("json"), payload=Depends(verify_scan_quota)):
    oid = _caller_org(payload)
    rec = _load_rec(target, scan_id)
    if rec is None or not _org_can_see(rec, oid): raise HTTPException(404)
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
