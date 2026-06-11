"""YouTube Channel v2 — VL-FORGE."""
import requests
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def gather(ctx):
    org=ctx.host.split(".")[0]
    key=os.environ.get("YOUTUBE_API_KEY","")
    ctx.state["api_key_configured"]=bool(key)
    if not key: return
    try:
        r=requests.get(f"https://www.googleapis.com/youtube/v3/search?part=snippet&q={org}&type=channel&maxResults=5&key={key}",
            timeout=12)
        if r.status_code==200:
            d=r.json()
            channels=[{"title":i["snippet"].get("title"),"id":i["snippet"].get("channelId"),
                "description":(i["snippet"].get("description") or "")[:200]} for i in d.get("items",[])]
            ctx.state["channels"]=channels; ctx.state["channel_count"]=len(channels)
            if channels: ctx.source(f"yt-{len(channels)}")
    except: pass
def _r_unkeyed(s):
    if s.get("api_key_configured"): return None
    return {"name":"YOUTUBE_API_KEY not set","severity":"INFO",
        "evidence":"Free 10k quota/day at console.cloud.google.com"}
def _r_found(s):
    n=s.get("channel_count",0)
    if n==0: return None
    return {"name":f"{n} YouTube channel(s) match brand","severity":"INFO","cwe":"T1593",
        "evidence":f"Top: {(s.get('channels') or [{}])[0].get('title','')}"}
FINDING_RULES=[_r_unkeyed,_r_found]
INTEL_FIELDS=[("API key","api_key_configured"),("Channels","channel_count")]
@router.post("/api/recon/youtube_channel")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="youtube_channel",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["channels","channel_count"])
def register(app): app.include_router(router)
