"""Web Screenshot - capture a CONTEXT snapshot of the live target homepage.

This is a "here is what the site looks like" image, NOT finding-specific proof.
Per-finding visual proof (source maps, exposed panels, directory listings) is
captured by each scanner via tools._vl_core.proof_capture.capture_proof, which
re-verifies the finding signal + SPA canary before screenshotting. This probe
just gives the report a contextual snapshot of the front door.

Detection-only: it loads the public homepage and never logs in or sends attack
traffic. Degrades silently when headless Chromium is not installed.
"""
import asyncio

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.proof_capture import capture_context

router = APIRouter()


async def gather(ctx):
    host = (ctx.host or "").strip()
    if not host:
        ctx.source("no target")
        return
    url = f"https://{host}/"
    shot = await asyncio.to_thread(capture_context, url)
    if not shot:
        url = f"http://{host}/"
        shot = await asyncio.to_thread(capture_context, url)
    ctx.state["shot"] = shot
    ctx.state["shot_url"] = url
    ctx.source(
        f"context snapshot {'captured' if shot else 'unavailable (headless Chromium not installed)'} "
        f"for {host}"
    )


def _r_shot(s):
    shot = s.get("shot")
    if not shot:
        return None
    return {
        "name": "Target homepage snapshot (context)",
        "severity": "INFO",
        "evidence": f"Contextual screenshot of the live homepage at {s.get('shot_url')}.",
        "screenshot": shot,
        "screenshot_caption": "Context only - a snapshot of the target's front door, not "
                              "proof of a specific finding.",
    }


FINDING_RULES = [_r_shot]
INTEL_FIELDS = [("Snapshot URL", "shot_url")]


@router.post("/api/recon/web_screenshot")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=recon_host(req.target), tool="web_screenshot",
        gather_func=gather, finding_rules=FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
