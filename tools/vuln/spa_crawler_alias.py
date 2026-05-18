"""Alias: /api/scan/spa_crawler → tools.webapp.spa_crawler.webapp_spa_crawler

Lets the WebApp module's /api/scan/* tile grid call the headless-browser
crawler without changing its URL scheme. If the webapp module is missing
(unlikely after rebuild), this file responds with a clean skipped_reason
instead of returning 404 and breaking the tile.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, standard_response

router = APIRouter()


@router.post("/api/scan/spa_crawler")
async def scan_spa_crawler(req: ScanRequest, payload=Depends(verify_scan_quota)):
    try:
        from tools.webapp.spa_crawler import webapp_spa_crawler
    except Exception as e:
        return standard_response(
            tool="spa_crawler", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=f"SPA crawler module not available: {e}",
            raw_data={"spa_crawler": {"error": str(e)[:200]}})
    return await webapp_spa_crawler(req, payload)


def register(app):
    app.include_router(router)
