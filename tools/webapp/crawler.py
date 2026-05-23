"""Webapp module - crawler: BFS web crawler
Route: POST /api/webapp/crawler
Thin alias of tools.recon.crawl.recon_crawl for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/crawler")
async def webapp_crawler(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.crawl import recon_crawl as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
