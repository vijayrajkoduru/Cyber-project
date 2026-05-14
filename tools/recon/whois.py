"""WHOIS Lookup — Pure-Python via python-whois.

Pattern: this file is the TEMPLATE for all recon tools.
  1. Import shared helpers
  2. Define endpoint
  3. Export register(app) — main.py auto-discovers this
"""
from fastapi import APIRouter, Depends
import whois as _whois_lib

from tools._shared import (
    ScanRequest, verify_token, recon_host, standard_response,
)

router = APIRouter()


@router.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, user=Depends(verify_token)):
    host = recon_host(req.target)
    try:
        w = _whois_lib.whois(host)
        raw = str(w.text or w)
        return standard_response(
            tool="whois",
            target=req.target,
            findings=[],
            tests_performed=1,
            tests_summary="1 WHOIS lookup via python-whois",
            raw_data={
                "registrar":    getattr(w, "registrar", None),
                "created":      str(getattr(w, "creation_date", None)) or None,
                "expires":      str(getattr(w, "expiration_date", None)) or None,
                "updated":      str(getattr(w, "updated_date", None)) or None,
                "name_servers": getattr(w, "name_servers", []) or [],
                "country":      getattr(w, "country", None),
                "raw_output":   raw,
            },
        )
    except Exception as e:
        return standard_response(
            tool="whois", target=req.target, findings=[],
            tests_performed=1, tests_summary="WHOIS lookup attempted",
            skipped_reason=f"WHOIS lookup failed: {e}",
        )


def register(app):
    app.include_router(router)
