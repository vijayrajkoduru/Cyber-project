"""OSINT & Threat Intel module — Kali-style isolated scanners.

Each /api/osint/<tool> endpoint lives in its own file. Patterns:

  tools/osint/<tool>.py
    router = APIRouter()
    @router.post("/api/osint/<tool>")
    async def scan_<tool>(req: ScanRequest, _=Depends(verify_scan_quota)):
        ...
        return standard_response(tool="<tool>", ...)
    def register(app): app.include_router(router)

The autoloader in main.py picks up every file dropped into this directory.
One scanner's failure can't crash the platform (exception-isolated import).

Frontend module: OsintModule in src/App.js (uses ModuleShell pattern).
Per-module orchestrator: endpoints/osint_orchestrator.py (when added).
"""
