"""Hydra — Authentication brute force.

Pattern: TEMPLATE for Kali shell-out tools. Each Kali tool is wrapped
in a subprocess call. If the binary is missing, returns a clear
skipped_reason — NEVER a silent failure.
"""
import asyncio
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from tools._shared import (
    verify_scan_quota, recon_host, wrap_finding, standard_response,
)

router = APIRouter()


class HydraRequest(BaseModel):
    target: str
    service: str  # ssh / ftp / http-post-form / mysql / etc.
    userlist: Optional[str] = None       # path to userlist on backend
    passlist: Optional[str] = None       # path to wordlist on backend
    threads: int = 4


async def _run_subprocess(cmd: list, timeout: int = 120):
    """Wrap subprocess.create — same pattern as the old run_tool helper."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {"output": out.decode("utf-8", errors="replace"),
                    "returncode": proc.returncode}
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            return {"output": f"[Timeout after {timeout}s]", "returncode": -1}
    except FileNotFoundError:
        return {"output": "", "returncode": -1, "error": "hydra binary not found"}
    except Exception as e:
        return {"output": "", "returncode": -1, "error": str(e)}


@router.post("/api/password/hydra")
async def password_hydra(req: HydraRequest, user=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    cmd = ["hydra", "-t", str(req.threads)]
    if req.userlist: cmd += ["-L", req.userlist]
    if req.passlist: cmd += ["-P", req.passlist]
    cmd += [host, req.service]

    result = await _run_subprocess(cmd, timeout=180)
    out = result.get("output", "")

    if result.get("error") == "hydra binary not found":
        return standard_response(
            tool="hydra", target=req.target, findings=[],
            tests_performed=0,
            tests_summary="Hydra not installed in this image",
            skipped_reason="Hydra (kali-tools-passwords) is not installed. "
                           "Add to Dockerfile: apt-get install -y hydra",
        )

    # Parse hydra success lines: "[80][http-form-post] host: target login: X password: Y"
    findings = []
    for line in out.splitlines():
        if "login:" in line and "password:" in line:
            findings.append(wrap_finding(
                f"Weak credential found: {line.strip()}",
                "CRITICAL", cvss="9.8", cwe="CWE-521",
                cwe_name="Weak Password Requirements", owasp="A07:2021",
                remediation="Enforce strong-password policy, account lockout "
                            "after N failed attempts, MFA where possible.",
                evidence_marker=line.strip(),
            ))

    return standard_response(
        tool="hydra", target=req.target, findings=findings,
        tests_performed=1,
        tests_summary=f"Hydra brute force against {host}:{req.service}",
        raw_data={"raw_output": out[-4000:]},
    )


def register(app):
    app.include_router(router)
