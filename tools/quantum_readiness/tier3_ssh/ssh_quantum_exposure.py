"""SSH Quantum Exposure - check whether an SSH server offers a post-quantum
key exchange, and flag its quantum-vulnerable host keys.

Detection-only, zero dependency: reads the server banner + the SSH_MSG_KEXINIT
packet off the socket and parses the advertised name-lists. No login is
attempted. Advisory/LOW.

Hardened end-to-end: defensive payload import (route always registers),
gather() can never raise, endpoint always returns a valid 200 - so the scanner
can never surface as "ERROR".
"""
import asyncio
import socket

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host, standard_response
from tools._vl_core import run_scanner

try:
    from tools._payloads.quantum_readiness._loader import (
        PQC_COMPLIANCE, PQC_SSH_KEX, host_key_is_vulnerable,
    )
except Exception:                                                   # pragma: no cover
    PQC_COMPLIANCE = ("NIST IR 8547 - NSA CNSA 2.0 - NIST FIPS 203 - "
                      "NIST SC-13 - BSI TR-02102")
    PQC_SSH_KEX = {
        "mlkem768x25519-sha256", "mlkem768x25519-sha256@openssh.com",
        "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
    }

    def host_key_is_vulnerable(algo):
        a = (algo or "").lower()
        return any(v in a for v in ("rsa", "ecdsa", "ed25519", "ed448", "dss"))

router = APIRouter()
_PORT = 22


def _read_kexinit(host, port=_PORT, timeout=6):
    """(kex_algorithms[list], host_key_algorithms[list]) or (None, None)."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        banner = b""
        while b"\n" not in banner or b"SSH-" not in banner:
            chunk = s.recv(256)
            if not chunk:
                break
            banner += chunk
            if len(banner) > 4096:
                break
        s.sendall(b"SSH-2.0-VulnusLab_QR\r\n")
        data = b""
        while len(data) < 4096:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) >= 6 and data[5] == 20:
                pkt_len = int.from_bytes(data[0:4], "big")
                if len(data) >= 4 + pkt_len:
                    break
        s.close()
        pkt_len = int.from_bytes(data[0:4], "big")
        pad_len = data[4]
        payload = data[5:4 + pkt_len - pad_len]
        if not payload or payload[0] != 20:
            return None, None
        i = 1 + 16
        lists = []
        for _ in range(2):
            ln = int.from_bytes(payload[i:i + 4], "big"); i += 4
            lists.append(payload[i:i + ln].decode("ascii", "ignore").split(","))
            i += ln
        return lists[0], lists[1]
    except Exception:
        return None, None


async def gather(ctx):
    try:
        host = (ctx.host or "").strip()
        if not host:
            ctx.source("no target")
            return
        kex, hostkeys = await asyncio.to_thread(_read_kexinit, host)
        if kex is None:
            ctx.state["reachable"] = False
            ctx.source(f"{host}:{_PORT} SSH not reachable / no KEXINIT")
            return
        kex_l = [k.lower() for k in kex if k]
        has_pqc = any(k in PQC_SSH_KEX or "mlkem" in k or "sntrup" in k for k in kex_l)
        ctx.state.update({
            "reachable": True,
            "kex": kex,
            "host_keys": hostkeys,
            "pqc_kex": has_pqc,
        })
        ctx.source(f"{host}:{_PORT} kex={len(kex)} pqc_kex={has_pqc}")
    except Exception as e:
        ctx.state.setdefault("reachable", False)
        ctx.source(f"ssh_quantum_exposure error: {type(e).__name__}: {str(e)[:120]}")


def _r_no_pqc_kex(s):
    if not s.get("reachable") or s.get("pqc_kex"):
        return None
    return {"name": "SSH key exchange has no post-quantum option",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-327",
            "evidence": ("Server's offered SSH key exchange list contains only classical "
                         f"algorithms ({', '.join((s.get('kex') or [])[:4])}...). Recorded sessions "
                         "are harvest-now-decrypt-later exposed."),
            "compliance": PQC_COMPLIANCE,
            "remediation": "Enable mlkem768x25519-sha256 (OpenSSH 9.9+) as the preferred SSH KEX."}


def _r_pqc_kex_ok(s):
    if not s.get("pqc_kex"):
        return None
    return {"name": "SSH offers a post-quantum key exchange",
            "severity": "POSITIVE",
            "evidence": "Server advertises a PQC hybrid SSH KEX (mlkem/sntrup) - quantum-safe."}


def _r_host_keys(s):
    hk = s.get("host_keys") or []
    if not s.get("reachable") or not hk:
        return None
    if not any(host_key_is_vulnerable(a) for a in hk):
        return None
    return {"name": "SSH host keys are quantum-vulnerable",
            "severity": "INFO", "cwe": "CWE-327",
            "evidence": (f"Host-key algorithms ({', '.join(hk[:4])}) are RSA/ECDSA/Ed25519 - all "
                         "breakable by Shor's algorithm. No PQC SSH host-key standard exists yet."),
            "compliance": PQC_COMPLIANCE,
            "remediation": "Track the IETF PQC SSH host-key work; rotate to PQC host keys when standardised."}


FINDING_RULES = [_r_no_pqc_kex, _r_pqc_kex_ok, _r_host_keys]
INTEL_FIELDS = [("KEX algorithms", "kex"), ("Host-key algorithms", "host_keys"),
                ("PQC KEX offered", "pqc_kex")]


@router.post("/api/quantum_readiness/ssh_quantum_exposure")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await run_scanner(
            host=recon_host(req.target), tool="ssh_quantum_exposure",
            gather_func=gather, finding_rules=FINDING_RULES,
            intel_fields=INTEL_FIELDS, flat_field_keys=["pqc_kex"],
        )
    except Exception as e:
        return standard_response(
            tool="ssh_quantum_exposure", target=req.target,
            findings=[{"name": "SSH quantum-exposure probe could not complete",
                       "severity": "INFO",
                       "evidence": f"{type(e).__name__}: {str(e)[:140]}"}])


def register(app):
    app.include_router(router)
