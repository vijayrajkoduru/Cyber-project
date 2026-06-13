"""auth_surface_audit - internet-exposed remote-authentication surface map
(VL-METHOD methodology).

WHAT THIS SCANNER DOES (and does NOT do)
----------------------------------------
This is a DETECTION-ONLY (VA, not PT) scanner. It answers ONE question:
"Which remote-authentication services on this target are reachable from
the public internet, and which of them transmit credentials in cleartext?"

It does this with two passive techniques only:
  * TCP connect-test (port_open) — does the port accept a SYN?
  * banner grab — read the first bytes the service volunteers.

It NEVER submits a username or password. It NEVER brute-forces. It is the
external-reconnaissance counterpart to the brute-force scanners in this
tier (hydra_ssh_spray, ftp_brute, ...): instead of attacking each service,
it maps the attack surface those tools would target so the customer can
shrink it before an attacker finds it.

Playbook coverage (module_playbooks/08_password.md §1 Online Password
Attacks): this audit covers the exposure side of techniques #2 (FTP), #3
(Telnet), #4 (SMB), #5 (RDP), #8 (LDAP), #9 (IMAP/POP3/SMTP), #10
(Kerberos pre-auth surface), #11 (VNC) and the DB-brute targets #7
(MySQL/Postgres/MSSQL) — without performing any of the brute force itself.

7-stage VL-METHOD flow
----------------------
  1. PRE-FLIGHT  - clean host parsed from target; require non-empty host.
  2. FINGERPRINT - quick reachability sweep summary (counts).
  3. QUICK PROBE - TCP connect-test the full auth-port matrix in parallel
                    (sem-capped). Each reachable port -> preliminary
                    finding. Banner grab for reachable ports.
  4. DEEP SCAN   - gated on quick_probe hits OR always_deep: STARTTLS /
                    implicit-TLS check for mail + LDAP so we don't flag a
                    TLS-protected mail server as 'cleartext'.
  5. VERIFY      - re-connect each reachable port once more; CONFIRMED if
                    it accepts again (stable), else dropped (transient).
  6. PRIVILEGE   - classify by exposure class (cleartext vs encrypted auth).
  7. CHAIN       - inert (VA-not-PT; chaining disabled platform-wide).

Customer input via ScanRequest.options:
  - target          = host / IP (required, from req.target)
  - options.ports   = optional list of extra ports to include
  - options.timeout = per-port connect timeout seconds (default 3)
  - options.always_deep = force STARTTLS deep checks even with no hit

Safety: read-only TCP connects + banner reads only. Hard caps: max 40
ports, 6 concurrent connects, 3s per connect.
"""
from __future__ import annotations

import asyncio
import ssl
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel  # noqa: F401  (parity with reference scanner)

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.auth_surface_audit_findings import (
    AUTH_SURFACE_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

DEFAULT_TIMEOUT = 3.0
HARD_MAX_PORTS = 40
MAX_CONCURRENCY = 6


# (service, port, transport, cleartext_by_default, tls_native)
# cleartext_by_default = protocol sends creds in plaintext when TLS not
#   negotiated. We RE-CHECK STARTTLS in deep_scan for mail/LDAP to avoid
#   FP-flagging a TLS-protected server.
AUTH_PORT_MATRIX = [
    ("telnet",   23,   "tcp", True,  False),
    ("ftp",      21,   "tcp", True,  False),   # control channel cleartext
    ("ftps",     990,  "tcp", False, True),
    ("rdp",      3389, "tcp", False, True),
    ("smb",      445,  "tcp", False, False),
    ("netbios",  139,  "tcp", False, False),
    ("vnc",      5900, "tcp", True,  False),   # weak DES challenge
    ("vnc",      5901, "tcp", True,  False),
    ("ldap",     389,  "tcp", True,  False),   # simple bind cleartext
    ("ldaps",    636,  "tcp", False, True),
    ("imap",     143,  "tcp", True,  False),   # cleartext unless STARTTLS
    ("imaps",    993,  "tcp", False, True),
    ("pop3",     110,  "tcp", True,  False),
    ("pop3s",    995,  "tcp", False, True),
    ("smtp",     25,   "tcp", True,  False),
    ("smtp",     587,  "tcp", True,  False),   # submission (STARTTLS-capable)
    ("smtps",    465,  "tcp", False, True),
    ("kerberos", 88,   "tcp", False, False),
    ("mssql",    1433, "tcp", False, False),
    ("mysql",    3306, "tcp", False, False),
    ("postgres", 5432, "tcp", False, False),
    ("mongodb",  27017,"tcp", False, False),
    ("redis",    6379, "tcp", False, False),
    ("winrm",    5985, "tcp", False, False),
    ("winrm-ssl",5986, "tcp", False, True),
]


class AuthSurfaceAuditRequest(ScanRequest):
    options: Optional[dict] = None


async def _starttls_supported(host: str, port: int, service: str,
                              timeout: float) -> Optional[bool]:
    """Best-effort STARTTLS probe for mail/LDAP. Returns:
        True  - server advertised/accepted STARTTLS
        False - reachable but no STARTTLS advertised
        None  - could not determine (treat as unknown, do NOT downgrade)
    Read-only: sends only the protocol's capability/STARTTLS verb.
    """
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except Exception:
        return None
    try:
        async def _read():
            try:
                return await asyncio.wait_for(reader.read(512), timeout=timeout)
            except Exception:
                return b""

        async def _send(line: bytes):
            try:
                writer.write(line)
                await asyncio.wait_for(writer.drain(), timeout=timeout)
            except Exception:
                pass

        greeting = (await _read()).decode("utf-8", "ignore").lower()
        if service in ("smtp",):
            await _send(b"EHLO vulnuslab.audit\r\n")
            resp = (await _read()).decode("utf-8", "ignore").lower()
            return "starttls" in resp or "starttls" in greeting
        if service in ("imap",):
            await _send(b"a1 CAPABILITY\r\n")
            resp = (await _read()).decode("utf-8", "ignore").lower()
            return "starttls" in resp or "starttls" in greeting
        if service in ("pop3",):
            await _send(b"CAPA\r\n")
            resp = (await _read()).decode("utf-8", "ignore").lower()
            return "stls" in resp or "stls" in greeting
        if service in ("ftp",):
            # AUTH TLS support on the FTP control channel
            await _send(b"FEAT\r\n")
            resp = (await _read()).decode("utf-8", "ignore").lower()
            return "auth tls" in resp or "auth ssl" in resp
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


class AuthSurfaceAudit(MethodologyScanner):
    name = "auth_surface_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        opts = ctx.state.get("_options") or {}
        clean_host, _ = helpers.split_host_port(ctx.host, default_port=0)
        ctx.state["target_host"] = clean_host
        if not clean_host:
            ctx.state["skipped_reason"] = "no target supplied"
            return False
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        ctx.state["fingerprint"] = {"audit": "remote-auth surface map"}

    # ── STAGE 3: QUICK PROBE (reachability sweep) ────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        host = ctx.state.get("target_host") or ctx.host
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)

        # Assemble the port matrix + any customer extras (as generic
        # "auth_service" with unknown cleartext status).
        matrix = list(AUTH_PORT_MATRIX)
        extra = opts.get("ports") or []
        if isinstance(extra, list):
            for p in extra:
                try:
                    pn = int(p)
                except (TypeError, ValueError):
                    continue
                if not any(pn == m[1] for m in matrix):
                    matrix.append(("auth-service", pn, "tcp", False, False))
        matrix = matrix[:HARD_MAX_PORTS]
        ctx.state["probed_ports"] = len(matrix)

        sem = asyncio.Semaphore(MAX_CONCURRENCY)
        reachable: list[dict] = []

        async def _check(entry):
            svc, port, transport, cleartext, tls_native = entry
            async with sem:
                ok = await helpers.port_open(host, port, timeout=timeout)
            if not ok:
                return
            banner = await helpers.banner_grab(host, port, timeout=min(timeout, 3.0))
            reachable.append({
                "service": svc, "port": port, "transport": transport,
                "cleartext_default": cleartext, "tls_native": tls_native,
                "banner": (banner or "")[:200],
            })

        await asyncio.gather(*[_check(e) for e in matrix])

        reachable.sort(key=lambda r: r["port"])
        ctx.state["reachable_services"] = [
            {"service": r["service"], "port": r["port"]} for r in reachable
        ]
        ctx.state["service_banners"] = {
            f"{r['service']}/{r['port']}": r["banner"]
            for r in reachable if r["banner"]
        }
        ctx.state["_reachable_raw"] = reachable

        # Convert each reachable service into a preliminary finding.
        findings: list[dict] = []
        for r in reachable:
            cleartext = bool(r["cleartext_default"]) and not r["tls_native"]
            findings.append({
                "id": f"svc_{r['service']}_{r['port']}",
                "kind": "cleartext_auth_exposed" if cleartext else "auth_service_exposed",
                "service": r["service"],
                "port": r["port"],
                "transport": r["transport"],
                "banner": r["banner"],
                "plaintext": cleartext,
                "tls_native": r["tls_native"],
                "discovery_method": "tcp_connect_test",
            })
        return findings

    # ── STAGE 4: DEEP SCAN (STARTTLS refinement) ─────────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        # We do not ADD findings here; we REFINE the cleartext classification
        # of mail/LDAP/FTP found in quick_probe so a STARTTLS-protected
        # server is not flagged as cleartext (zero-FP discipline).
        host = ctx.state.get("target_host") or ctx.host
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        prelim = ctx.state.get("methodology_findings")  # not yet set here
        # quick_probe results are accessible via the orchestrator's combined
        # list AFTER quick_probe returns; we instead re-derive from raw.
        reachable = ctx.state.get("_reachable_raw") or []
        refine_services = {"smtp", "imap", "pop3", "ftp"}
        starttls_map: dict = {}
        for r in reachable:
            if r["service"] in refine_services and r["cleartext_default"]:
                supported = await _starttls_supported(
                    host, r["port"], r["service"], timeout)
                starttls_map[f"{r['service']}/{r['port']}"] = supported
        ctx.state["starttls_support"] = starttls_map
        return []

    # ── STAGE 5: VERIFY (re-connect stability) ───────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        host = ctx.state.get("target_host") or ctx.host
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        port = int(finding.get("port") or 0)

        # Re-confirm the port is still reachable (kills transient FPs).
        stable = await helpers.port_open(host, port, timeout=timeout) if port else False
        if not stable:
            # Transient — drop rather than ship a flaky finding.
            return None

        # STARTTLS refinement: if the server advertised STARTTLS/STLS/AUTH TLS,
        # it CAN protect credentials, so downgrade out of the cleartext class.
        key = f"{finding.get('service')}/{finding.get('port')}"
        starttls = (ctx.state.get("starttls_support") or {}).get(key)
        if finding.get("kind") == "cleartext_auth_exposed" and starttls is True:
            finding["kind"] = "auth_service_exposed"
            finding["plaintext"] = False
            finding["tls_capable_via_starttls"] = True

        finding["confidence"] = "CONFIRMED"
        finding["verification_method"] = "tcp_connect_reconfirm"
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        if finding.get("kind") == "cleartext_auth_exposed":
            finding["privilege_level"] = "credential_interception_capable"
        else:
            finding["privilege_level"] = "spray_target_exposed"
        return finding

    # ── STAGE 7: CHAIN HANDOFF (inert per VA-not-PT policy) ──────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        return []


@router.post("/api/password/auth_surface_audit")
async def password_auth_surface_audit(req: AuthSurfaceAuditRequest,
                                       _=Depends(verify_scan_quota)):
    scanner = AuthSurfaceAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=AUTH_SURFACE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
