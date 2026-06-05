"""ncrack_rdp_spray - RDP password spray via Ncrack (VL-METHOD methodology).

REWRITTEN 2026-06-05 to use the VL-METHOD 7-step pentest pattern. Mirrors
the Hydra SSH spray reference scanner; tailored to RDP/3389 specifics.

The 7 stages this scanner now performs:

  1. PRE-FLIGHT  - Parse target (strip URL/:port), TCP-connect 3389. If
                    the port is unreachable, skip with SKIPPED status -
                    no point burning cycles or ncrack subprocesses on a
                    closed Windows host.

  2. FINGERPRINT - Send a raw X.224 RDP connection request (the 19-byte
                    PDU used by mstsc) and inspect the server's response:
                      response[15] & 0x03 == 0x03  -> NLA enabled
                    Then attempt a TLS handshake on 3389 and capture the
                    cert subject CN (Windows hosts usually self-issue
                    "WIN-XYZ" hostnames) plus the RDP protocol version
                    flag. Result drives PDF hardening recommendations.

  3. QUICK PROBE - Try 5 known-bad Windows defaults BEFORE customer's
                    full wordlist, one ncrack subprocess per pair so each
                    can be confirmed independently:
                      Administrator / (blank)
                      admin / admin
                      guest / (blank)
                      user / user
                      test / test
                    Per-attempt 8s timeout (NLA hosts are slow). Total
                    budget 60s. Most leaked / fresh-installed Windows
                    hosts fall here without ever touching the deep spray.

  4. DEEP SCAN   - Only runs if quick_probe found something OR customer
                    set options.always_deep=True. Ncrack with customer's
                    full userlist/passlist (hard-clamped to 10x25),
                    --connection-limit 2 to avoid lockout, -T 4 timing,
                    240s wall-clock cap.

  5. VERIFY      - Re-run ncrack with ONLY the discovered user+pwd pair
                    via a separate subprocess. If the second attempt also
                    reports the credential, mark CONFIRMED with
                    verification_method=ncrack_second_attempt. Else mark
                    SUSPECTED (ncrack_single_attempt_unverified).

  6. PRIVILEGE   - If WinRM/5985 is open AND we have CONFIRMED creds,
                    use pywinrm to run `whoami /priv` + `whoami /groups`
                    on the host:
                      SeDebugPrivilege / SeImpersonatePrivilege -> admin
                      BUILTIN\\Administrators group        -> admin
                    Otherwise (no WinRM), fall back to username heuristic:
                      Administrator / admin -> admin
                      guest                  -> guest
                      anything else          -> user

  7. CHAIN       - For CONFIRMED admin: enqueue persistence audit + WinPEAS
                    + lateral pivot artifacts.
                    For CONFIRMED non-admin: enqueue persistence audit only.
                    Else: empty list.

Customer input via ScanRequest.options:
  - target              = RDP host/IP (required - from req.target)
  - options.userlist    = newline-separated usernames (deep_scan only)
  - options.passlist    = newline-separated passwords (deep_scan only)
  - options.port        = RDP port override (default 3389)
  - options.always_deep = bool, force deep_scan even if quick_probe empty
  - options.timeout_sec = wall-clock cap for deep ncrack (default 240)

Safety: deep_scan hard-clamped to 10 users x 25 passwords; quick_probe
fixed at 5 well-known pairs; --connection-limit=2 to dodge RDP throttle.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import socket
import ssl
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.ncrack_rdp_spray_findings import NCRACK_RDP_SPRAY_FINDING_RULES

router = APIRouter()
NCRACK_BIN = shutil.which("ncrack")
DEFAULT_TIMEOUT = 240
HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25
QUICK_PROBE_PER_ATTEMPT_TIMEOUT = 8.0
QUICK_PROBE_BUDGET = 60.0
WINRM_PORT = 5985

# Top-5 RDP credential pairs that compromised Windows hosts fall to.
QUICK_PROBE_DEFAULTS = [
    ("Administrator", ""),
    ("admin", "admin"),
    ("guest", ""),
    ("user", "user"),
    ("test", "test"),
]

# Raw 19-byte X.224 Connection Request PDU (matches mstsc.exe initial
# handshake). Server response byte 15 carries the negotiated security
# flags - 0x03 indicates NLA/CredSSP required.
X224_CR_PDU = (
    b"\x03\x00\x00\x13"          # TPKT header, length 19
    b"\x0e\xe0\x00\x00\x00\x00\x00"  # X.224 CR
    b"\x01\x00\x08\x00\x03\x00\x00\x00"  # negotiation request
)


class NcrackRdpSprayRequest(ScanRequest):
    options: Optional[dict] = None


# Ncrack success format:
#   "Discovered credentials on rdp://1.2.3.4:3389 'Administrator' 'P@ssw0rd1'"
# Older builds emit:
#   "1.2.3.4 3389/tcp rdp: 'Administrator' 'P@ssw0rd1'"
# We accept either.
_RE_SUCCESS_NEW = re.compile(
    r"Discovered credentials on rdp://(?P<host>[^:\s]+):(?P<port>\d+)\s+"
    r"'(?P<user>[^']*)'\s+'(?P<pwd>[^']*)'",
    re.IGNORECASE,
)
_RE_SUCCESS_OLD = re.compile(
    r"(?P<host>\S+)\s+(?P<port>\d+)/tcp\s+rdp:\s+'(?P<user>[^']*)'\s+'(?P<pwd>[^']*)'",
    re.IGNORECASE,
)


def _split_lines(s: str, limit: int) -> list[str]:
    """Trim + dedupe + clamp a newline-separated user/pass string."""
    if not s:
        return []
    seen: list[str] = []
    for raw in s.splitlines():
        v = raw.strip()
        if not v or v in seen:
            continue
        seen.append(v)
        if len(seen) >= limit:
            break
    return seen


def _write_tempfile(prefix: str, lines: list[str]) -> str:
    fd, path = tempfile.mkstemp(prefix=f"vl_{prefix}_", suffix=".lst")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except Exception:
        try: os.close(fd)
        except Exception: pass
        raise
    return path


def _redact(pwd: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction: length + last 3 chars only.
    When show_plaintext=True, returns the plaintext password (customer
    scanning own infra). Default False keeps the redacted marker."""
    if pwd is None:
        return "len=0"
    pwd = pwd.strip()
    if not pwd:
        return "len=0"
    if show_plaintext:
        return pwd
    if len(pwd) <= 3:
        return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-3:]}"


def _parse_ncrack_success(stdout: str) -> list[tuple[str, str, str, int]]:
    """Return list of (host, port, user, pwd) tuples discovered in stdout."""
    out: list[tuple[str, str, str, int]] = []
    for line in stdout.splitlines():
        m = _RE_SUCCESS_NEW.search(line) or _RE_SUCCESS_OLD.search(line)
        if not m:
            continue
        try:
            port_i = int(m.group("port"))
        except Exception:
            port_i = 3389
        out.append((m.group("host"), m.group("user"), m.group("pwd"), port_i))
    return out


async def _ncrack_single_pair(host: str, port: int, user: str, pwd: str,
                              timeout: float) -> tuple[bool, str]:
    """Run ncrack against a single (user, pwd) pair. Returns (success, raw_stdout)."""
    if not NCRACK_BIN:
        return (False, "")
    cmd = [
        NCRACK_BIN,
        "-p", str(port),
        "--user", user,
        "--pass", pwd,
        "-T", "3",
        f"rdp://{host}",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except Exception:
        return (False, "")
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        return (False, "")
    stdout = (out_b or b"").decode("utf-8", errors="ignore")
    success = bool(_parse_ncrack_success(stdout))
    return (success, stdout)


async def _fingerprint_rdp(host: str, port: int) -> dict:
    """Send X.224 PDU + try TLS, return fingerprint dict.
    {nla_enabled: bool, cert_cn: str, rdp_version: str, raw_response_hex: str}"""
    fp = {"nla_enabled": False, "cert_cn": "", "rdp_version": "unknown",
          "raw_response_hex": ""}

    # Stage A: raw X.224 negotiation
    def _x224_probe() -> bytes:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        try:
            s.connect((host, port))
            s.sendall(X224_CR_PDU)
            return s.recv(64)
        finally:
            try: s.close()
            except Exception: pass
    try:
        loop = asyncio.get_event_loop()
        resp = await asyncio.wait_for(loop.run_in_executor(None, _x224_probe), timeout=5.0)
        if resp:
            fp["raw_response_hex"] = resp.hex()
            # Negotiation Response is server's reply. Byte index 15 holds
            # the selected protocol flags when type byte (11) is 0x02.
            if len(resp) >= 16:
                flags = resp[15]
                if (flags & 0x03) == 0x03:
                    fp["nla_enabled"] = True
                    fp["rdp_version"] = "RDP+TLS+CredSSP/NLA"
                elif (flags & 0x01) == 0x01:
                    fp["rdp_version"] = "RDP+TLS"
                else:
                    fp["rdp_version"] = "RDP standard"
    except Exception:
        pass

    # Stage B: TLS handshake to grab cert CN (Windows hostname hint)
    def _tls_probe() -> str:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        try:
            s.connect((host, port))
            # Repeat X.224 to coax server into TLS upgrade
            s.sendall(X224_CR_PDU)
            try:
                _ = s.recv(64)
            except Exception:
                pass
            wrapped = ctx.wrap_socket(s, server_hostname=host)
            cert = wrapped.getpeercert(binary_form=False) or {}
            subj = cert.get("subject") or ()
            for rdn in subj:
                for k, v in rdn:
                    if k.lower() == "commonname":
                        return v
            return ""
        finally:
            try: s.close()
            except Exception: pass
    try:
        loop = asyncio.get_event_loop()
        cn = await asyncio.wait_for(loop.run_in_executor(None, _tls_probe), timeout=6.0)
        if cn:
            fp["cert_cn"] = cn
    except Exception:
        pass

    return fp


async def _winrm_priv_check(host: str, user: str, pwd: str) -> str:
    """Use pywinrm to run whoami /priv + /groups. Returns 'admin' | 'user' | ''."""
    try:
        import winrm  # pywinrm
    except ImportError:
        return ""

    def _probe() -> str:
        try:
            sess = winrm.Session(
                f"http://{host}:{WINRM_PORT}/wsman",
                auth=(user, pwd),
                transport="ntlm",
                read_timeout_sec=10,
                operation_timeout_sec=8,
            )
            priv_out = ""
            grp_out = ""
            try:
                r = sess.run_cmd("whoami /priv")
                priv_out = (r.std_out or b"").decode("utf-8", errors="ignore")
            except Exception:
                pass
            try:
                r = sess.run_cmd("whoami /groups")
                grp_out = (r.std_out or b"").decode("utf-8", errors="ignore")
            except Exception:
                pass
            combined = (priv_out + "\n" + grp_out).lower()
            if ("sedebugprivilege" in combined
                    or "seimpersonateprivilege" in combined
                    or "builtin\\administrators" in combined
                    or "s-1-5-32-544" in combined):
                return "admin"
            if combined.strip():
                return "user"
            return ""
        except Exception:
            return ""

    try:
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(loop.run_in_executor(None, _probe), timeout=14.0)
    except Exception:
        return ""


def _classify_by_username(user: str) -> str:
    u = (user or "").lower()
    if u in ("administrator", "admin"):
        return "admin"
    if u in ("guest",):
        return "guest"
    if not u:
        return "unknown"
    return "user"


# ═══════════════════════════════════════════════════════════════════
#  NcrackRdpSpray - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class NcrackRdpSpray(MethodologyScanner):
    name = "ncrack_rdp_spray"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = ctx.host
        opts = ctx.state.get("_options") or {}
        port_arg = int(opts.get("port") or 3389)
        clean_host, parsed_port = helpers.split_host_port(target, default_port=port_arg)
        port = parsed_port if parsed_port else port_arg
        ctx.state["target_host"] = clean_host
        ctx.state["target_port"] = port
        if not clean_host:
            ctx.state["skipped_reason"] = "no target supplied"
            return False
        reachable = await helpers.port_open(clean_host, port, timeout=3.0)
        ctx.state["port_reachable"] = reachable
        if not reachable:
            ctx.state["skipped_reason"] = (
                f"RDP/{port} on {clean_host} not reachable (port closed or filtered)"
            )
            return False
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 3389)
        fp = await _fingerprint_rdp(host, port)
        ctx.state["fingerprint"] = fp
        ctx.state["nla_enabled"] = bool(fp.get("nla_enabled"))

    # ── STAGE 3: QUICK PROBE (5 known defaults via ncrack) ───────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 3389)
        ctx.state["quick_probe_attempts"] = 0
        ctx.state["quick_probe_hits"] = 0
        if not NCRACK_BIN:
            ctx.state["ncrack_missing"] = True
            return []

        show = bool((ctx.state.get("_options") or {}).get("show_plaintext"))
        findings: list[dict] = []
        loop = asyncio.get_event_loop()
        budget_start = loop.time()
        attempts = 0
        for i, (user, pwd) in enumerate(QUICK_PROBE_DEFAULTS):
            if loop.time() - budget_start > QUICK_PROBE_BUDGET:
                break
            attempts += 1
            success, _stdout = await _ncrack_single_pair(
                host, port, user, pwd, timeout=QUICK_PROBE_PER_ATTEMPT_TIMEOUT)
            if success:
                findings.append({
                    "id": f"quick_{i}",
                    "kind": "default_credential",
                    "user": user,
                    "password_marker": _redact(pwd, show_plaintext=show),
                    "discovery_method": "quick_probe_known_defaults",
                    "host": host,
                    "port": port,
                    # Stash the actual password under a private key so verify+
                    # privilege_check can re-use it without leaking via output.
                    "_pwd_private": pwd,
                })
        ctx.state["quick_probe_attempts"] = attempts
        ctx.state["quick_probe_hits"] = len(findings)
        return findings

    # ── STAGE 4: DEEP SCAN (full ncrack spray, gated) ────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        if not NCRACK_BIN:
            ctx.state["ncrack_missing"] = True
            return []
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 3389)
        opts = ctx.state.get("_options") or {}
        userlist_raw = (opts.get("userlist") or "").strip()
        passlist_raw = (opts.get("passlist") or "").strip()
        if not userlist_raw or not passlist_raw:
            ctx.state["deep_skipped"] = "userlist/passlist not supplied"
            return []
        max_users = min(int(opts.get("max_users") or HARD_MAX_USERS), HARD_MAX_USERS)
        max_pass = min(int(opts.get("max_passwords") or HARD_MAX_PASSWORDS),
                       HARD_MAX_PASSWORDS)
        users = _split_lines(userlist_raw, max_users)
        passwords = _split_lines(passlist_raw, max_pass)
        if not users or not passwords:
            ctx.state["deep_skipped"] = "empty wordlists after dedupe"
            return []
        timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), 600)

        user_path = pass_path = None
        try:
            user_path = _write_tempfile("users", users)
            pass_path = _write_tempfile("passwords", passwords)
            cmd = [
                NCRACK_BIN,
                "-U", user_path,
                "-P", pass_path,
                "-p", str(port),
                "--connection-limit", "2",
                "-T", "4",
                f"rdp://{host}",
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE)
            except Exception as e:
                ctx.state["deep_skipped"] = f"ncrack spawn failed: {type(e).__name__}"
                return []
            try:
                out_b, _err_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                try: proc.kill()
                except Exception: pass
                ctx.state["deep_skipped"] = f"ncrack timeout @ {timeout}s"
                return []
            stdout = (out_b or b"").decode("utf-8", errors="ignore")
            ctx.state["ncrack_attempts"] = len(users) * len(passwords)
            ctx.state["ncrack_users_tried"] = len(users)
            ctx.state["ncrack_passwords_tried"] = len(passwords)
            show = bool((ctx.state.get("_options") or {}).get("show_plaintext"))
            findings: list[dict] = []
            for i, (h, u, p, prt) in enumerate(_parse_ncrack_success(stdout)):
                findings.append({
                    "id": f"deep_{i}",
                    "kind": "spray_credential",
                    "user": u,
                    "password_marker": _redact(p, show_plaintext=show),
                    "discovery_method": "ncrack_deep_spray",
                    "host": h or host,
                    "port": prt or port,
                    "_pwd_private": p,
                })
            return findings
        finally:
            for p in (user_path, pass_path):
                if p:
                    try: os.unlink(p)
                    except Exception: pass

    # ── STAGE 5: VERIFY (second ncrack attempt) ──────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        host = finding.get("host") or ctx.state.get("target_host") or ctx.host
        port = int(finding.get("port") or ctx.state.get("target_port") or 3389)
        user = finding.get("user", "")
        pwd = finding.get("_pwd_private", "")

        if not NCRACK_BIN:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "ncrack_missing_cannot_verify"
            return finding

        try:
            success, _ = await _ncrack_single_pair(
                host, port, user, pwd, timeout=QUICK_PROBE_PER_ATTEMPT_TIMEOUT + 2.0)
        except Exception:
            success = False

        if success:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "ncrack_second_attempt"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "ncrack_single_attempt_unverified"
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        host = finding.get("host") or ctx.state.get("target_host") or ctx.host
        user = finding.get("user", "")
        pwd = finding.get("_pwd_private", "")
        confirmed = finding.get("confidence") == "CONFIRMED"

        winrm_open = False
        if confirmed:
            winrm_open = await helpers.port_open(host, WINRM_PORT, timeout=2.5)
        finding["winrm_reachable"] = winrm_open

        priv = ""
        if confirmed and winrm_open and pwd is not None:
            priv = await _winrm_priv_check(host, user, pwd)
            if priv:
                finding["privilege_source"] = "winrm_whoami"

        if not priv:
            priv = _classify_by_username(user)
            finding.setdefault("privilege_source", "username_heuristic")

        finding["privilege_level"] = priv

        # Strip the private password before exposing finding to UI / PDF
        finding.pop("_pwd_private", None)
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext,
                            findings: list[dict]) -> list[str]:
        confirmed_admin = any(
            f.get("confidence") == "CONFIRMED" and f.get("privilege_level") == "admin"
            for f in findings
        )
        if confirmed_admin:
            return [
                "post_exploit_windows_persistence_audit",
                "privesc_winpeas_check",
                "post_exploit_lateral_pivot_artifacts",
            ]
        any_confirmed = any(f.get("confidence") == "CONFIRMED" for f in findings)
        if any_confirmed:
            return ["post_exploit_windows_persistence_audit"]
        return []


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper - adapts MethodologyScanner to existing framework
# ═══════════════════════════════════════════════════════════════════


INTEL_FIELDS = [
    ("Stage timings (ms)",        "stage_timings"),
    ("Target host",               "target_host"),
    ("Target port",               "target_port"),
    ("Port reachable",            "port_reachable"),
    ("RDP fingerprint",           "fingerprint"),
    ("NLA enabled",               "nla_enabled"),
    ("Quick-probe attempts",      "quick_probe_attempts"),
    ("Quick-probe hits",          "quick_probe_hits"),
    ("Ncrack deep attempts",      "ncrack_attempts"),
    ("Methodology findings",      "methodology_findings"),
    ("Chain handoff next",        "chain_next"),
    ("Stage errors",              "stage_errors"),
]


@router.post("/api/password/ncrack_rdp_spray")
async def password_ncrack_rdp_spray(req: NcrackRdpSprayRequest,
                                     _=Depends(verify_scan_quota)):
    scanner = NcrackRdpSpray()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=NCRACK_RDP_SPRAY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
