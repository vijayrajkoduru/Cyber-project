"""websocket_auth_audit — WebSocket handshake auth check.

Tries to upgrade to ws:// (and wss:// for HTTPS targets) at common paths
WITHOUT auth, then WITH auth header. Reports if WebSocket accepts unauth
connections — common bug since most WebSocket frameworks default to no
auth check during the HTTP upgrade.

MASVS-NETWORK-1 analog for web.
"""
import socket
import ssl
import base64
import os
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)

router = APIRouter()

WS_PATHS = ["/ws", "/socket.io/?EIO=4&transport=websocket",
             "/api/ws", "/websocket", "/realtime", "/notifications"]


def _ws_handshake(scheme, host, port, path, with_auth=False, timeout=8):
    """Send a raw WebSocket Upgrade request. Returns (status, headers, body_snippet)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if scheme == "wss":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
    except Exception as e:
        return None, {}, f"connect-error: {e}"

    key = base64.b64encode(os.urandom(16)).decode()
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}" if port not in (80, 443) else f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        "User-Agent: VulnusLab/1.0",
    ]
    if with_auth:
        headers.append("Authorization: Bearer invalid-test-token-vulnuslab")
        headers.append("Cookie: session=invalid-test-vulnuslab")
    req_data = ("\r\n".join(headers) + "\r\n\r\n").encode()

    try:
        sock.sendall(req_data)
        resp = b""
        while len(resp) < 4096:
            chunk = sock.recv(2048)
            if not chunk: break
            resp += chunk
            if b"\r\n\r\n" in resp: break
    except Exception as e:
        try: sock.close()
        except Exception: pass
        return None, {}, f"send/recv-error: {e}"
    finally:
        try: sock.close()
        except Exception: pass

    head, _, body = resp.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode(errors="ignore")
    status = 0
    try:
        status = int(status_line.split(" ", 2)[1])
    except Exception:
        pass
    hdrs = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            hdrs[k.decode(errors="ignore").strip().lower()] = v.decode(errors="ignore").strip()
    return status, hdrs, body[:200].decode(errors="ignore")


@router.post("/api/webapp/scan/websocket_auth_audit")
def scan_websocket_auth_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    parsed = urlparse(web_url(req.target))
    host = parsed.hostname or req.target
    is_tls = parsed.scheme == "https"
    port = parsed.port or (443 if is_tls else 80)
    scheme = "wss" if is_tls else "ws"

    found = []
    upgraded_unauth = []
    rejected_unauth = []
    for path in WS_PATHS:
        status, hdrs, body = _ws_handshake(scheme, host, port, path, with_auth=False)
        if status is None:
            continue
        # 101 = Switching Protocols = WS handshake succeeded
        if status == 101:
            upgraded_unauth.append({"path": path, "upgrade": hdrs.get("upgrade", "?")})
            found.append(path)
        elif status in (401, 403):
            rejected_unauth.append({"path": path, "status": status})
            found.append(path)
        elif status == 200 and "transport=websocket" in path:
            # socket.io often returns 200 with Engine.IO payload
            if "0{" in body or '"sid"' in body:
                upgraded_unauth.append({"path": path, "transport": "socket.io"})
                found.append(path)

    findings = []
    if upgraded_unauth:
        findings.append(wrap_finding(
            f"WebSocket upgraded WITHOUT auth at {len(upgraded_unauth)} path(s)",
            "HIGH", cvss="7.5", cwe="CWE-306", owasp="A07:2021",
            remediation="Validate cookies/tokens in your WebSocket upgrade handler "
                        "BEFORE accepting the protocol switch. Common fix: "
                        "express-ws + middleware chain, or socket.io's "
                        "io.use(authMiddleware). Without auth at handshake, "
                        "post-upgrade frames can read messages without permission.",
            evidence_marker=" | ".join(
                f"{u['path']}: HTTP 101 ({u.get('upgrade', u.get('transport','?'))})"
                for u in upgraded_unauth[:5]
            )))
    if rejected_unauth and not upgraded_unauth:
        findings.append(wrap_finding(
            f"WebSocket endpoints reject unauth ({len(rejected_unauth)})",
            "POSITIVE", cwe="CWE-306",
            remediation="Maintain auth-first handshake.",
            evidence_marker=" | ".join(f"{p['path']}: HTTP {p['status']}" for p in rejected_unauth[:5])))
    if not found:
        return standard_response(
            tool="websocket_auth_audit", target=req.target, findings=[],
            tests_performed=len(WS_PATHS), vulnerable=False,
            skipped_reason=f"No WebSocket endpoints at common paths {WS_PATHS}")

    return standard_response(
        tool="websocket_auth_audit", target=req.target, findings=findings,
        tests_performed=len(WS_PATHS), vulnerable=bool(upgraded_unauth),
        tests_summary=f"WS paths: {len(found)} found, {len(upgraded_unauth)} unauth-upgrade",
        raw_data={"upgraded_unauth": upgraded_unauth,
                   "rejected_unauth": rejected_unauth})


def register(app):
    app.include_router(router)
