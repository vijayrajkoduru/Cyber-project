"""websocket_message_size_dos — WS connection accepts giant frame.

WebSocket servers must cap incoming frame size. Without cap, attacker
sends a single 100MB frame → server allocates buffer + crashes (or DoS).

Opens WS connection at common paths (/ws, /socket.io) then sends a
large frame. Records server response (close-frame with policy violation
= good; connection-hang or huge memory consumption = bad).
"""
import socket
import ssl
import struct
import base64
import os
import time
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

WS_PATHS = ["/ws", "/socket.io/?EIO=4&transport=websocket",
             "/websocket", "/realtime"]


def _ws_handshake(scheme, host, port, path, timeout=8):
    """Open WebSocket, return (socket, success_bool)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if scheme == "wss":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        return None, False
    key = base64.b64encode(os.urandom(16)).decode()
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket", "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13",
        "User-Agent: VulnusLab/1.0",
    ]
    try:
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
        resp = b""
        while len(resp) < 4096:
            chunk = sock.recv(2048)
            if not chunk: break
            resp += chunk
            if b"\r\n\r\n" in resp: break
        if b"101" not in resp.split(b"\r\n", 1)[0]:
            sock.close()
            return None, False
        return sock, True
    except Exception:
        try: sock.close()
        except Exception: pass
        return None, False


def _send_large_text_frame(sock, size_kb=512):
    """Send a single text frame of size_kb KB. Returns (server_closed, elapsed_ms)."""
    payload = (b"V" * (size_kb * 1024))
    payload_len = len(payload)
    # Build frame: FIN=1 + opcode=1 (text), mask=1, len in extended form
    header = bytearray([0x81])  # FIN+text
    if payload_len < 126:
        header.append(0x80 | payload_len)
    elif payload_len < 65536:
        header.append(0x80 | 126)
        header += struct.pack(">H", payload_len)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", payload_len)
    mask = os.urandom(4)
    header += mask
    masked = bytearray(payload)
    for i in range(len(masked)):
        masked[i] ^= mask[i % 4]

    t0 = time.time()
    try:
        sock.sendall(bytes(header) + bytes(masked))
        # Read response (close frame should arrive quickly if rejected)
        sock.settimeout(8)
        resp = b""
        try:
            while len(resp) < 1024:
                chunk = sock.recv(1024)
                if not chunk: break
                resp += chunk
        except socket.timeout:
            pass
        elapsed = int((time.time() - t0) * 1000)
        # 0x88 = close opcode
        server_closed = bool(resp and resp[0] == 0x88)
        return server_closed, elapsed, len(resp)
    except Exception:
        return False, int((time.time() - t0) * 1000), 0


@router.post("/api/webapp/scan/websocket_message_size_dos")
@vl_turbo()
def scan_websocket_message_size_dos(req: ScanRequest, payload=Depends(verify_scan_quota)):
    parsed = urlparse(web_url(req.target))
    host = parsed.hostname or req.target
    is_tls = parsed.scheme == "https"
    port = parsed.port or (443 if is_tls else 80)
    scheme = "wss" if is_tls else "ws"

    accepted_giant = []
    rejected = []
    no_ws = True

    for path in WS_PATHS:
        sock, ok = _ws_handshake(scheme, host, port, path)
        if not ok or sock is None: continue
        no_ws = False
        try:
            closed, elapsed, resp_len = _send_large_text_frame(sock, size_kb=512)
        finally:
            try: sock.close()
            except Exception: pass

        if closed:
            rejected.append({"path": path, "elapsed_ms": elapsed})
        elif elapsed > 6000:
            # Hung — could be DoS
            accepted_giant.append({"path": path, "elapsed_ms": elapsed,
                                     "response_size": resp_len,
                                     "issue": "hang"})
        else:
            accepted_giant.append({"path": path, "elapsed_ms": elapsed,
                                     "response_size": resp_len,
                                     "issue": "accepted-512KB-frame"})

    if no_ws:
        return standard_response(
            tool="websocket_message_size_dos", target=req.target, findings=[],
            tests_performed=len(WS_PATHS), vulnerable=False,
            skipped_reason="No WebSocket endpoints at common paths")

    findings = []
    if accepted_giant:
        findings.append(wrap_finding(
            f"WebSocket accepts 512KB frame at {len(accepted_giant)} endpoint(s) — DoS surface",
            "MEDIUM", cvss="5.3", cwe="CWE-409", owasp="A04:2021",
            remediation="Configure WebSocket frame-size limit. Common defaults: "
                        "nginx 'proxy_buffer_size' = 4 KB (good). Direct Node "
                        "ws library: 'maxPayload: 1048576' (1 MB). Without "
                        "limits, attacker sends 100 MB+ frames → OOM kill.",
            evidence_marker=" | ".join(
                f"{a['path']}: {a['elapsed_ms']}ms ({a.get('issue','?')})"
                for a in accepted_giant[:3]
            )))
    else:
        findings.append(wrap_finding(
            f"WebSocket properly rejects 512KB frame ({len(rejected)} endpoints)",
            "POSITIVE", cwe="CWE-409",
            remediation="Maintain.",
            evidence_marker=" | ".join(
                f"{r['path']}: server closed after {r['elapsed_ms']}ms"
                for r in rejected[:5]
            )))

    return standard_response(
        tool="websocket_message_size_dos", target=req.target, findings=findings,
        tests_performed=len(WS_PATHS), vulnerable=bool(accepted_giant),
        tests_summary=f"giant-accepted: {len(accepted_giant)}, rejected: {len(rejected)}",
        raw_data={"accepted_giant": accepted_giant, "rejected": rejected})


def register(app):
    app.include_router(router)
