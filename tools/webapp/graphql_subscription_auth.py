"""graphql_subscription_auth — GraphQL subscriptions WebSocket auth check.

GraphQL subscriptions use WebSocket with subprotocols 'graphql-ws' or
'graphql-transport-ws'. Auth happens via connectionParams in the init
message, NOT via cookies. Bug: server skips connectionParams check →
attacker subscribes to events for any user.
"""
import socket
import ssl
import base64
import os
import json
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

WS_PATHS = ["/graphql", "/api/graphql", "/subscriptions", "/api/subscriptions"]
SUBPROTOCOLS = ["graphql-transport-ws", "graphql-ws"]


def _ws_init(scheme, host, port, path, subprotocol, timeout=8):
    """Open WS with subprotocol, send connection_init {payload: {}}, get response."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if scheme == "wss":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        return None
    key = base64.b64encode(os.urandom(16)).decode()
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket", "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Protocol: {subprotocol}",
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
            sock.close(); return None
        # Send connection_init message with EMPTY payload (no auth)
        init_msg = json.dumps({"type": "connection_init", "payload": {}})
        # Build text frame: FIN+opcode=1, mask=1, len, mask, masked_payload
        pl = init_msg.encode()
        frame = bytearray([0x81])
        if len(pl) < 126:
            frame.append(0x80 | len(pl))
        else:
            frame.append(0x80 | 126)
            frame += len(pl).to_bytes(2, "big")
        mask = os.urandom(4)
        frame += mask
        for i, b in enumerate(pl):
            frame.append(b ^ mask[i % 4])
        sock.sendall(bytes(frame))
        # Read server reply
        sock.settimeout(5)
        try:
            reply = sock.recv(8192)
        except socket.timeout:
            reply = b""
        sock.close()
        if not reply: return None
        # Parse reply frame opcode + payload
        if len(reply) < 2: return None
        opcode = reply[0] & 0x0F
        if opcode == 0x8:
            return {"closed": True, "raw": reply.hex()[:200]}
        # Extract payload (no mask in server→client)
        ln = reply[1] & 0x7F
        if ln == 126:
            payload_start = 4
            actual_len = int.from_bytes(reply[2:4], "big")
        elif ln == 127:
            payload_start = 10
            actual_len = int.from_bytes(reply[2:10], "big")
        else:
            payload_start = 2
            actual_len = ln
        payload = reply[payload_start:payload_start + actual_len]
        return {"closed": False, "payload_text": payload.decode(errors="ignore")}
    except Exception:
        try: sock.close()
        except Exception: pass
        return None


@router.post("/api/webapp/scan/graphql_subscription_auth")
@vl_turbo()
@vl_verify()
def scan_graphql_subscription_auth(req: ScanRequest, payload=Depends(verify_scan_quota)):
    parsed = urlparse(web_url(req.target))
    host = parsed.hostname or req.target
    is_tls = parsed.scheme == "https"
    port = parsed.port or (443 if is_tls else 80)
    scheme = "wss" if is_tls else "ws"

    results = []
    unauth_acceptances = []

    for path in WS_PATHS:
        for proto in SUBPROTOCOLS:
            res = _ws_init(scheme, host, port, path, proto)
            if res is None: continue
            results.append({"path": path, "protocol": proto, "result": res})
            text = res.get("payload_text", "")
            if "connection_ack" in text:
                unauth_acceptances.append({"path": path, "protocol": proto})

    if not results:
        return standard_response(
            tool="graphql_subscription_auth", target=req.target, findings=[],
            tests_performed=len(WS_PATHS) * len(SUBPROTOCOLS),
            vulnerable=False,
            skipped_reason="No GraphQL subscription endpoint with WS subprotocols")

    findings = []
    if unauth_acceptances:
        findings.append(wrap_finding(
            f"GraphQL subscriptions ACK without auth at {len(unauth_acceptances)} endpoint(s)",
            "HIGH", cvss="7.5", cwe="CWE-306", owasp="A07:2021",
            remediation="connection_init with EMPTY payload returned connection_ack "
                        "= server doesn't validate auth at WebSocket layer. Add "
                        "auth check in the connection_init handler: verify "
                        "Authorization token in connectionParams BEFORE acking. "
                        "Reference: graphql-ws docs onConnect callback.",
            evidence_marker=" | ".join(
                f"{u['path']} ({u['protocol']})" for u in unauth_acceptances[:3]
            )))
    else:
        rejected_count = sum(1 for r in results if r["result"].get("closed") or
                              "connection_error" in r["result"].get("payload_text", ""))
        findings.append(wrap_finding(
            f"GraphQL subscriptions reject unauth init ({rejected_count} of {len(results)} probes)",
            "POSITIVE", cwe="CWE-306",
            remediation="Maintain. Continue requiring auth in connection_init.",
            evidence_marker=f"{rejected_count} rejected with close/error frame"))

    return standard_response(
        tool="graphql_subscription_auth", target=req.target, findings=findings,
        tests_performed=len(WS_PATHS) * len(SUBPROTOCOLS),
        vulnerable=bool(unauth_acceptances),
        tests_summary=f"{len(results)} WS handshakes, {len(unauth_acceptances)} unauth-acks",
        raw_data={"unauth_acceptances": unauth_acceptances,
                   "all_results": [{"path": r["path"], "protocol": r["protocol"]}
                                     for r in results[:10]]})


def register(app):
    app.include_router(router)
