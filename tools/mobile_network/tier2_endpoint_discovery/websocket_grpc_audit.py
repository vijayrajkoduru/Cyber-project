"""websocket_grpc_audit — detect modern non-REST transports.
- WebSocket (ws:// / wss://, OkHttp WebSocket, java-websocket)
- gRPC (io.grpc.ManagedChannel, *.proto schemas)
- MQTT (Paho client, mqtt:// URIs)
- Server-Sent Events (text/event-stream)
These don't show up in standard URL scans and are routinely missed in
mobile pentests because Burp doesn't intercept them by default."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.websocket_grpc_audit_findings import WEBSOCKET_GRPC_AUDIT_FINDING_RULES

router = APIRouter()

WS_URI_RE = re.compile(r'"(wss?://[A-Za-z0-9.\-:/%_+#?&=]{4,200})"')
MQTT_URI_RE = re.compile(r'"(mqtts?://[A-Za-z0-9.\-:/]{4,200})"')
GRPC_HOST_RE = re.compile(r'forAddress\("([A-Za-z0-9.\-]+)"\s*,\s*(\d+)\)')

PROTOCOL_MARKERS = {
    "WebSocket (OkHttp)":  ["okhttp3/WebSocket", "newWebSocket"],
    "WebSocket (java-websocket)": ["org/java_websocket/WebSocketClient"],
    "WebSocket (Scarlet)":  ["com/tinder/scarlet"],
    "gRPC (io.grpc)":       ["io/grpc/ManagedChannel", "io/grpc/Stub"],
    "MQTT (Paho)":          ["org/eclipse/paho/client/mqttv3"],
    "MQTT (HiveMQ)":        ["com/hivemq/client"],
    "Server-Sent Events":   ["text/event-stream", "EventSource"],
    "Socket.IO":            ["io/socket/client/Socket"],
    "SignalR":              ["com/microsoft/signalr"],
}
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["websocket_grpc_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["websocket_grpc_audit_error"] = str(e)
        return

    protocols = {}
    ws_uris = set()
    mqtt_uris = set()
    grpc_hosts = []
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for proto, markers in PROTOCOL_MARKERS.items():
            for m in markers:
                if m in txt:
                    protocols.setdefault(proto, [])
                    if p.name not in protocols[proto] and len(protocols[proto]) < 5:
                        protocols[proto].append(p.name)
                    break
        for m in WS_URI_RE.finditer(txt):
            ws_uris.add(m.group(1))
        for m in MQTT_URI_RE.finditer(txt):
            mqtt_uris.add(m.group(1))
        for m in GRPC_HOST_RE.finditer(txt):
            grpc_hosts.append(f"{m.group(1)}:{m.group(2)}")

    ctx.state["protocols_detected"] = protocols
    ctx.state["websocket_uris"] = sorted(ws_uris)[:30]
    ctx.state["mqtt_uris"] = sorted(mqtt_uris)[:20]
    ctx.state["grpc_hosts"] = grpc_hosts[:20]
    ctx.state["files_scanned"] = files_scanned
    ctx.state["websocket_grpc_audit_total"] = len(protocols)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Non-REST protocols detected", "protocols_detected"),
    ("WebSocket URIs", "websocket_uris"),
    ("MQTT URIs", "mqtt_uris"),
    ("gRPC hosts", "grpc_hosts"),
]


@router.post("/api/mobile_network/websocket_grpc_audit")
async def mobile_network_websocket_grpc_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="websocket_grpc_audit",
        gather_func=gather,
        finding_rules=WEBSOCKET_GRPC_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
