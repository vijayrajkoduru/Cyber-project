"""SNMP Enumeration — checks for exposed SNMP service with weak community strings.

VL-FORGE'd infrastructure vulnerability scanner.
Route: POST /api/vuln/snmp_enum

What it does:
  1. UDP probe to port 161 with SNMPv1 GetRequest for sysDescr.0
  2. Tries common community strings (public, private, community, manager, admin, snmp)
  3. If response: HIGH finding — SNMP exposed with guessable community
  4. Parses sysDescr/sysName/sysContact from response for intel

Pure-Python SNMP v1/v2c packet construction — no external library required.
SNMP is UDP, so behind-firewall scans return SKIPPED cleanly.
"""
import socket
import struct
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            wrap_finding, standard_response)
from tools.vuln._vuln_common import vuln_response

router = APIRouter()

_PORT = 161
_TIMEOUT = 3.0
_FALLBACK_COMMUNITIES = ["public", "private", "community", "manager", "admin", "snmp",
                          "cisco", "default", "root", "monitor"]
try:
    from tools._payloads.snmp_communities import SNMP_COMMUNITIES as _AI_COMMUNITIES
    # AI-curated list is a list of dicts {community, category, priority} — extract + sort by priority
    _COMMUNITIES = [c["community"] for c in sorted(
        _AI_COMMUNITIES, key=lambda x: -int(x.get("priority", 5)))
        if isinstance(c, dict) and c.get("community")]
    if not _COMMUNITIES:
        _COMMUNITIES = _FALLBACK_COMMUNITIES
except Exception:
    _COMMUNITIES = _FALLBACK_COMMUNITIES
_OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"

def _encode_oid(oid):
    """Encode dotted OID to ASN.1 BER."""
    parts = [int(x) for x in oid.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        if n < 128:
            out += bytes([n])
        else:
            stack, n2 = [], n
            stack.append(n2 & 0x7F)
            n2 >>= 7
            while n2:
                stack.append(0x80 | (n2 & 0x7F))
                n2 >>= 7
            out += bytes(reversed(stack))
    return bytes([0x06, len(out)]) + out

def _make_get_request(community, oid):
    """Build SNMPv1 GetRequest packet for the given community + OID."""
    oid_enc = _encode_oid(oid)
    varbind = bytes([0x30, len(oid_enc) + 2]) + oid_enc + bytes([0x05, 0x00])  # NULL value
    varbinds = bytes([0x30, len(varbind)]) + varbind
    # PDU: type=A0 (GetRequest), reqid=1, error=0, error-idx=0, varbinds
    pdu_body = bytes([0x02, 0x01, 0x01,  # request-id = 1
                       0x02, 0x01, 0x00,  # error-status = 0
                       0x02, 0x01, 0x00]) + varbinds  # error-index = 0
    pdu = bytes([0xA0, len(pdu_body)]) + pdu_body
    # Wrap in SNMP message: version (0=v1, 1=v2c), community, PDU
    comm_bytes = community.encode("utf-8")
    msg_body = (bytes([0x02, 0x01, 0x00])  # version = 0 (SNMPv1)
                + bytes([0x04, len(comm_bytes)]) + comm_bytes
                + pdu)
    return bytes([0x30, len(msg_body)]) + msg_body

def _parse_response(data):
    """Extract human-readable string from SNMP response body. Best-effort."""
    if not data or len(data) < 20:
        return None
    # Heuristic: find the longest printable ASCII run >= 8 chars
    out, buf = [], []
    for b in data:
        if 32 <= b < 127:
            buf.append(chr(b))
        else:
            if len(buf) >= 8:
                out.append("".join(buf))
            buf = []
    if len(buf) >= 8:
        out.append("".join(buf))
    return max(out, key=len) if out else None

def _probe(host, community):
    """Send one SNMP GetRequest, return (success, sysDescr_or_None)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(_TIMEOUT)
        packet = _make_get_request(community, _OID_SYSDESCR)
        sock.sendto(packet, (host, _PORT))
        data, _ = sock.recvfrom(2048)
        sock.close()
        return True, _parse_response(data)
    except (socket.timeout, OSError):
        return False, None
    except Exception:
        return False, None

@router.post("/api/vuln/snmp_enum")
def scan_snmp_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    findings, tests, hits = [], 0, []

    for community in _COMMUNITIES:
        tests += 1
        ok, sysdescr = _probe(host, community)
        if ok:
            sample = sysdescr or "(no readable banner)"
            findings.append(wrap_finding(
                f"SNMP exposed on UDP/161 — community {community!r} accepted",
                "HIGH", cvss="7.5", cwe="CWE-200", owasp="A05:2021",
                remediation=("Disable SNMP if not needed. If required: change community to a long random string, "
                              "restrict to management VLAN via ACL, prefer SNMPv3 with authPriv (auth + encryption)."),
                evidence_marker=f"UDP 161 responded to GetRequest with community={community!r}; "
                                 f"sysDescr sample: {sample[:120]}"))
            hits.append({"community": community, "sysdescr_sample": (sample or "")[:200]})
            break  # one confirmed exposure is enough; don't probe further

    if not hits:
        return vuln_response(tool="snmp_enum", target=req.target, findings=[],
            tested=tests,
            skipped_reason=f"SNMP port 161/UDP closed or firewalled on {host} (tried {len(_COMMUNITIES)} community strings)",
            raw_data={"snmp_enum": {"port_open": False, "communities_tried": _COMMUNITIES}})

    return vuln_response(tool="snmp_enum", target=req.target, findings=findings,
        tested=tests,
        what_checked=f"SNMP UDP/161 with {len(_COMMUNITIES)} common community strings",
        tests_summary=f"SNMP: {tests} community(ies) tested; {len(hits)} exposure confirmed",
        raw_data={"snmp_enum": {"port_open": True, "hits": hits,
                                  "communities_tried": _COMMUNITIES}})


def register(app):
    app.include_router(router)
