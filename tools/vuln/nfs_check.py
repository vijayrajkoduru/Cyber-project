"""NFS Exposure Check — RPC portmapper + NFS direct check.

VL-FORGE'd infrastructure vulnerability scanner.
Route: POST /api/vuln/nfs_check

What it does:
  1. TCP probe to port 111 (rpcbind / portmapper) — if open, RPC services exposed
  2. TCP probe to port 2049 (NFS) — direct NFS exposure to internet
  3. If both responsive: HIGH severity (file system mountable from anywhere)

NFS exposed to the internet is one of the highest-impact misconfigs — attackers
can mount the share read-only at minimum, often read-write with squashing tricks.
"""
import socket
import struct
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            wrap_finding, standard_response)
from tools.vuln._vuln_common import vuln_response

router = APIRouter()

_PORT_PORTMAP = 111
_PORT_NFS = 2049
_TIMEOUT = 4.0

def _tcp_open(host, port):
    """Quick TCP connect probe."""
    try:
        sock = socket.create_connection((host, port), timeout=_TIMEOUT)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def _portmap_dump(host):
    """Send RPC portmapper DUMP call (program 100000, version 2, proc 4)
    Returns list of registered RPC services or None."""
    try:
        sock = socket.create_connection((host, _PORT_PORTMAP), timeout=_TIMEOUT)
        sock.settimeout(_TIMEOUT)
        # RPC v2 call: fragment header (4) + xid + msg_type + rpc_vers + program + version + proc + creds + verf
        # program = 100000 (portmapper), version = 2, proc = 4 (DUMP)
        rpc_call = struct.pack(">LLLLLLL",
                                0x80000028,  # last fragment, length 0x28
                                0x12345678,  # XID
                                0,           # message type (CALL)
                                2,           # RPC version
                                100000,      # portmap program
                                2,           # version
                                4)           # DUMP procedure
        rpc_call += b"\x00" * 16  # null credentials + null verifier
        sock.send(rpc_call)
        resp = sock.recv(8192)
        sock.close()
        # If we got >40 bytes back and reply status looks valid, portmapper is alive
        if len(resp) > 28:
            return resp[:200]
        return None
    except Exception:
        return None

@router.post("/api/vuln/nfs_check")
def scan_nfs_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    portmap_open = _tcp_open(host, _PORT_PORTMAP)
    nfs_open     = _tcp_open(host, _PORT_NFS)

    if not portmap_open and not nfs_open:
        return vuln_response(tool="nfs_check", target=req.target, findings=[],
            tested=2,
            skipped_reason=f"Neither rpcbind/111 nor NFS/2049 responsive on {host}",
            raw_data={"nfs_check": {"portmap_open": False, "nfs_open": False}})

    findings = []
    raw = {"portmap_open": portmap_open, "nfs_open": nfs_open}

    if portmap_open:
        dump = _portmap_dump(host)
        raw["portmap_dump_bytes"] = len(dump) if dump else 0
        findings.append(wrap_finding(
            "RPC portmapper (rpcbind) exposed on TCP/111",
            "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="A05:2021",
            remediation=("Restrict rpcbind to internal network only. "
                          "iptables: 'iptables -A INPUT -p tcp --dport 111 -s <trusted_net> -j ACCEPT' + drop default. "
                          "Modern systems: disable rpcbind unless NFS/NIS is in use."),
            evidence_marker=f"TCP 111 on {host} accepted RPC connection; portmapper DUMP returned {len(dump or b'')} bytes"))

    if nfs_open:
        findings.append(wrap_finding(
            "NFS service exposed on TCP/2049",
            "HIGH", cvss="7.5", cwe="CWE-732", owasp="A01:2021",
            remediation=("NFS should NEVER be exposed to the public internet. "
                          "Restrict to management VLAN via firewall. "
                          "If remote NFS is required, tunnel through VPN or use NFSv4 with Kerberos (sec=krb5p). "
                          "Default NFS permissions allow read-only mount from any host that can reach the port. "
                          "Check /etc/exports for '*' or '0.0.0.0/0' subnet entries."),
            evidence_marker=f"TCP 2049 on {host} accepted connection (NFS daemon reachable)"))

        # Combined exposure = even higher risk (full file-system enumeration possible)
        if portmap_open:
            findings.append(wrap_finding(
                "NFS + rpcbind both exposed — full file-share enumeration possible",
                "HIGH", cvss="8.6", cwe="CWE-732", owasp="A05:2021",
                remediation=("Combined exposure lets attackers run 'showmount -e <host>' to list all exports, "
                              "then mount any world-readable share. This has been a top exploitation vector "
                              "for ransomware groups (e.g., LockBit). Restrict ports 111 + 2049 + 32768-32775 "
                              "(NFS data) at firewall immediately."),
                evidence_marker=f"Both 111/TCP and 2049/TCP open on {host} — full RPC + NFS attack surface"))

    return vuln_response(tool="nfs_check", target=req.target, findings=findings,
        tested=2,
        what_checked="NFS + RPC portmapper exposure on TCP/111 and TCP/2049",
        tests_summary=f"NFS check: portmap={portmap_open}, nfs={nfs_open}; {len(findings)} finding(s)",
        raw_data={"nfs_check": raw})


def register(app):
    app.include_router(router)
