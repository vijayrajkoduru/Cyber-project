"""§30 IoT/OT/ICS Security — 58 endpoints per 30_iot_ot.md.

VL-FORGE upgrade 2026-05-30: 6 live probes for externally-observable
ICS/SCADA protocols on standard ports (Modbus 502, Siemens S7 102,
EtherNet/IP 44818, BACnet 47808, DNP3 20000, Mirai-era IoT telnet 23/2323).
"""
import socket
from contextlib import closing
from tools._pack_common import make_advisory_router, _adv_response
from tools._shared import wrap_finding


def _host(t):
    return t.split("://", 1)[-1].split("/")[0].split(":")[0].strip().lower() or t

def _tcp_open(host, port, timeout=2.0):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False

def _udp_probe(host, port, payload=b"\x00", timeout=1.5):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
            s.settimeout(timeout)
            s.sendto(payload, (host, port))
            try:
                data, _ = s.recvfrom(512)
                return True, data
            except socket.timeout:
                return False, b""
    except Exception:
        return False, b""

def _build(tool, target, findings, tested, summary):
    sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"POSITIVE":0}
    top = "INFO"
    for f in findings:
        if sev_order.get(f.get("severity","INFO"),0) > sev_order.get(top,0):
            top = f.get("severity","INFO")
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": top in ("CRITICAL","HIGH","MEDIUM"),
            "severity": top, "findings": findings,
            "tests_performed": tested, "tests_summary": summary, "raw_data": {}}


def _probe_modbus(target, req):
    host = _host(target)
    findings = []
    if _tcp_open(host, 502):
        # Send Modbus function code 0x01 (Read Coils)
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                s.settimeout(3.0)
                if s.connect_ex((host, 502)) == 0:
                    req_pkt = b"\x00\x01\x00\x00\x00\x06\x01\x01\x00\x00\x00\x01"
                    s.send(req_pkt)
                    resp = s.recv(256)
                    if resp and len(resp) >= 8 and resp[7] == 0x01:
                        findings.append(wrap_finding(
                            "Modbus TCP/502 service responding — UNAUTH critical-control protocol exposed",
                            "CRITICAL", cvss="9.5", cwe="CWE-306", owasp="A05:2021",
                            remediation="NEVER expose Modbus to internet. Segregate OT network from corporate; use Modbus-Sec or VPN.",
                            evidence_marker=f"TCP/502 open; Function 01 (Read Coils) accepted"))
                    else:
                        findings.append(wrap_finding(
                            "TCP/502 open but no Modbus response",
                            "HIGH", cvss="7.0", cwe="CWE-306",
                            remediation="Verify what listens on 502; if Modbus, restrict immediately.",
                            evidence_marker="TCP/502 open, no protocol confirm"))
        except Exception as e:
            findings.append(wrap_finding(
                f"TCP/502 open but probe error: {str(e)[:50]}",
                "MEDIUM", cvss="5.0", cwe="CWE-306",
                remediation="Manual review.", evidence_marker=str(e)[:80]))
    else:
        findings.append(wrap_finding(
            "Modbus TCP/502 not externally reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue OT-network segregation.",
            evidence_marker="TCP/502 closed"))
    return _build("modbus_502_probe", target, findings, 1, "Modbus TCP/502 protocol probe")


def _probe_siemens_s7(target, req):
    host = _host(target)
    findings = []
    if _tcp_open(host, 102):
        findings.append(wrap_finding(
            "Siemens S7 TCP/102 (ISO-TSAP) reachable — likely PLC exposed",
            "CRITICAL", cvss="9.5", cwe="CWE-306",
            remediation="NEVER expose PLC management to internet. Use industrial firewall + VPN.",
            evidence_marker="TCP/102 open"))
    else:
        findings.append(wrap_finding(
            "Siemens S7 TCP/102 not reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue PLC network isolation.",
            evidence_marker="TCP/102 closed"))
    return _build("siemens_s7_102_probe", target, findings, 1, "Siemens S7 PLC probe")


def _probe_ethernet_ip(target, req):
    host = _host(target)
    findings = []
    if _tcp_open(host, 44818):
        findings.append(wrap_finding(
            "EtherNet/IP TCP/44818 reachable — Allen-Bradley/Rockwell PLC likely exposed",
            "CRITICAL", cvss="9.5", cwe="CWE-306",
            remediation="Block EtherNet/IP at corporate firewall; segregate OT.",
            evidence_marker="TCP/44818 open"))
    else:
        findings.append(wrap_finding(
            "EtherNet/IP TCP/44818 not reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue OT segregation.",
            evidence_marker="TCP/44818 closed"))
    return _build("ethernet_ip_probe", target, findings, 1, "EtherNet/IP probe")


def _probe_bacnet(target, req):
    host = _host(target)
    findings = []
    # BACnet/IP uses UDP/47808 with a Who-Is broadcast
    bacnet_who_is = b"\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08"
    reachable, data = _udp_probe(host, 47808, bacnet_who_is, timeout=2.0)
    if reachable or _tcp_open(host, 47808):
        findings.append(wrap_finding(
            "BACnet UDP/47808 reachable — building automation system exposed",
            "HIGH", cvss="7.5", cwe="CWE-306",
            remediation="Restrict BACnet to building network; firewall internet exposure.",
            evidence_marker=f"UDP/47808 probe {'returned data' if reachable else 'no response (possibly filtered)'}"))
    else:
        findings.append(wrap_finding(
            "BACnet UDP/47808 not reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue BMS network segregation.",
            evidence_marker="UDP/47808 silent"))
    return _build("bacnet_47808_probe", target, findings, 1, "BACnet UDP/47808 probe")


def _probe_dnp3(target, req):
    host = _host(target)
    findings = []
    if _tcp_open(host, 20000):
        findings.append(wrap_finding(
            "DNP3 TCP/20000 reachable — power/water SCADA likely exposed",
            "CRITICAL", cvss="9.5", cwe="CWE-306",
            remediation="DNP3 must be on isolated network; use DNP3-SA + VPN.",
            evidence_marker="TCP/20000 open"))
    else:
        findings.append(wrap_finding(
            "DNP3 TCP/20000 not reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue SCADA isolation.",
            evidence_marker="TCP/20000 closed"))
    return _build("dnp3_unauth_advisory", target, findings, 1, "DNP3 TCP/20000 probe")


def _probe_iot_telnet(target, req):
    host = _host(target)
    findings = []
    for port in [23, 2323]:
        if _tcp_open(host, port, timeout=2):
            try:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                    s.settimeout(2)
                    if s.connect_ex((host, port)) == 0:
                        banner = s.recv(128).decode("utf-8", errors="ignore").strip()
                        findings.append(wrap_finding(
                            f"Telnet {port}/tcp open — IoT/Mirai-era backdoor risk",
                            "HIGH", cvss="8.0", cwe="CWE-319",
                            remediation="Disable telnet; use SSH + key auth; check for embedded default creds.",
                            evidence_marker=f"TCP/{port} banner: {banner[:80] if banner else '(empty)'}"))
            except Exception:
                pass
    if not findings:
        findings.append(wrap_finding(
            "Telnet 23/2323 not externally reachable",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue.",
            evidence_marker="Both ports closed"))
    return _build("iot_telnet_2323_probe", target, findings, 2, "IoT telnet port probe")


PROBES = {
    "modbus_502_probe":          _probe_modbus,
    "siemens_s7_102_probe":      _probe_siemens_s7,
    "ethernet_ip_probe":         _probe_ethernet_ip,
    "bacnet_47808_probe":        _probe_bacnet,
    "dnp3_unauth_advisory":      _probe_dnp3,
    "iot_telnet_2323_probe":     _probe_iot_telnet,
}

T = [
    # §1 ICS/SCADA Discovery (11)
    ("ics_shodan_scada_query", "Shodan SCADA query.", "INFO", "0.0"),
    ("ics_censys_scada_query", "Censys SCADA query.", "INFO", "0.0"),
    ("ics_grassmarlin_discovery", "GRASSMARLIN discovery.", "INFO", "0.0"),
    ("ics_nmap_ics_scripts", "nmap ICS NSE scripts.", "MEDIUM", "5.5"),
    ("ics_plcscan_discovery", "PLCScan discovery.", "MEDIUM", "5.5"),
    ("ics_pcap_protocol_inspect", "PCAP protocol inspect.", "INFO", "0.0"),
    ("ics_asset_inventory", "ICS asset inventory.", "INFO", "0.0"),
    ("ics_purdue_model_audit", "Purdue model audit.", "INFO", "0.0"),
    ("ics_dmz_audit", "ICS DMZ audit.", "MEDIUM", "5.5"),
    ("ics_iec62443_compliance", "IEC 62443 compliance check.", "MEDIUM", "5.5"),
    ("manual_ics_discovery", "Manual ICS discovery.", "INFO", "0.0"),
    # §2 Modbus/DNP3/EtherNet/IP (8)
    ("modbus_502_probe", "Modbus TCP/502 probe.", "MEDIUM", "5.5"),
    ("modbus_read_holding_registers", "Modbus read holding registers.", "HIGH", "7.0"),
    ("modbus_write_coils_advisory", "Modbus write coils advisory.", "HIGH", "8.0"),
    ("dnp3_unauth_advisory", "DNP3 unauth advisory.", "HIGH", "7.5"),
    ("ethernet_ip_probe", "EtherNet/IP probe.", "MEDIUM", "5.5"),
    ("cip_attribute_audit", "CIP attribute audit.", "MEDIUM", "5.5"),
    ("modbus_flood_dos", "Modbus flood DoS advisory.", "HIGH", "7.0"),
    ("manual_modbus_review", "Manual Modbus review.", "INFO", "0.0"),
    # §3 Siemens/Schneider/Rockwell (7)
    ("siemens_s7_102_probe", "Siemens S7 TCP/102 probe.", "MEDIUM", "5.5"),
    ("siemens_simatic_audit", "SIMATIC step7 audit.", "MEDIUM", "5.5"),
    ("schneider_modicon_probe", "Schneider Modicon probe.", "MEDIUM", "5.5"),
    ("rockwell_allenbradley_probe", "Rockwell/AB probe.", "MEDIUM", "5.5"),
    ("rockwell_logix5000_advisory", "Logix5000 advisory.", "MEDIUM", "5.5"),
    ("siemens_default_creds", "Siemens default creds.", "HIGH", "7.5"),
    ("manual_vendor_review", "Manual vendor review.", "INFO", "0.0"),
    # §4 BACnet/KNX/LonWorks (6)
    ("bacnet_47808_probe", "BACnet UDP/47808 probe.", "MEDIUM", "5.5"),
    ("bacnet_unauth_object_list", "BACnet unauth object list.", "HIGH", "7.5"),
    ("knx_3671_probe", "KNX UDP/3671 probe.", "MEDIUM", "5.5"),
    ("lonworks_audit", "LonWorks audit.", "MEDIUM", "5.5"),
    ("bms_default_creds", "BMS default creds.", "HIGH", "7.5"),
    ("manual_building_review", "Manual building automation review.", "INFO", "0.0"),
    # §5 IoT Device Recon (13)
    ("iot_shodan_query", "IoT Shodan query.", "INFO", "0.0"),
    ("iot_censys_query", "IoT Censys query.", "INFO", "0.0"),
    ("iot_mac_oui_lookup", "MAC OUI vendor lookup.", "INFO", "0.0"),
    ("iot_default_creds_check", "IoT default creds check.", "HIGH", "8.0"),
    ("iot_telnet_2323_probe", "Telnet 23/2323 probe (Mirai).", "HIGH", "8.0"),
    ("iot_upnp_audit", "UPnP audit.", "HIGH", "7.5"),
    ("iot_mdns_dnssd_audit", "mDNS/DNS-SD audit.", "MEDIUM", "5.5"),
    ("iot_rtsp_camera_probe", "RTSP camera probe.", "HIGH", "7.5"),
    ("iot_onvif_camera_audit", "ONVIF camera audit.", "MEDIUM", "5.5"),
    ("iot_router_firmware_audit", "Router firmware audit.", "MEDIUM", "5.5"),
    ("iot_dvr_default_creds", "DVR default creds.", "HIGH", "7.5"),
    ("iot_printer_default_creds", "Printer default creds.", "MEDIUM", "5.5"),
    ("manual_iot_review", "Manual IoT review.", "INFO", "0.0"),
    # §6 Zigbee/Z-Wave/Thread (5)
    ("zigbee_killerbee_audit", "Zigbee killerbee audit.", "MEDIUM", "5.5"),
    ("zwave_zforce_audit", "Z-Wave Z-Force audit.", "MEDIUM", "5.5"),
    ("thread_audit", "Thread protocol audit.", "MEDIUM", "5.5"),
    ("matter_audit", "Matter protocol audit.", "MEDIUM", "5.5"),
    ("manual_mesh_iot_review", "Manual mesh IoT review.", "INFO", "0.0"),
    # §7 Matter/Smart Home (4)
    ("matter_commissioning_audit", "Matter commissioning audit.", "MEDIUM", "5.5"),
    ("matter_pase_pake_audit", "Matter PASE/PAKE audit.", "MEDIUM", "5.5"),
    ("matter_otacert_audit", "Matter OTA cert audit.", "MEDIUM", "5.5"),
    ("manual_matter_review", "Manual Matter review.", "INFO", "0.0"),
    # §8 OT Pentest Methodology (4)
    ("ot_safety_first_audit", "OT safety-first audit.", "INFO", "0.0"),
    ("ot_lockout_procedure", "OT lockout/tagout procedure check.", "INFO", "0.0"),
    ("ot_change_management", "OT change management audit.", "INFO", "0.0"),
    ("manual_ot_pentest_planning", "Manual OT pentest planning.", "INFO", "0.0"),
]

router = make_advisory_router("iot_ot", T,
    playbook_ref="See module_playbooks/30_iot_ot.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
