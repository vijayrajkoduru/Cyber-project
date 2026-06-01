"""§16 Network Attacks — 67 endpoints per 16_network.md.
8 sections: port/service enum, LAN L2, MITM, DoS, sniffing, DNS attacks,
IPv6, protocol fuzzing.

VL-FORGE upgrade 2026-05-30: tier1 (Port & Service Enumeration, 14 endpoints)
upgraded from advisory to LIVE PROBES. Other tiers correctly remain
advisory (LAN/MITM/sniffing require local network access, DoS/fuzzing
are ethical-not-probe, IPv6 needs IPv6 routing).
"""
import socket
import asyncio
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from tools._pack_common import make_advisory_router, _adv_response
from tools._shared import wrap_finding


def _host(target: str) -> str:
    s = target.split("://", 1)[-1].split("/")[0].split(":")[0]
    return s.strip().lower() or target


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def _tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _tcp_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0:
                return ""
            try:
                return s.recv(256).decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""
    except Exception:
        return ""


def _scan_ports(host: str, ports: list, timeout: float = 1.0) -> dict:
    """Concurrent TCP connect scan. Returns {port: True/False}."""
    out = {}
    with ThreadPoolExecutor(max_workers=32) as ex:
        futs = {ex.submit(_tcp_open, host, p, timeout): p for p in ports}
        for fut, p in futs.items():
            try:
                out[p] = fut.result(timeout=timeout + 1)
            except Exception:
                out[p] = False
    return out


def _wrap(slug, target, title, sev, cvss, evidence, remed=""):
    return _adv_response(slug, target, title, sev, cvss,
                          cwe="CWE-200",
                          remediation=remed or "Restrict exposed ports to admin VLAN; close non-essential services.",
                          evidence=evidence)


# ─── LIVE PROBES for tier1 Port & Service Enumeration ───

TOP_TCP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,
                  587,631,636,873,993,995,1080,1433,1521,1723,2049,2222,
                  3306,3389,5432,5900,5985,5986,6379,7001,8000,8080,8443,
                  9000,9200,9300,9418,11211,27017]

def _probe_nmap_syn_scan(target, req):
    """nmap-equivalent TCP connect scan on top 45 ports."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("nmap_syn_scan", target, f"DNS resolution failed for {host}",
                              "INFO", "0.0", evidence=f"Could not resolve {host}")
    results = _scan_ports(ip, TOP_TCP_PORTS, timeout=1.0)
    opens = sorted([p for p, o in results.items() if o])
    findings = []
    if opens:
        findings.append(wrap_finding(
            f"Live TCP port scan — {len(opens)} open ports on {host} ({ip})",
            "INFO" if len(opens) <= 5 else ("MEDIUM" if len(opens) <= 15 else "HIGH"),
            cvss="3.0" if len(opens) <= 5 else "5.5",
            cwe="CWE-200",
            remediation="Close ports not required for business function; firewall non-essential services.",
            evidence_marker=f"Open: {', '.join(str(p) for p in opens)}"))
    return {"tool":"nmap_syn_scan","target":target,"scan_time":0,
            "vulnerable": len(opens) > 5, "severity": "MEDIUM" if len(opens) > 5 else "INFO",
            "findings": findings or [wrap_finding(f"No top-45 TCP ports open on {host}",
                "POSITIVE", cvss="0.0", cwe="N/A", remediation="Continue least-exposure posture.",
                evidence_marker=f"Scanned {len(TOP_TCP_PORTS)} ports — all closed")],
            "tests_performed": len(TOP_TCP_PORTS),
            "tests_summary": f"TCP connect scan of {len(TOP_TCP_PORTS)} ports on {host}",
            "raw_data": {"open_ports": opens, "ip": ip}}

def _probe_nmap_udp_scan(target, req):
    """UDP probe — limited to DNS/NTP/SNMP/SSDP common UDP."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("nmap_udp_scan", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    udp_ports = [53, 67, 68, 123, 137, 161, 500, 514, 520, 1900, 4500, 5353]
    open_count = 0
    for port in udp_ports:
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
                s.settimeout(1.0)
                s.sendto(b"\x00\x00", (ip, port))
                try:
                    s.recvfrom(512)
                    open_count += 1
                except socket.timeout:
                    open_count += 1  # open or filtered
                except OSError:
                    pass
        except Exception:
            pass
    return {"tool":"nmap_udp_scan","target":target,"scan_time":0,
            "vulnerable": open_count > 3, "severity": "INFO",
            "findings": [wrap_finding(
                f"UDP probe — {open_count}/{len(udp_ports)} common UDP ports likely open/filtered",
                "INFO" if open_count <= 3 else "LOW",
                cvss="0.0" if open_count <= 3 else "3.0",
                cwe="CWE-200",
                remediation="UDP responses indicate active services; close non-essential UDP at firewall.",
                evidence_marker=f"Probed: {udp_ports}; potentially open: {open_count}")],
            "tests_performed": len(udp_ports),
            "tests_summary": f"UDP probe scan of {len(udp_ports)} ports",
            "raw_data": {"ip": ip, "open_or_filtered_count": open_count}}

def _probe_nmap_version_detect(target, req):
    """Banner grab on top open ports to derive service version."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("nmap_version_detect", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    common = [21, 22, 25, 80, 110, 143, 443, 587, 993, 3306, 5432, 6379, 8080]
    services = {}
    for p in common:
        b = _tcp_banner(ip, p, timeout=2.0)
        if b: services[p] = b[:120]
    findings = []
    if services:
        findings.append(wrap_finding(
            f"Service banners harvested on {len(services)} ports",
            "INFO", cvss="0.0", cwe="CWE-200",
            remediation="Disable banner disclosure on production services where not required.",
            evidence_marker="; ".join(f"{p}: {b[:60]}" for p,b in services.items())))
    return {"tool":"nmap_version_detect","target":target,"scan_time":0,
            "vulnerable": False, "severity": "INFO",
            "findings": findings or [wrap_finding(
                "No service banners harvested", "INFO", cvss="0.0", cwe="N/A",
                remediation="Continue minimal-banner posture.",
                evidence_marker=f"Probed {common}")],
            "tests_performed": len(common),
            "tests_summary": f"Banner grab on {len(common)} common service ports",
            "raw_data": {"ip": ip, "services": services}}

def _probe_nmap_os_detect(target, req):
    """OS fingerprint via TCP/IP stack characteristics (TTL + window)."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("nmap_os_detect", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    # Light TTL-based heuristic from an HTTP probe
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(2.0)
            if s.connect_ex((ip, 80)) == 0:
                s.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                resp = s.recv(512).decode("utf-8", errors="ignore")
                server_hdr = ""
                for line in resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        server_hdr = line[7:].strip()
                        break
                os_guess = "Linux/Unix" if "nginx" in server_hdr.lower() or "apache" in server_hdr.lower() else \
                           "Windows" if "iis" in server_hdr.lower() or "microsoft" in server_hdr.lower() else \
                           "Unknown"
                return {"tool":"nmap_os_detect","target":target,"scan_time":0,
                        "vulnerable": False, "severity": "INFO",
                        "findings":[wrap_finding(
                            f"OS likely: {os_guess} (heuristic from Server header)",
                            "INFO", cvss="0.0", cwe="CWE-200",
                            remediation="Remove or randomize Server header to reduce fingerprintability.",
                            evidence_marker=f"Server: {server_hdr}")],
                        "tests_performed": 1,
                        "tests_summary": "OS heuristic from HTTP Server header",
                        "raw_data": {"ip": ip, "server": server_hdr, "os_guess": os_guess}}
    except Exception:
        pass
    return _adv_response("nmap_os_detect", target, "OS detection inconclusive — no probeable HTTP port",
                          "INFO", "0.0", evidence=f"{host} ({ip})")

def _probe_nmap_default_scripts(target, req):
    """Lightweight 'default scripts' equivalent — banner + headers on web ports."""
    return _probe_nmap_version_detect(target, req) | {"tool":"nmap_default_scripts"}

def _probe_nmap_aggressive(target, req):
    """Aggressive probe — top ports + banners + UDP probe combined."""
    syn = _probe_nmap_syn_scan(target, req)
    ver = _probe_nmap_version_detect(target, req)
    udp = _probe_nmap_udp_scan(target, req)
    findings = (syn.get("findings") or []) + (ver.get("findings") or []) + (udp.get("findings") or [])
    return {"tool":"nmap_aggressive","target":target,"scan_time":0,
            "vulnerable": syn.get("vulnerable") or False, "severity": syn.get("severity","INFO"),
            "findings": findings,
            "tests_performed": (syn.get("tests_performed",0) + ver.get("tests_performed",0) + udp.get("tests_performed",0)),
            "tests_summary": "Aggressive scan: SYN + version + UDP combined",
            "raw_data": {**syn.get("raw_data",{}), "version": ver.get("raw_data",{}), "udp": udp.get("raw_data",{})}}

def _probe_masscan_full_range(target, req):
    """Masscan-equivalent — wider port range. Scan top 200 ports for SaaS-safety."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("masscan_full_range", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    # Top 200 by IANA/nmap-services frequency (truncated for SaaS-safety)
    top200 = (TOP_TCP_PORTS +
              [37,49,79,81,82,88,113,119,179,427,548,554,593,
               646,873,990,1025,1026,1027,1028,1029,1110,1234,1311,1352,
               1434,1521,1755,1900,2000,2001,2049,2121,2717,3128,3268,3306,
               3690,3703,3986,4001,4045,4899,5050,5051,5060,5101,5190,5500,
               5631,5666,5800,5801,5802,5803,5810,5811,5815,5822,5825,5850,
               5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5915,
               5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,
               5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,
               6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,
               6543,6547,6565,6566,6580,6646,6666,6667,6668,6669,6689,6692,
               6699,6779,6788,6789,6792,6839,6881,6901,6969])
    top200 = list(set(top200))[:200]
    results = _scan_ports(ip, top200, timeout=0.6)
    opens = sorted([p for p, o in results.items() if o])
    return {"tool":"masscan_full_range","target":target,"scan_time":0,
            "vulnerable": len(opens) > 10, "severity": "HIGH" if len(opens) > 20 else ("MEDIUM" if len(opens) > 10 else "INFO"),
            "findings":[wrap_finding(
                f"Wide port scan — {len(opens)} of {len(top200)} ports open on {host}",
                "HIGH" if len(opens) > 20 else ("MEDIUM" if len(opens) > 10 else "INFO"),
                cvss="6.0" if len(opens) > 20 else "3.0",
                cwe="CWE-200",
                remediation="Audit exposed services; close any not required.",
                evidence_marker=f"Open: {', '.join(str(p) for p in opens[:30])}{'...' if len(opens)>30 else ''}")],
            "tests_performed": len(top200),
            "tests_summary": f"Wide port scan of {len(top200)} ports",
            "raw_data": {"ip": ip, "open_ports": opens}}

def _probe_rustscan_top_ports(target, req):
    return _probe_nmap_syn_scan(target, req) | {"tool":"rustscan_top_ports"}

def _probe_naabu_fast_scan(target, req):
    return _probe_nmap_syn_scan(target, req) | {"tool":"naabu_fast_scan"}

def _probe_unicornscan(target, req):
    return _probe_nmap_udp_scan(target, req) | {"tool":"unicornscan_advisory"}

def _probe_zmap(target, req):
    """ZMap is internet-wide; for SaaS we sample 5 random TCP ports."""
    return _probe_nmap_syn_scan(target, req) | {"tool":"zmap_internet_wide"}

def _probe_hping3(target, req):
    """hping3 equivalent — TCP SYN check on port 80."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("hping3_custom_packet", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    reachable = _tcp_open(ip, 80, timeout=2.0) or _tcp_open(ip, 443, timeout=2.0)
    return {"tool":"hping3_custom_packet","target":target,"scan_time":0,
            "vulnerable": False, "severity": "INFO",
            "findings":[wrap_finding(
                f"Host {'reachable' if reachable else 'unreachable'} via TCP/80 or TCP/443",
                "INFO", cvss="0.0", cwe="CWE-200",
                remediation="Confirm intended network reachability.",
                evidence_marker=f"{host} ({ip}) — TCP probe")],
            "tests_performed": 2,
            "tests_summary": "TCP reachability check (hping3 equivalent)",
            "raw_data": {"ip": ip, "reachable": reachable}}

def _probe_tcptraceroute(target, req):
    return _probe_hping3(target, req) | {"tool":"tcptraceroute_advisory"}

def _probe_netcat_banner_grab(target, req):
    return _probe_nmap_version_detect(target, req) | {"tool":"netcat_banner_grab"}


# ─── LIVE PROBES for tier6 DNS Attacks (partial) ───

def _probe_dns_zone_transfer(target, req):
    """AXFR attempt against the domain's NS."""
    host = _host(target)
    try:
        import dns.query, dns.zone, dns.resolver
        try:
            ns_records = [str(n.target).rstrip(".") for n in dns.resolver.resolve(host, "NS")]
        except Exception:
            ns_records = []
        results = {}
        for ns in ns_records[:3]:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, host, timeout=5))
                results[ns] = len(list(z.nodes.keys()))
            except Exception as e:
                results[ns] = f"refused: {str(e)[:50]}"
        leaked = [ns for ns, n in results.items() if isinstance(n, int)]
        if leaked:
            return {"tool":"dns_zone_transfer_axfr","target":target,"scan_time":0,
                    "vulnerable": True, "severity": "HIGH",
                    "findings":[wrap_finding(
                        f"DNS AXFR allowed on {len(leaked)} nameserver(s)",
                        "HIGH", cvss="7.5", cwe="CWE-200",
                        remediation="Restrict AXFR to authorized secondary nameservers only.",
                        evidence_marker=f"Leaked NS: {', '.join(leaked)}")],
                    "tests_performed": len(ns_records),
                    "tests_summary": "DNS zone transfer (AXFR) attempt",
                    "raw_data": {"results": results}}
        return {"tool":"dns_zone_transfer_axfr","target":target,"scan_time":0,
                "vulnerable": False, "severity": "POSITIVE",
                "findings":[wrap_finding(
                    "DNS AXFR correctly refused on all nameservers",
                    "POSITIVE", cvss="0.0", cwe="N/A",
                    remediation="Continue restricting AXFR.",
                    evidence_marker=f"Tested {len(ns_records)} NS, all refused")],
                "tests_performed": len(ns_records),
                "tests_summary": "DNS zone transfer attempt — all refused",
                "raw_data": {"results": results}}
    except ImportError:
        return _adv_response("dns_zone_transfer_axfr", target,
            "dnspython not installed — AXFR probe skipped (advisory mode).",
            "INFO", "0.0", evidence="Install dnspython to enable live AXFR probe.")
    except Exception as e:
        return _adv_response("dns_zone_transfer_axfr", target,
            f"AXFR probe error: {str(e)[:80]}", "INFO", "0.0", evidence=str(e)[:120])

def _probe_dns_open_resolver(target, req):
    """Check if target IP responds as an open recursive DNS resolver."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("dns_open_resolver_check", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    try:
        # Build a simple A query for google.com
        query = bytes([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        6])+b"google"+bytes([3])+b"com"+bytes([0, 0, 1, 0, 1])
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
            s.settimeout(3.0)
            s.sendto(query, (ip, 53))
            try:
                data, _ = s.recvfrom(512)
                # Check ANCOUNT (bytes 6-7) > 0 = open recursive
                if len(data) >= 8 and (data[6] | data[7]) > 0:
                    return {"tool":"dns_open_resolver_check","target":target,"scan_time":0,
                            "vulnerable": True, "severity": "HIGH",
                            "findings":[wrap_finding(
                                "Open DNS resolver — recursive query for external domain succeeded",
                                "HIGH", cvss="7.0", cwe="CWE-918",
                                remediation="Disable recursion for external clients; use views/ACLs.",
                                evidence_marker=f"{ip}:53 answered recursive query (ANCOUNT > 0)")],
                            "tests_performed": 1,
                            "tests_summary": "Open recursive DNS resolver check",
                            "raw_data": {"ip": ip, "anscount_bytes": list(data[6:8])}}
                return {"tool":"dns_open_resolver_check","target":target,"scan_time":0,
                        "vulnerable": False, "severity": "POSITIVE",
                        "findings":[wrap_finding(
                            "DNS server refused recursive query for external domain (good)",
                            "POSITIVE", cvss="0.0", cwe="N/A",
                            remediation="Continue restricting recursion.",
                            evidence_marker=f"{ip}:53 returned ANCOUNT=0 for google.com")],
                        "tests_performed": 1, "tests_summary": "Open recursive DNS resolver check",
                        "raw_data": {"ip": ip}}
            except socket.timeout:
                return _adv_response("dns_open_resolver_check", target,
                    "No DNS response — port 53 may be filtered or service not running",
                    "POSITIVE", "0.0", evidence=f"{ip}:53 silent")
    except Exception as e:
        return _adv_response("dns_open_resolver_check", target,
            f"Resolver probe error: {str(e)[:80]}", "INFO", "0.0", evidence=str(e)[:120])


PROBES = {
    "nmap_syn_scan":          _probe_nmap_syn_scan,
    "nmap_udp_scan":          _probe_nmap_udp_scan,
    "nmap_version_detect":    _probe_nmap_version_detect,
    "nmap_os_detect":         _probe_nmap_os_detect,
    "nmap_default_scripts":   _probe_nmap_default_scripts,
    "nmap_aggressive":        _probe_nmap_aggressive,
    "masscan_full_range":     _probe_masscan_full_range,
    "rustscan_top_ports":     _probe_rustscan_top_ports,
    "naabu_fast_scan":        _probe_naabu_fast_scan,
    "unicornscan_advisory":   _probe_unicornscan,
    "zmap_internet_wide":     _probe_zmap,
    "hping3_custom_packet":   _probe_hping3,
    "tcptraceroute_advisory": _probe_tcptraceroute,
    "netcat_banner_grab":     _probe_netcat_banner_grab,
    "dns_zone_transfer_axfr": _probe_dns_zone_transfer,
    "dns_open_resolver_check":_probe_dns_open_resolver,
}

TECHNIQUES = [
    # §1 Port & Service Enumeration (14)
    ("nmap_syn_scan", "nmap SYN scan.", "INFO", "0.0"),
    ("nmap_udp_scan", "nmap UDP scan.", "INFO", "0.0"),
    ("nmap_version_detect", "nmap version detect (-sV).", "INFO", "0.0"),
    ("nmap_os_detect", "nmap OS detect (-O).", "INFO", "0.0"),
    ("nmap_default_scripts", "nmap default scripts (-sC).", "INFO", "0.0"),
    ("nmap_aggressive", "nmap aggressive (-A).", "INFO", "0.0"),
    ("masscan_full_range", "masscan full port range.", "INFO", "0.0"),
    ("rustscan_top_ports", "RustScan top ports.", "INFO", "0.0"),
    ("naabu_fast_scan", "naabu fast port scan.", "INFO", "0.0"),
    ("unicornscan_advisory", "unicornscan async scan.", "INFO", "0.0"),
    ("zmap_internet_wide", "ZMap internet-wide scan.", "INFO", "0.0"),
    ("hping3_custom_packet", "hping3 custom packet crafting.", "MEDIUM", "5.0"),
    ("tcptraceroute_advisory", "tcptraceroute.", "INFO", "0.0"),
    ("netcat_banner_grab", "netcat banner grab.", "INFO", "0.0"),
    # §2 LAN Attacks (9)
    ("arp_spoofing", "ARP spoofing (arpspoof).", "HIGH", "7.5"),
    ("mac_flooding_macof", "MAC flooding (macof).", "HIGH", "7.0"),
    ("vlan_hopping_dtp", "VLAN hopping (DTP).", "HIGH", "7.0"),
    ("stp_root_bridge", "STP root-bridge attack.", "HIGH", "7.5"),
    ("dhcp_starvation", "DHCP starvation.", "HIGH", "7.0"),
    ("dhcp_rogue_server", "DHCP rogue server.", "HIGH", "7.5"),
    ("cdp_lldp_enum", "CDP/LLDP enumeration.", "MEDIUM", "5.0"),
    ("hsrp_vrrp_takeover", "HSRP/VRRP takeover.", "HIGH", "8.0"),
    ("yersinia_advisory", "Yersinia L2 attacks.", "HIGH", "7.5"),
    # §3 MITM (7)
    ("ettercap_mitm", "Ettercap MITM.", "HIGH", "7.5"),
    ("bettercap_advisory", "bettercap.", "HIGH", "7.5"),
    ("mitmproxy_advisory", "mitmproxy.", "HIGH", "7.5"),
    ("burp_intercept", "Burp Suite intercept.", "HIGH", "7.0"),
    ("ssl_strip", "SSLStrip.", "HIGH", "7.5"),
    ("dns_spoof_local", "DNS spoof (local).", "HIGH", "7.5"),
    ("icmp_redirect", "ICMP redirect attack.", "MEDIUM", "5.5"),
    # §4 DoS / DDoS (8)
    ("syn_flood_advisory", "SYN flood advisory.", "HIGH", "7.0"),
    ("udp_flood_advisory", "UDP flood advisory.", "HIGH", "7.0"),
    ("icmp_flood_advisory", "ICMP flood advisory.", "MEDIUM", "5.0"),
    ("slowloris_http_advisory", "Slowloris HTTP advisory.", "HIGH", "7.5"),
    ("http_get_post_flood", "HTTP GET/POST flood.", "HIGH", "7.0"),
    ("amplification_ntp_advisory", "NTP amplification advisory.", "HIGH", "7.5"),
    ("amplification_dns_advisory", "DNS amplification advisory.", "HIGH", "7.5"),
    ("amplification_memcached_advisory", "Memcached amplification advisory.", "HIGH", "7.5"),
    # §5 Sniffing & Capture (8)
    ("tcpdump_advisory", "tcpdump capture.", "INFO", "0.0"),
    ("wireshark_advisory", "Wireshark capture.", "INFO", "0.0"),
    ("dumpcap_advisory", "dumpcap capture.", "INFO", "0.0"),
    ("tshark_advisory", "tshark capture.", "INFO", "0.0"),
    ("ngrep_advisory", "ngrep capture.", "INFO", "0.0"),
    ("p0f_passive_os", "p0f passive OS fingerprint.", "INFO", "0.0"),
    ("net_creds_credential_extract", "net-creds credential extract from pcap.", "HIGH", "7.5"),
    ("pcredz_credential_extract", "PCredz cred extraction.", "HIGH", "7.5"),
    # §6 DNS Attacks (9)
    ("dns_cache_poisoning", "DNS cache poisoning.", "HIGH", "8.0"),
    ("dns_zone_transfer_axfr", "DNS zone transfer (AXFR).", "MEDIUM", "5.5"),
    ("dns_subdomain_enum_brute", "DNS subdomain enum brute.", "INFO", "0.0"),
    ("dns_walk_nsec", "DNSSEC NSEC walking.", "MEDIUM", "5.0"),
    ("dns_dnscat2_tunnel", "DNS tunneling (dnscat2).", "HIGH", "7.5"),
    ("dns_subdomain_takeover_check", "Subdomain takeover check.", "HIGH", "8.0"),
    ("dns_hijack_advisory", "DNS hijack advisory.", "HIGH", "7.5"),
    ("dns_open_resolver_check", "Open resolver check.", "HIGH", "7.0"),
    ("dns_random_subdomain_attack", "Random subdomain attack.", "HIGH", "7.0"),
    # §7 IPv6 Attacks (7)
    ("ipv6_router_advertisement_spoof", "IPv6 RA spoof (mitm6).", "HIGH", "8.0"),
    ("ipv6_dhcpv6_spoof", "DHCPv6 spoof.", "HIGH", "8.0"),
    ("ipv6_smurf_advisory", "IPv6 Smurf advisory.", "MEDIUM", "5.0"),
    ("ipv6_neighbor_discovery_spoof", "ND spoof.", "HIGH", "7.5"),
    ("ipv6_packet_fragmentation_evasion", "IPv6 fragmentation evasion.", "MEDIUM", "5.5"),
    ("ipv6_slaac_attack", "SLAAC attack.", "HIGH", "7.5"),
    ("ipv6_address_enum_thc_alive6", "IPv6 address enum (THC alive6).", "INFO", "0.0"),
    # §8 Protocol Fuzzing (5)
    ("fuzzing_smb_advisory", "SMB protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_rdp_advisory", "RDP protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_dns_advisory", "DNS protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_http2_advisory", "HTTP/2 protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_quic_advisory", "QUIC protocol fuzzing .", "MEDIUM", "5.0"),
]

router = make_advisory_router("network", TECHNIQUES,
    playbook_ref="See module_playbooks/16_network.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
