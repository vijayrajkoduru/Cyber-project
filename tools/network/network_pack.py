"""§16 Network Attacks — 67 endpoints per 16_network.md.
8 sections: port/service enum, LAN L2, MITM, DoS, sniffing, DNS attacks,
IPv6, protocol fuzzing.
"""
from tools._pack_common import make_advisory_router

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
    # §7 IPv6 Attacks (7) ⭐
    ("ipv6_router_advertisement_spoof", "⭐ IPv6 RA spoof (mitm6).", "HIGH", "8.0"),
    ("ipv6_dhcpv6_spoof", "⭐ DHCPv6 spoof.", "HIGH", "8.0"),
    ("ipv6_smurf_advisory", "⭐ IPv6 Smurf advisory.", "MEDIUM", "5.0"),
    ("ipv6_neighbor_discovery_spoof", "⭐ ND spoof.", "HIGH", "7.5"),
    ("ipv6_packet_fragmentation_evasion", "⭐ IPv6 fragmentation evasion.", "MEDIUM", "5.5"),
    ("ipv6_slaac_attack", "⭐ SLAAC attack.", "HIGH", "7.5"),
    ("ipv6_address_enum_thc_alive6", "⭐ IPv6 address enum (THC alive6).", "INFO", "0.0"),
    # §8 Protocol Fuzzing (5)
    ("fuzzing_smb_advisory", "SMB protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_rdp_advisory", "RDP protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_dns_advisory", "DNS protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_http2_advisory", "HTTP/2 protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_quic_advisory", "QUIC protocol fuzzing ⭐.", "MEDIUM", "5.0"),
]

router = make_advisory_router("network", TECHNIQUES,
    playbook_ref="See module_playbooks/16_network.md.")


def register(app):
    app.include_router(router)
