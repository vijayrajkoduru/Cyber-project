"""§30 IoT/OT/ICS Security — 58 endpoints per 30_iot_ot.md."""
from tools._pack_common import make_advisory_router

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
    # §7 Matter/Smart Home (4) ⭐
    ("matter_commissioning_audit", "⭐ Matter commissioning audit.", "MEDIUM", "5.5"),
    ("matter_pase_pake_audit", "⭐ Matter PASE/PAKE audit.", "MEDIUM", "5.5"),
    ("matter_otacert_audit", "⭐ Matter OTA cert audit.", "MEDIUM", "5.5"),
    ("manual_matter_review", "Manual Matter review.", "INFO", "0.0"),
    # §8 OT Pentest Methodology (4)
    ("ot_safety_first_audit", "OT safety-first audit.", "INFO", "0.0"),
    ("ot_lockout_procedure", "OT lockout/tagout procedure check.", "INFO", "0.0"),
    ("ot_change_management", "OT change management audit.", "INFO", "0.0"),
    ("manual_ot_pentest_planning", "Manual OT pentest planning.", "INFO", "0.0"),
]

router = make_advisory_router("iot_ot", T,
    playbook_ref="See module_playbooks/30_iot_ot.md.")


def register(app):
    app.include_router(router)
