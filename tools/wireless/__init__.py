"""wireless module - 802.11 Wi-Fi + Bluetooth/BLE audit probes
(per module_playbooks/18_wireless.md).

8 sections, 84 techniques. This starter package autoloads tier*
subdirectories. Tier1 wraps Wi-Fi recon/audit (iw, airodump-ng, reaver);
Tier2 wraps Bluetooth/BLE enumeration (bluetoothctl, hcitool).

All probes are PRODUCTION-SAFE detect/audit — no active attacks, no
deauth floods, no rogue AP. They require either a monitor-mode capable
USB Wi-Fi adapter or a working bluez stack passed through to the
backend container with --privileged. On a VPS without hardware the
probes gracefully return INFO ("no monitor-mode interface available")
with a remediation hint pointing to local-runner / agent mode.
"""
