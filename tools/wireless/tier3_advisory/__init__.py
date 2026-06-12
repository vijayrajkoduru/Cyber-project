"""wireless tier3_advisory - honest advisory-by-design INFO scanners.

These cover the large RF / hardware / LAN-adjacent portion of
module_playbooks/18_wireless.md (WPA3 SAE, Enterprise WPA2-EAP, Rogue AP /
Evil Twin, Bluetooth/BLE active, NFC/RFID, Cellular/5G/SDR) that genuinely
CANNOT be actively probed from an external SaaS scanner — they require
monitor-mode RF hardware, physical proximity, on-host execution, or
engagement-scope authorization.

Each scanner here emits INFO-only findings with an [ADVISORY-BY-DESIGN] marker
and vulnerable:false. They never fabricate a graded severity — the planned
playbook severity is documented in remediation text, never passed through as the
finding severity. This keeps the module honest (zero false positives) while
still surfacing every technique family in the customer report with concrete
manual / red-team / on-agent guidance.
"""
