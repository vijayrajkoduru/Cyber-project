"""firmware module - Embedded / IoT firmware static audit (playbook 31_firmware.md).

8 sections, 76 techniques. This package autoloads tier* subdirectories,
each containing real Python probes that wrap binwalk / radare2 / jefferson /
custom byte-pattern scanners. Customer provides a firmware blob path at
scan time via ScanRequest.target = /tmp/<uploaded>.bin
"""
