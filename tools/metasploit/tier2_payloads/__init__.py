"""tier2_payloads - msfvenom benign payload test + post-ex module catalog.

The payload generation probe uses CMD=calc.exe (a benign payload that
launches the Windows calculator) and discards the resulting shellcode.
The catalog probe inventories post-exploitation modules available in the
customer's MSF installation - no exploitation is performed.
"""
