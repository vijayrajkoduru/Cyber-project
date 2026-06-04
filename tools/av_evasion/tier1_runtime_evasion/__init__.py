"""av_evasion tier1_runtime_evasion - AMSI / ETW / encoded-payload tests.

Each probe pushes a known-public bypass primitive over WinRM and reports
whether the customer's EDR caught it. Payloads are BENIGN (no malicious
behaviour); only the detection chain is exercised.
"""
