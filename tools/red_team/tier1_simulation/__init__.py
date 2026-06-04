"""tier1_simulation - LOUD adversary-emulation signals.

Each probe sends a known TTP signal (Atomic Red Team test execution,
C2 beacon pattern, DNS exfil) to a customer-controlled receiver. The
test does NOT exploit anything — it emits a deterministic signature
the customer's SIEM/EDR should detect.

Targets are customer-supplied via ScanRequest.options:
  - c2_callback_url   (HTTPS endpoint the customer's monitoring owns)
  - c2_dns_domain     (DNS zone the customer's monitoring owns)
  - exfil_dns_domain  (DNS zone for chunked DNS-exfil simulation)
  - atomic_target     (Linux SSH host or Windows WinRM host)
"""
