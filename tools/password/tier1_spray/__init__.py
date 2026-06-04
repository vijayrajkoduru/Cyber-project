"""tier1_spray - online password spray + brute-force probes.

Each probe wraps a Kali-installed engine (hydra/ncrack/medusa/patator)
against a single live service on the customer's target. Engines are
detected via shutil.which; missing binary returns an INFO finding.
"""
