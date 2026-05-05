#!/bin/bash
# Run this ONCE on Kali to install all dependencies for the OSCP Dashboard
# Usage: sudo bash setup_dependencies.sh

set -e
echo "=== OSCP Dashboard — Dependency Setup ==="

# Core network tools
apt-get install -y nmap masscan nikto gobuster dirb hydra sqlmap wafw00f whatweb \
  dnsrecon whois dnsx subfinder amass tcpdump hping3 arpspoof ettercap-text-only \
  netcat-openbsd theharvester dnschef responder seclists wordlists

# Install subfinder if not via apt
if ! command -v subfinder &>/dev/null; then
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
fi

# Wordlists
apt-get install -y wordlists dirb seclists 2>/dev/null || true
[ -f /usr/share/wordlists/rockyou.txt.gz ] && gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Masscan passwordless sudo (required — masscan needs raw socket access)
SUDOERS_LINE="kali ALL=(ALL) NOPASSWD: /usr/bin/masscan"
grep -qF "$SUDOERS_LINE" /etc/sudoers || echo "$SUDOERS_LINE" >> /etc/sudoers
echo "  masscan sudo: OK"

# Verify key tools
echo ""
echo "=== Tool Check ==="
for tool in nmap nikto gobuster hydra sqlmap wafw00f whatweb dnsrecon whois theharvester subfinder amass tcpdump hping3; do
  if command -v "$tool" &>/dev/null; then
    echo "  [OK]  $tool"
  else
    echo "  [MISSING] $tool — install manually: apt install $tool"
  fi
done

echo ""
echo "=== Wordlist Check ==="
for wl in /usr/share/wordlists/dirb/common.txt /usr/share/wordlists/rockyou.txt /usr/share/seclists/Discovery/Web-Content/common.txt; do
  [ -f "$wl" ] && echo "  [OK]  $wl" || echo "  [MISSING] $wl"
done

echo ""
echo "All done! Restart the backend:"
echo "  pkill -f uvicorn; uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
