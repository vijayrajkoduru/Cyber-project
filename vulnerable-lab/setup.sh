#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  OSCP Vulnerable Lab — Setup Script
#  Run this on Kali Linux to install everything
# ══════════════════════════════════════════════════════════════
set -e

echo "╔══════════════════════════════════════════╗"
echo "║   OSCP Vulnerable Lab Setup              ║"
echo "║   13 targets — Linux + Windows-style     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Step 1: Install Docker ─────────────────────────────────
echo "[1/4] Installing Docker..."
if ! command -v docker &>/dev/null; then
    apt-get update -qq
    apt-get install -y docker.io docker-compose
    systemctl enable docker
    systemctl start docker
    echo "✓ Docker installed"
else
    echo "✓ Docker already installed: $(docker --version)"
fi

# ── Step 2: Install Docker Compose ─────────────────────────
if ! command -v docker-compose &>/dev/null; then
    apt-get install -y docker-compose
fi
echo "✓ Docker Compose: $(docker-compose --version)"

# ── Step 3: Copy lab files to ~/vulnerable-lab ─────────────
echo "[2/4] Setting up lab directory..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$HOME/vulnerable-lab"

if [ "$SCRIPT_DIR" != "$LAB_DIR" ]; then
    cp -r "$SCRIPT_DIR"/* "$LAB_DIR/" 2>/dev/null || true
fi

cd "$LAB_DIR"
echo "✓ Lab directory: $LAB_DIR"

# ── Step 4: Pull + Build images ────────────────────────────
echo "[3/4] Pulling Docker images (takes a few minutes)..."
docker-compose pull 2>/dev/null || true
echo ""
echo "[4/4] Building custom images (vsftpd, samba, shellshock, etc.)..."
docker-compose build --parallel 2>/dev/null || docker-compose build

# ── Start lab ──────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Starting all 13 containers...          ║"
echo "╚══════════════════════════════════════════╝"
docker-compose up -d

sleep 3
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Lab Status                                             ║"
echo "╠══════════════════════════════════════════════════════════╣"
docker-compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || docker-compose ps
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   TARGET IPs (use in OSCP Dashboard)                    ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  DVWA          →  172.20.0.10   port 80                ║"
echo "║  WebGoat       →  172.20.0.11   port 8080              ║"
echo "║  Juice Shop    →  172.20.0.12   port 3000              ║"
echo "║  Mutillidae    →  172.20.0.13   port 80                ║"
echo "║  bWAPP         →  172.20.0.14   port 80                ║"
echo "║  vsftpd 2.3.4  →  172.20.0.20   port 21  CVE-2011-2523 ║"
echo "║  SambaCry      →  172.20.0.21   port 445 CVE-2017-7494 ║"
echo "║  Struts2 RCE   →  172.20.0.22   port 8080 CVE-2017-5638║"
echo "║  Shellshock    →  172.20.0.23   port 80  CVE-2014-6271 ║"
echo "║  Heartbleed    →  172.20.0.24   port 443 CVE-2014-0160 ║"
echo "║  Log4Shell     →  172.20.0.25   port 8983 CVE-2021-44228║"
echo "║  UnrealIRCd    →  172.20.0.26   port 6667 CVE-2010-2075║"
echo "║  ProFTPd       →  172.20.0.27   port 21  CVE-2010-4221 ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Your Kali IP → $(ip route get 1 | awk '{print $7}' | head -1)                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Dashboard: http://localhost:3000"
echo "  Stop lab:  docker-compose down"
echo "  Logs:      docker-compose logs -f <service>"
echo ""
