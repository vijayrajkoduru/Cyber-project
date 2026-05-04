#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  KALI CLEANUP — Remove old vulnerable app installations
#  Frees disk space before switching to Docker-based lab
#  Run: sudo bash cleanup-old.sh
# ══════════════════════════════════════════════════════════════
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }
rm_()  { echo -e "${RED}[-]${NC} Removing: $1"; }

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Kali Vulnerable Lab Cleanup                        ║"
echo "║   Removes old installs — replaces with Docker        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Show disk before ─────────────────────────────────────────
info "Disk usage BEFORE cleanup:"
df -h / | tail -1
echo ""

# ══════════════════════════════════════════════════════════════
# 1. STOP & REMOVE OLD DOCKER CONTAINERS + IMAGES
# ══════════════════════════════════════════════════════════════
info "Cleaning old Docker containers and images..."

# Stop all running containers
RUNNING=$(docker ps -q 2>/dev/null)
if [ -n "$RUNNING" ]; then
    warn "Stopping all running containers..."
    docker stop $RUNNING 2>/dev/null || true
fi

# Remove stopped containers
docker container prune -f 2>/dev/null && log "Removed stopped containers" || true

# Remove dangling images (untagged layers)
docker image prune -f 2>/dev/null && log "Removed dangling images" || true

# Remove old vulnerable images specifically
OLD_IMAGES=(
    "vulnerables/web-dvwa"
    "webgoat/webgoat-8.0"
    "webgoat/goatandwolf"
    "raesene/bwapp"
    "citizenstig/dvwa"
    "metasploitable"
    "tleemcjr/metasploitable2"
    "phocean/msf"
)

for img in "${OLD_IMAGES[@]}"; do
    if docker images -q "$img" 2>/dev/null | grep -q .; then
        rm_ "Docker image: $img"
        docker rmi -f "$img" 2>/dev/null || true
    fi
done

# Remove old volumes
docker volume prune -f 2>/dev/null && log "Removed unused volumes" || true
echo ""

# ══════════════════════════════════════════════════════════════
# 2. REMOVE MANUALLY INSTALLED DVWA
# ══════════════════════════════════════════════════════════════
info "Checking for manually installed DVWA..."
if [ -d "/var/www/html/dvwa" ] || [ -d "/var/www/html/DVWA" ]; then
    rm_ "/var/www/html/dvwa or DVWA"
    rm -rf /var/www/html/dvwa /var/www/html/DVWA 2>/dev/null || true
    log "DVWA web files removed"
fi

if [ -d "/opt/dvwa" ] || [ -d "/home/*/dvwa" ]; then
    rm_ "/opt/dvwa"
    rm -rf /opt/dvwa 2>/dev/null || true
fi

# ══════════════════════════════════════════════════════════════
# 3. REMOVE MANUALLY INSTALLED bWAPP
# ══════════════════════════════════════════════════════════════
info "Checking for manually installed bWAPP..."
if [ -d "/var/www/html/bWAPP" ] || [ -d "/var/www/html/bwapp" ]; then
    rm_ "/var/www/html/bWAPP"
    rm -rf /var/www/html/bWAPP /var/www/html/bwapp 2>/dev/null || true
    log "bWAPP web files removed"
fi

# ══════════════════════════════════════════════════════════════
# 4. REMOVE MANUALLY INSTALLED WebGoat / Juice Shop
# ══════════════════════════════════════════════════════════════
info "Checking for manually installed WebGoat / Juice Shop..."
for d in /opt/webgoat /opt/WebGoat /opt/juiceshop /opt/juice-shop /home/*/webgoat; do
    if [ -d "$d" ]; then
        rm_ "$d"
        rm -rf "$d" 2>/dev/null || true
    fi
done

# Remove WebGoat jar files
find /opt /home /tmp -name "webgoat*.jar" -delete 2>/dev/null || true
find /opt /home /tmp -name "juice-shop*.zip" -delete 2>/dev/null || true
log "WebGoat / Juice Shop cleared"

# ══════════════════════════════════════════════════════════════
# 5. REMOVE OLD VSFTPD INSTALLATION (system-level)
# ══════════════════════════════════════════════════════════════
info "Checking for system vsftpd installation..."
if systemctl is-active --quiet vsftpd 2>/dev/null; then
    warn "Stopping system vsftpd..."
    systemctl stop vsftpd
    systemctl disable vsftpd
fi
if dpkg -l vsftpd 2>/dev/null | grep -q "^ii"; then
    rm_ "vsftpd (system package)"
    apt-get remove -y vsftpd 2>/dev/null || true
    rm -rf /etc/vsftpd* /var/ftp 2>/dev/null || true
    log "vsftpd removed"
fi

# Remove any compiled vsftpd 2.3.4 in /tmp or /opt
find /tmp /opt -name "vsftpd" -type f -delete 2>/dev/null || true
find /tmp /opt -name "vsftpd-2.3*" -type d -exec rm -rf {} + 2>/dev/null || true

# ══════════════════════════════════════════════════════════════
# 6. REMOVE OLD PROFTPD INSTALLATION
# ══════════════════════════════════════════════════════════════
info "Checking for system ProFTPd installation..."
if systemctl is-active --quiet proftpd 2>/dev/null; then
    systemctl stop proftpd
    systemctl disable proftpd
fi
if dpkg -l proftpd-basic 2>/dev/null | grep -q "^ii"; then
    rm_ "proftpd (system package)"
    apt-get remove -y proftpd-basic proftpd 2>/dev/null || true
    rm -rf /etc/proftpd /var/log/proftpd* 2>/dev/null || true
    log "ProFTPd removed"
fi
find /tmp /opt /usr/local/proftpd -name "proftpd" -type f -delete 2>/dev/null || true

# ══════════════════════════════════════════════════════════════
# 7. REMOVE OLD SAMBA (if installed for lab purposes)
# ══════════════════════════════════════════════════════════════
info "Checking for lab-purpose Samba installation..."
# Only remove if it was for lab (don't remove if user needs it for file sharing)
if [ -f "/etc/samba/smb.conf" ]; then
    if grep -q "vulnlab\|sambacry\|vulnerable\|ctf" /etc/samba/smb.conf 2>/dev/null; then
        warn "Found lab Samba config — removing..."
        systemctl stop smbd nmbd 2>/dev/null || true
        apt-get remove -y samba samba-common-bin 2>/dev/null || true
        rm -rf /etc/samba /var/lib/samba 2>/dev/null || true
        log "Lab Samba removed"
    else
        warn "Samba found but appears to be user config — skipping (not removing)"
    fi
fi

# ══════════════════════════════════════════════════════════════
# 8. REMOVE OLD UNREALIRCD INSTALLATION
# ══════════════════════════════════════════════════════════════
info "Checking for UnrealIRCd installation..."
if pgrep -x "unreal" > /dev/null 2>&1; then
    pkill -f unreal 2>/dev/null || true
fi
for d in /home/*/Unreal* /opt/Unreal* /usr/local/unrealircd; do
    if [ -d "$d" ]; then
        rm_ "$d"
        rm -rf "$d" 2>/dev/null || true
    fi
done
find /tmp -name "Unreal*.tar.gz" -delete 2>/dev/null || true
log "UnrealIRCd cleared"

# ══════════════════════════════════════════════════════════════
# 9. REMOVE OLD APACHE / MYSQL IF ONLY USED FOR LABS
# ══════════════════════════════════════════════════════════════
info "Checking Apache / MySQL lab-only services..."

# Apache — only stop if no real sites are configured
APACHE_SITES=$(ls /etc/apache2/sites-enabled/ 2>/dev/null | grep -v "000-default" | wc -l)
if [ "$APACHE_SITES" -eq 0 ]; then
    if systemctl is-active --quiet apache2 2>/dev/null; then
        warn "Stopping Apache (no real sites detected — was likely for labs)..."
        systemctl stop apache2
        systemctl disable apache2
        log "Apache stopped"
    fi
else
    warn "Apache has active sites — leaving it running"
fi

# MySQL/MariaDB — stop if no real databases (other than dvwa/bwapp)
if command -v mysql &>/dev/null; then
    DBS=$(mysql -e "SHOW DATABASES;" 2>/dev/null | grep -vE "^(Database|information_schema|performance_schema|mysql|sys)$" | wc -l)
    if [ "$DBS" -le 2 ]; then
        warn "MySQL has only lab DBs — stopping service..."
        systemctl stop mysql mariadb 2>/dev/null || true
        systemctl disable mysql mariadb 2>/dev/null || true
        # Drop lab databases
        mysql -e "DROP DATABASE IF EXISTS dvwa; DROP DATABASE IF EXISTS bwapp; DROP DATABASE IF EXISTS webgoat;" 2>/dev/null || true
        log "MySQL lab databases dropped, service stopped"
    else
        warn "MySQL has user databases — leaving it running"
    fi
fi

# ══════════════════════════════════════════════════════════════
# 10. CLEAN UP /tmp BUILD ARTIFACTS
# ══════════════════════════════════════════════════════════════
info "Cleaning /tmp build artifacts..."
rm -rf /tmp/vsftpd* /tmp/proftpd* /tmp/Unreal* /tmp/samba* \
        /tmp/struts* /tmp/solr* /tmp/webgoat* /tmp/dvwa* \
        /tmp/bWAPP* /tmp/heartbleed* /tmp/log4* 2>/dev/null || true

# Remove old payload files from BOF/exploit testing
find /tmp -name "payload_*.elf" -o -name "payload_*.exe" -o \
          -name "masscan_*" -o -name "dnsrecon_*" -o \
          -name "amass_*" -o -name "sublist3r_*" 2>/dev/null | \
    xargs rm -f 2>/dev/null || true
log "/tmp cleaned"

# ══════════════════════════════════════════════════════════════
# 11. APT CLEANUP
# ══════════════════════════════════════════════════════════════
info "Running apt cleanup..."
apt-get autoremove -y 2>/dev/null | tail -3
apt-get autoclean -y 2>/dev/null | tail -3
apt-get clean 2>/dev/null
log "apt cache cleaned"

# ══════════════════════════════════════════════════════════════
# 12. REMOVE OLD METASPLOIT DATABASE HISTORY (optional)
# ══════════════════════════════════════════════════════════════
info "Cleaning Metasploit workspace data..."
# Remove old scan sessions but keep the MSF install
if [ -d "$HOME/.msf4" ]; then
    rm -rf $HOME/.msf4/loot/* $HOME/.msf4/logs/* 2>/dev/null || true
    find $HOME/.msf4 -name "*.log" -delete 2>/dev/null || true
    log "MSF loot/logs cleared (MSF itself kept)"
fi

# ══════════════════════════════════════════════════════════════
# DONE — Show disk after
# ══════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Cleanup Complete                                   ║"
echo "╚══════════════════════════════════════════════════════╝"
info "Disk usage AFTER cleanup:"
df -h / | tail -1
echo ""

# Show Docker disk usage
if command -v docker &>/dev/null; then
    info "Docker disk usage:"
    docker system df 2>/dev/null || true
fi

echo ""
echo "  Next step: sudo docker-compose up -d"
echo "  This will pull/build fresh Docker images for all 13 targets."
echo ""
