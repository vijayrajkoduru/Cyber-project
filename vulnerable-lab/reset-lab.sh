#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  RESET LAB — Wipe all lab Docker containers + images
#  Use this when lab containers are broken or you want a clean start
#  Run: sudo bash reset-lab.sh
# ══════════════════════════════════════════════════════════════
echo "Stopping and removing all lab containers..."
docker-compose down --volumes --remove-orphans 2>/dev/null || true

echo "Removing lab images..."
docker images | grep "vuln-\|vulnerable-lab" | awk '{print $3}' | xargs docker rmi -f 2>/dev/null || true

echo "Pruning unused Docker resources..."
docker system prune -f 2>/dev/null || true

echo ""
echo "Docker disk after reset:"
docker system df

echo ""
echo "Rebuild and start: sudo docker-compose up -d --build"
