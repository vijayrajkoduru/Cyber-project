#!/usr/bin/env bash
# lab_watchdog.sh -- keep practice labs up. A restart policy only recovers a
# container that EXITS; this also recovers one that is hung (running but
# unhealthy) or missing. Only ever touches lab_* containers. Safe to run on
# a cron, e.g.:  */5 * * * * /root/Cyber-project/scripts/lab_watchdog.sh
set -u
cd "$(dirname "$0")/.." || exit 1
LOG="${LAB_WATCHDOG_LOG:-/root/Cyber-project/data/lab_watchdog.log}"
mkdir -p "$(dirname "$LOG")" 2>/dev/null
ts(){ date '+%Y-%m-%d %H:%M:%S'; }
log(){ echo "$(ts) $*" | tee -a "$LOG"; }

# Labs that should always be running (match docker-compose service list).
LABS="lab_dvwa lab_juiceshop lab_bwapp lab_mutillidae lab_webgoat lab_pwd_ssh lab_pwd_smb lab_pwd_web"

restarted=0
for c in $LABS; do
    exists=$(docker ps -a --filter "name=^/${c}$" --format '{{.Names}}' 2>/dev/null)
    if [ -z "$exists" ]; then
        # Not created at all -> bring it up from compose (service name == container name here).
        log "MISSING $c -> docker compose up -d $c"
        docker compose up -d "$c" >>"$LOG" 2>&1 && restarted=$((restarted+1))
        continue
    fi
    running=$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)
    health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c" 2>/dev/null)
    if [ "$running" != "true" ]; then
        log "DOWN $c (running=$running) -> docker start"
        docker start "$c" >>"$LOG" 2>&1 && restarted=$((restarted+1))
    elif [ "$health" = "unhealthy" ]; then
        log "UNHEALTHY $c -> docker restart"
        docker restart "$c" >>"$LOG" 2>&1 && restarted=$((restarted+1))
    fi
done

[ "$restarted" -gt 0 ] && log "watchdog recovered $restarted lab(s)" || true
exit 0
