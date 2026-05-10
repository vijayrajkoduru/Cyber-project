# Every Morning Checklist

## 1. Check VPS is Running
Open your dashboard in browser.
- Green dot = Online (good)
- Red dot = Backend offline (check VPS)

If offline, SSH into VPS and run:
```bash
docker compose ps
docker compose up -d
```

---

## MORNING ONE-LINE COMMAND (Run This First)
```bash
echo "=== CONTAINERS ===" && docker compose ps && echo "=== DISK ===" && df -h && echo "=== USERS ===" && docker exec oscp_backend sqlite3 /app/data/users.db "SELECT username, plan, created_at FROM users;"
```
Shows containers + disk space + registered users — all in one shot.

---

## 2. Check Disk Space
```bash
cat /root/disk.log
```
- Above 80% used = run manual cleanup
- Below 80% = fine, do nothing

Manual cleanup if needed:
```bash
docker image prune -f
docker builder prune -f --keep-storage 2gb
```

---

## 3. Check All Containers Running
```bash
docker compose ps
```
All should show status: **Up**

If any container is down:
```bash
docker compose up -d
```

---

## 4. Deploy New Code (Only If You Changed Something)
```bash
cd ~/Cyber-project
git pull origin main
docker compose up -d --build
```
Wait 2-3 minutes then refresh dashboard.

---

## 5. Quick Scan Test (2 minutes)
- Open dashboard
- Target: `http://testphp.vulnweb.com`
- Run XSS Scanner → should show CRITICAL
- Run SQL Injection → should show CRITICAL
- If both show CRITICAL = everything working

---

## 6. Check Logs If Something Feels Wrong
```bash
# See backend errors
docker logs oscp_backend --tail 50

# See cleanup log
cat /root/disk.log

# See all running containers
docker compose ps
```

---

## Weekly (Every Monday)
- [ ] Check how many users registered
- [ ] Check scan history is working
- [ ] Test Register + Login with a new account
- [ ] Check disk space trend in /root/disk.log

---

## Quick SSH Command (Save This)
```bash
ssh root@YOUR_VPS_IP
```

---

## Emergency — Dashboard Down
```bash
# Step 1
docker compose ps

# Step 2 - restart everything
docker compose down
docker compose up -d

# Step 3 - if still down, full rebuild
docker compose build --no-cache backend
docker compose up -d
```
