#!/bin/bash
service mariadb start
sleep 3
mysql -e "CREATE DATABASE bwapp;" 2>/dev/null || true
mysql -e "CREATE USER 'bwapp'@'localhost' IDENTIFIED BY 'bug';" 2>/dev/null || true
mysql -e "GRANT ALL PRIVILEGES ON bwapp.* TO 'bwapp'@'localhost';" 2>/dev/null || true
mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
apache2-foreground
