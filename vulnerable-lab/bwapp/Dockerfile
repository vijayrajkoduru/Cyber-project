FROM php:7.2-apache
# ── bWAPP — Buggy Web Application ───────────────────────────
# 100+ bugs: SQLi, XSS, CSRF, SSRF, XXE, LFI, RFI, Shellshock, etc.
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    mariadb-server mariadb-client \
    wget unzip \
    libpng-dev libjpeg-dev \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install mysqli pdo pdo_mysql

# Download bWAPP
WORKDIR /tmp
RUN wget -q "https://sourceforge.net/projects/bwapp/files/bWAPP/bWAPP%202.0/bWAPP_v2.2.zip" || true
RUN unzip -q bWAPP*.zip -d /var/www/html/ 2>/dev/null || true
RUN find /tmp -name "*.zip" -exec unzip -q {} -d /var/www/html/ \; 2>/dev/null || true

RUN chmod -R 777 /var/www/html/

COPY bwapp-setup.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80

CMD ["/docker-entrypoint.sh"]
