FROM tomcat:8.5-jdk8-openjdk
# ── Apache Struts2 — CVE-2017-5638 (S2-045) ─────────────────
# Content-Type OGNL injection → RCE without auth
# Exploit: set Content-Type: %{(#_='multipart/form-data')...}
ENV DEBIAN_FRONTEND=noninteractive

# Download Struts2 showcase app (uses vulnerable Struts 2.3.31)
WORKDIR /tmp
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*
RUN wget -q "https://archive.apache.org/dist/struts/2.3.31/struts-2.3.31-apps.zip" || \
    wget -q "https://archive.apache.org/dist/struts/2.5.10/struts-2.5.10-apps.zip" || true

RUN apt-get update && apt-get install -y unzip 2>/dev/null; unzip -q struts-*.zip 2>/dev/null || true
RUN find /tmp -name "struts2-showcase*.war" -exec cp {} /usr/local/tomcat/webapps/struts2.war \; 2>/dev/null || true

EXPOSE 8080

CMD ["catalina.sh", "run"]
