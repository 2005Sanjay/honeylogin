import socket
import datetime
import requests
import json
import os
import sys
import smtplib
from email.mime.text import MIMEText
from collections import Counter, defaultdict
import time
import random
import subprocess

HOST = "0.0.0.0"
PORT = 2222

# Email settings
ALERT_EMAIL_TO = "sanjaymeenakumar06@gmail.com"
ALERT_EMAIL_FROM = "sanjaymeenakumar06@gmail.com"
ALERT_EMAIL_PASS = "iyab hpfp wroc sbjr"   # <-- Replace this

# Brute force detection
attempt_window = defaultdict(list)
ALERT_THRESHOLD = 10
ALERT_TIME_WINDOW = 60  # seconds

# SSH banner rotation
BANNERS = [
    b"SSH-2.0-OpenSSH_8.9\r\n",
    b"SSH-2.0-OpenSSH_7.6\r\n",
    b"SSH-2.0-OpenSSH_6.4\r\n",
    b"SSH-2.0-dropbear_2016.74\r\n",
    b"SSH-2.0-Cisco-1.25\r\n",
    b"SSH-2.0-Fortinet_5.4\r\n",
    b"SSH-2.0-OpenSSH_9.0\r\n",
    b"SSH-2.0-OpenSSH_5.3\r\n"
]


# ----------------------- GEOIP LOOKUP ---------------------------

def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        if response.status_code == 200:
            data = response.json()
            return data.get("country", "Unknown"), data.get("city", "Unknown"), data.get("org", "Unknown")
        else:
            return "Unknown", "Unknown", "Unknown"
    except:
        return "Unknown", "Unknown", "Unknown"


# ---------------------- IP BLOCKER ------------------------------

def block_ip(ip):
    print(f"[BLOCKER] Blocking IP: {ip}")
    try:
        # Try UFW first
        subprocess.run(["sudo", "ufw", "deny", "from", ip], check=False)
        print(f"[BLOCKER] Blocked using UFW: {ip}")
    except:
        print("[BLOCKER] UFW failed, trying iptables...")
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=False)
            print(f"[BLOCKER] Blocked using iptables: {ip}")
        except:
            print("[BLOCKER ERROR] Could not block IP")


# ---------------------- EMAIL ALERT ------------------------------

def send_alert(ip, attempts):
    subject = f"⚠️ HoneyLogin Alert: Brute-force Detected from {ip}"
    body = f"""
HoneyLogin Honeypot Alert 🚨

An IP has triggered brute-force detection.

IP Address: {ip}
Attempts in last {ALERT_TIME_WINDOW} seconds: {len(attempts)}

GeoIP Info:
Country: {get_ip_info(ip)[0]}
City: {get_ip_info(ip)[1]}
Organization / ISP: {get_ip_info(ip)[2]}

>> IP has been automatically BLOCKED by firewall <<

Stay safe 💀  
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = ALERT_EMAIL_FROM
    msg["To"] = ALERT_EMAIL_TO

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(ALERT_EMAIL_FROM, ALERT_EMAIL_PASS)
        server.sendmail(ALERT_EMAIL_FROM, ALERT_EMAIL_TO, msg.as_string())
        server.quit()
        print(f"[ALERT] Email sent for IP {ip}!")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

    # 🔥 Block the attacker
    block_ip(ip)


def check_bruteforce(ip):
    now = time.time()
    attempt_window[ip].append(now)

    # Keep only recent attempts
    attempt_window[ip] = [t for t in attempt_window[ip] if now - t <= ALERT_TIME_WINDOW]

    if len(attempt_window[ip]) >= ALERT_THRESHOLD:
        send_alert(ip, attempt_window[ip])
        attempt_window[ip].clear()


# ---------------------- LOGGING SYSTEM ---------------------------

def log_attempt(ip, username, password):
    country, city, org = get_ip_info(ip)
    time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_line = f"[{time_now}] {ip} ({country}, {city} - {org}) tried {username}:{password}\n"
    with open("logs/attempts.log", "a") as f:
        f.write(log_line)

    json_data = {
        "time": time_now,
        "ip": ip,
        "country": country,
        "city": city,
        "org": org,
        "username": username,
        "password": password
    }

    with open("logs/attempts.json", "a") as jf:
        jf.write(json.dumps(json_data) + "\n")

    check_bruteforce(ip)


# ---------------------- STATS MODE ------------------------------

def show_stats():
    file = "logs/attempts.json"
    if not os.path.exists(file):
        print("No logs yet!")
        return

    ips = []
    usernames = []
    passwords = []
    countries = []
    orgs = []

    with open(file, "r") as jf:
        for line in jf:
            entry = json.loads(line)
            ips.append(entry["ip"])
            usernames.append(entry["username"])
            passwords.append(entry["password"])
            countries.append(entry["country"])
            orgs.append(entry["org"])

    print("\n======= HoneyLogin Stats =======\n")
    print("Total attempts:", len(ips))

    print("\n🔥 Top IPs:")
    for ip, c in Counter(ips).most_common(5):
        print(ip, c)

    print("\n🔐 Top Usernames:")
    for u, c in Counter(usernames).most_common(5):
        print(u, c)

    print("\n🔑 Top Passwords:")
    for p, c in Counter(passwords).most_common(5):
        print(p, c)

    print("\n🌍 Countries:")
    for ct, c in Counter(countries).most_common():
        print(ct, c)

    print("\n🏢 ISPs:")
    for o, c in Counter(orgs).most_common(5):
        print(o, c)

    print("\n================================")


# ---------------------- HONEYPOT SERVER -------------------------

def start_honeypot():
    if not os.path.exists("logs"):
        os.mkdir("logs")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)

    print(f"[+] HoneyLogin running with GeoIP + Stats + Alert + Banner Rotation + IP Blocker on port {PORT}...")

    while True:
        conn, addr = sock.accept()
        ip = addr[0]

        # Random SSH banner
        banner = random.choice(BANNERS)
        conn.send(banner)

        conn.send(b"username: ")
        username = conn.recv(1024).strip().decode()

        conn.send(b"password: ")
        password = conn.recv(1024).strip().decode()

        log_attempt(ip, username, password)

        conn.send(b"Access denied.\n")
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--stats":
        show_stats()
    else:
        start_honeypot()

