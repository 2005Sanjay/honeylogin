import socket
import datetime
import os
import json
import requests
import subprocess
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = "logs/attempts.log"

# Load secrets from environment
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL")
ALERT_EMAIL_PASS = os.getenv("ALERT_EMAIL_PASS")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL")   # send alert to same gmail

API_URL = "http://ip-api.com/json/"

BANNERS = [
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
    "SSH-2.0-OpenSSH_7.6",
    "SSH-2.0-OpenSSH_9.0",
]

def send_email_alert(ip, username, password, country, org):
    import smtplib
    from email.mime.text import MIMEText

    body = f"""
🔥 HoneyLogin Alert!

IP: {ip}
Username: {username}
Password: {password}
Country: {country}
Org: {org}
    """

    msg = MIMEText(body)
    msg["Subject"] = f"Honeypot Attack Detected — {ip}"
    msg["From"] = ALERT_EMAIL_FROM
    msg["To"] = ALERT_EMAIL_TO

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(ALERT_EMAIL_FROM, ALERT_EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        print(f"[ALERT] Email sent for IP {ip}!")
    except Exception as e:
        print("[ERROR] Failed to send email:", e)


def block_ip(ip):
    print(f"[BLOCKER] Blocking IP: {ip}")

    try:
        subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True)
        print(f"[BLOCKER] Blocked using UFW: {ip}")
    except Exception as e:
        print("[ERROR] Failed to block:", e)


def geo_lookup(ip):
    try:
        r = requests.get(API_URL + ip, timeout=3)
        data = r.json()

        return {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "org": data.get("org", "Unknown"),
            "lat": data.get("lat", None),
            "lon": data.get("lon", None)
        }
    except:
        return {"country": "Unknown", "city": "Unknown", "org": "Unknown", "lat": None, "lon": None}


def log_attempt(ip, username, password):
    info = geo_lookup(ip)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = {
        "time": ts,
        "ip": ip,
        "username": username,
        "password": password,
        "country": info["country"],
        "city": info["city"],
        "org": info["org"],
        "lat": info["lat"],
        "lon": info["lon"]
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    send_email_alert(ip, username, password, info["country"], info["org"])
    block_ip(ip)


def start_honeypot():
    print("[+] HoneyLogin running with GeoIP + Alerts + Blocking + Banner Rotation on port 2222...")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 2222))
    server.listen(5)

    while True:
        client, addr = server.accept()
        ip = addr[0]

        banner = BANNERS[datetime.datetime.now().second % len(BANNERS)]
        client.send((banner + "\n").encode())

        client.send(b"username: ")
        username = client.recv(1024).decode().strip()

        client.send(b"password: ")
        password = client.recv(1024).decode().strip()

        log_attempt(ip, username, password)
        client.send(b"Access denied.\n")
        client.close()


if __name__ == "__main__":
    if not os.path.exists("logs"):
        os.makedirs("logs")

    start_honeypot()

