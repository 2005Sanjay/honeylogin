🛡️ HoneyLogin — Advanced SSH Honeypot with Real-Time Attack Dashboard

A fully featured cybersecurity honeypot that captures attacker login attempts, performs GeoIP lookups, triggers email alerts, blocks malicious IPs, and displays everything inside a professional SOC-style dashboard with a real-time world attack map, charts, analytics, and export tools.

This project is designed to be beginner-friendly, powerful, and portfolio-ready.

🚀 Features
🛡️ Honeypot Engine (SSH Fake Login)

Runs on port 2222

Accepts all credentials (fake login)

Logs every attempt with:

IP address

Username

Password

Timestamp

GeoIP data (country, city, org, lat/lon)

All logs are stored in:
logs/attempts.log

🌍 Real-Time World Attack Map

A full-width interactive global attack map powered by Leaflet.

Features include:

📍 Pin markers for attackers

🔵 Bubble circles (size = number of attempts)

🔥 Heatmap mode (toggle ON/OFF)

🎯 Click on Top IP → Center map on attacker

🌎 Country fallback (local/unknown IPs mapped to country centroid)

🔄 Auto-refresh every 10 seconds

Perfect SOC-style visualization.

📊 Advanced SOC Dashboard

Accessible at:
http://127.0.0.1:5000/login

Includes:

✔ Charts

Username distribution (Pie)

Password frequency (Bar)

Hourly attack timeline (Line)

Country distribution

✔ Stats

Total attack attempts

Top 5 IPs

Top usernames

Top passwords

✔ Filters

Search logs by:

IP

Country

Username

Limit results

✔ Export tools

Export CSV

Export JSON

Export Excel (XLSX)

🔐 Dashboard Login

Secure admin login using .env stored credentials:
ADMIN_USER=Darkseid
ADMIN_PASS=Darkseid28_2005!

Session based, protected pages)
📬 Email Alerts

Instant email notifications when an attacker logs in.

Format:
🔥 Honeypot Alert!

IP: 185.144.xx.xx
Username: admin
Password: 123456
Country: Russia
Org: AS35624

Uses secure Gmail App Passwords (not real Gmail password).
🚫 Automatic IP Blocking

Using UFW:

Detect attacker → block instantly

Prevents repeated brute-forcing

Every block is logged

Example:
[BLOCKER] Blocking IP: 185.14.28.9
[BLOCKER] Blocked using UFW: 185.14.28.9

🔐 Security (Secrets Hidden Using .env)

Secrets like:

Gmail address

Gmail app password

Dashboard admin user/password

are stored in:
.env

and never pushed to GitHub.
.gitignore contains:
.env
venv/
__pycache__/

This keeps your public repo 100% safe.
🏗️ Project Structure
honeylogin/
│
├── honeypot.py                 # Main SSH honeypot
├── logs/
│   └── attempts.log            # Captured attacks
│
├── dashboard/
│   ├── app.py                  # Flask backend
│   └── templates/
│       ├── base.html
│       ├── login.html
│       └── dashboard.html      # UI + charts + map
│
├── .env                        # (Not included in repo)
├── .gitignore
└── README.md

⚙️ Setup Instructions
1. Clone the repo
git clone https://github.com/2005Sanjay/honeylogin.git
cd honeylogin

🧪 Create virtual environment
python3 -m venv venv
source venv/bin/activate

🔐 Create .env file
ALERT_EMAIL=yourgmail@gmail.com
ALERT_EMAIL_PASS=your_gmail_app_password

ADMIN_USER=Darkseid
ADMIN_PASS=Darkseid28_2005!

📦 Install dependencies
pip install -r dashboard/requirements.txt
pip install python-dotenv requests pandas openpyxl

🛡️ Run the Honeypot
python3 honeypot.py

Honeypot will start listening on port 2222.

📊 Run the Dashboard
python3 dashboard/app.py

Open in browser:
http://127.0.0.1:5000/login

🎯 Future Enhancements (Optional)

You can extend this project with:

Telegram alerts

IP reputation lookup (AbuseIPDB API)

Dark web monitoring

Attacker behavior profiling

Live attack feed (WebSocket)

Cloud deployment (AWS, Railway, Render)

SSH interaction recording (Cowrie-style)

❤️ Developed by
👤 Sanjay



