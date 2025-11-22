HoneyLogin – Simple SSH Honeypot

A lightweight, beginner-friendly SSH honeypot built using Python.
It simulates a fake SSH server, logs attacker login attempts, and helps you understand brute-force behavior safely.

🚀 Features:

Fake SSH service running on port 2222

Logs:

Username

Password

Attacker IP

Timestamp

Python socket-based design

Easy to run locally or on a VPS

Beginner friendly honeypot project


Project Structure:

honeylogin/
 ├── honeypot.py
 ├── logs/
 │    └── attempts.log
 └── README.md


How HoneyLogin Works:

Opens a TCP socket on port 2222

Pretends to be an SSH server (SSH-2.0-OpenSSH_8.9)

Asks for username and password

Logs whatever the attacker enters

Always returns Access denied

This shows how attackers attempt brute-force logins in real life.

🛠️ Installation:

1. Clone this repository:

git clone https://github.com/<your-username>/honeylogin.git
cd honeylogin

2. Create the logs folder:

mkdir logs

3. Run the honeypot:

python3 honeypot.py


You should see:

[+] HoneyLogin is running on port 2222...


🧪 Testing the Honeypot

Open a second terminal:

nc 127.0.0.1 2222


You will see:
SSH-2.0-OpenSSH_8.9
username:


Enter anything:

admin
123456


📄 Log Output Example

Logs are saved inside:
logs/attempts.log


Example:

[2025-11-22 17:14:10] 127.0.0.1 tried admin:123456


⚠️ Security Notes

Do NOT run this on real SSH port (22)

Do NOT use this in production systems

Honeypots attract bots → use firewall rules

Education / research purpose only

🎯 Future Enhancements

GeoIP lookup (attacker country)

Dashboard for viewing attempts

Alert system for repeated brute-force attempts

JSON formatted logs

Statistics page

IP blocking module

🤝 Contributor

Sanjay M (Developer)

📜 License

MIT License


