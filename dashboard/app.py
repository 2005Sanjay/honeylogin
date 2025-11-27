import os
import json
import datetime
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
from dotenv import load_dotenv

load_dotenv()

ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASS = os.getenv("ADMIN_PASS")

LOG_FILE = "../logs/attempts.log"

app = Flask(__name__)
app.secret_key = "supersecretkey123"   # safe to keep (just session cookie)


# ----------------------------- Utility ---------------------------------

def read_logs():
    rows = []
    if not os.path.exists(LOG_FILE):
        return rows

    for line in open(LOG_FILE):
        try:
            rows.append(json.loads(line.strip()))
        except:
            pass
    return rows


def compute_stats(rows):
    from collections import Counter

    ips = Counter([r["ip"] for r in rows])
    users = Counter([r["username"] for r in rows])
    pwds = Counter([r["password"] for r in rows])
    countries = Counter([r["country"] for r in rows])

    return {
        "total": len(rows),
        "top_ips": ips.most_common(5),
        "top_users": users.most_common(5),
        "top_pwds": pwds.most_common(5),
        "countries": countries
    }


# ----------------------------- Auth ---------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")

        if u == ADMIN_USER and p == ADMIN_PASS:
            session["logged_in"] = True
            session["user"] = u
            return redirect("/dashboard")
        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ----------------------------- Map Data API --------------------------

@app.route("/mapdata")
def mapdata():
    rows = read_logs()
    points = {}

    for r in rows:
        ip = r["ip"]
        if ip not in points:
            points[ip] = {
                "ip": ip,
                "count": 0,
                "country": r["country"],
                "city": r["city"],
                "org": r["org"],
                "lat": r["lat"],
                "lon": r["lon"],
                "usernames": set(),
                "passwords": set(),
                "last_seen": r["time"]
            }

        points[ip]["count"] += 1
        points[ip]["usernames"].add(r["username"])
        points[ip]["passwords"].add(r["password"])
        points[ip]["last_seen"] = r["time"]

    # convert sets to lists
    for ip in points:
        points[ip]["usernames"] = list(points[ip]["usernames"])
        points[ip]["passwords"] = list(points[ip]["passwords"])

    return jsonify({"data": list(points.values()), "now": datetime.datetime.now().timestamp()})


# ----------------------------- Dashboard -----------------------------

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect("/login")

    rows = read_logs()
    stats = compute_stats(rows)

    # prepare chart data
    username_labels = [u for u, _ in stats["top_users"]]
    username_values = [c for _, c in stats["top_users"]]

    password_labels = [p for p, _ in stats["top_pwds"]]
    password_values = [c for _, c in stats["top_pwds"]]

    # hourly counts
    hour_counts = {}
    for r in rows:
        h = datetime.datetime.strptime(r["time"], "%Y-%m-%d %H:%M:%S").hour
        hour_counts[h] = hour_counts.get(h, 0) + 1

    hour_labels = list(range(24))
    hour_values = [hour_counts.get(h, 0) for h in hour_labels]

    return render_template(
        "dashboard.html",
        total=stats["total"],
        top_ips=stats["top_ips"],
        top_users=stats["top_users"],
        top_pwds=stats["top_pwds"],
        countries=stats["countries"],
        username_labels=username_labels,
        username_values=username_values,
        password_labels=password_labels,
        password_values=password_values,
        hour_labels=hour_labels,
        hour_values=hour_values,
        recent=rows[-50:]  # last 50 attempts
    )


# ----------------------------- Export Routes -------------------------

@app.route("/export/csv")
def export_csv():
    rows = read_logs()
    df = pd.DataFrame(rows)
    df.to_csv("export.csv", index=False)
    return send_file("export.csv", as_attachment=True)


@app.route("/export/json")
def export_json():
    rows = read_logs()
    with open("export.json", "w") as f:
        json.dump(rows, f, indent=4)
    return send_file("export.json", as_attachment=True)


@app.route("/export/excel")
def export_excel():
    rows = read_logs()
    df = pd.DataFrame(rows)
    df.to_excel("export.xlsx", index=False)
    return send_file("export.xlsx", as_attachment=True)


# ----------------------------- Run App -------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

