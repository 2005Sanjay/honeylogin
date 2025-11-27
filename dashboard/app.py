# dashboard/app.py
import os
import json
import hashlib
import time
from collections import Counter, defaultdict
from datetime import datetime
from dateutil import parser
from flask import Flask, render_template, request, url_for, redirect, session, flash, send_file, jsonify

import pandas as pd
from io import BytesIO
import requests

# ================================
# PATHS
# ================================
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_JSON = os.path.join(os.path.dirname(APP_ROOT), "logs", "attempts.json")
MAP_CACHE = os.path.join(APP_ROOT, "map_cache.json")  # store ip -> {loc,country,city,org,last_seen}

# ================================
# FLASK APP SETUP
# ================================
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("HONEYLOGIN_SECRET_KEY", "change_this_secret")

# ================================
# LOGIN CREDENTIALS
# ================================
DASH_USER = "Darkseid"
_RAW_PASSWORD = "Darkseid28_2005!"
DASH_PASS_HASH = hashlib.sha256(_RAW_PASSWORD.encode()).hexdigest()

# ================================
# UTIL: MAP CACHE
# ================================
def load_map_cache():
    if os.path.exists(MAP_CACHE):
        try:
            return json.load(open(MAP_CACHE, "r"))
        except:
            return {}
    return {}

def save_map_cache(cache):
    try:
        json.dump(cache, open(MAP_CACHE, "w"), indent=2)
    except Exception as e:
        print("Failed to save map cache:", e)

# Use ipinfo.io free endpoint to get location (no token required for low volume)
def fetch_ipinfo(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=4)
        if r.status_code == 200:
            data = r.json()
            loc = data.get("loc")  # "lat,lng"
            if loc:
                lat, lon = loc.split(",")
                return {
                    "lat": float(lat),
                    "lon": float(lon),
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "org": data.get("org", "Unknown")
                }
    except Exception as e:
        # network problems or rate-limit — fail gracefully
        print("ipinfo error for", ip, e)
    return None

# ================================
# READ LOG FILES
# ================================
def read_logs():
    entries = []
    if not os.path.exists(LOG_JSON):
        return entries

    try:
        with open(LOG_JSON, "r") as jf:
            for line in jf:
                try:
                    obj = json.loads(line)
                    obj["_ts"] = parser.parse(obj["time"]) if "time" in obj else datetime.now()
                    entries.append(obj)
                except:
                    continue
    except Exception as e:
        print("Error reading logs:", e)

    entries.sort(key=lambda x: x["_ts"], reverse=True)
    return entries

# ================================
# COMPUTE STATISTICS
# ================================
def compute_stats(entries):
    ips = [e.get("ip") for e in entries]
    users = [e.get("username") for e in entries]
    pwds = [e.get("password") for e in entries]
    countries = [e.get("country", "Unknown") for e in entries]

    stats = {
        "total": len(entries),
        "top_ips": Counter(ips).most_common(8),
        "top_users": Counter(users).most_common(8),
        "top_pwds": Counter(pwds).most_common(8),
        "country_dist": Counter(countries).most_common(20),
    }
    return stats

# ================================
# AUTH HELPERS
# ================================
def check_auth():
    return session.get("logged_in", False)

def require_login(func):
    def wrapper(*args, **kwargs):
        if not check_auth():
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# ================================
# ROUTES: AUTH
# ================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if check_auth():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username != DASH_USER:
            flash("Invalid credentials", "danger")
            return render_template("login.html")

        if hashlib.sha256(password.encode()).hexdigest() != DASH_PASS_HASH:
            flash("Invalid credentials", "danger")
            return render_template("login.html")

        session["logged_in"] = True
        session["user"] = username
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ================================
# MAIN DASHBOARD
# ================================
@app.route("/")
def index():
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
@require_login
def dashboard():
    entries = read_logs()
    stats = compute_stats(entries)

    # filters
    q_ip = request.args.get("ip", "").strip()
    q_country = request.args.get("country", "").strip()
    q_user = request.args.get("username", "").strip()
    try:
        q_limit = int(request.args.get("limit", 50))
    except:
        q_limit = 50

    filtered = entries
    if q_ip:
        filtered = [e for e in filtered if e["ip"] == q_ip]
    if q_country:
        filtered = [e for e in filtered if e.get("country", "").lower() == q_country.lower()]
    if q_user:
        filtered = [e for e in filtered if e.get("username", "").lower() == q_user.lower()]

    recent = filtered[:q_limit]

    # prepare graph data
    country_labels = [c for c, _ in stats["country_dist"]]
    country_data = [v for _, v in stats["country_dist"]]

    username_labels = [u for u, _ in stats["top_users"]]
    username_values = [c for _, c in stats["top_users"]]

    password_labels = [p for p, _ in stats["top_pwds"]]
    password_values = [c for _, c in stats["top_pwds"]]

    # hourly graph
    hour_counts = {}
    for e in entries:
        hour = e["_ts"].hour
        hour_counts[hour] = hour_counts.get(hour, 0) + 1

    hour_labels = list(range(24))
    hour_values = [hour_counts.get(h, 0) for h in hour_labels]

    return render_template(
        "dashboard.html",
        total=stats["total"],
        top_ips=stats["top_ips"],
        top_users=stats["top_users"],
        top_pwds=stats["top_pwds"],
        country_labels=country_labels,
        country_data=country_data,
        username_labels=username_labels,
        username_values=username_values,
        password_labels=password_labels,
        password_values=password_values,
        hour_labels=hour_labels,
        hour_values=hour_values,
        recent=recent,
        q_ip=q_ip,
        q_country=q_country,
        q_user=q_user,
        q_limit=q_limit,
    )

# ================================
# MAP DATA API (used by frontend to render map)
# ================================
@app.route("/mapdata")
@require_login
def mapdata():
    entries = read_logs()

    # aggregate by IP: count, usernames, passwords, last_seen, country/city/org
    agg = {}
    for e in entries:
        ip = e.get("ip")
        if not ip:
            continue
        if ip not in agg:
            agg[ip] = {
                "count": 0,
                "usernames": [],
                "passwords": [],
                "last_seen": None,
                "country": e.get("country", "Unknown"),
                "city": e.get("city", "Unknown"),
                "org": e.get("org", "Unknown"),
            }
        agg[ip]["count"] += 1
        if e.get("username"):
            agg[ip]["usernames"].append(e.get("username"))
        if e.get("password"):
            agg[ip]["passwords"].append(e.get("password"))
        # track most recent
        ts = e.get("_ts")
        if agg[ip]["last_seen"] is None or ts > agg[ip]["last_seen"]:
            agg[ip]["last_seen"] = ts

    # load cache and update missing coordinates
    cache = load_map_cache()
    changed = False
    results = []
    for ip, info in agg.items():
        if ip in cache and "lat" in cache[ip]:
            lat = cache[ip]["lat"]
            lon = cache[ip]["lon"]
        else:
            # try to fetch
            ipinfo = fetch_ipinfo(ip)
            if ipinfo:
                lat = ipinfo["lat"]
                lon = ipinfo["lon"]
                cache[ip] = {
                    "lat": lat,
                    "lon": lon,
                    "country": ipinfo.get("country", info.get("country")),
                    "city": ipinfo.get("city", info.get("city")),
                    "org": ipinfo.get("org", info.get("org")),
                    "last_seen": time.time()
                }
                changed = True
            else:
                # fallback: skip adding precise coordinates
                lat = None
                lon = None

        results.append({
            "ip": ip,
            "lat": lat,
            "lon": lon,
            "count": info["count"],
            "country": info["country"],
            "city": info["city"],
            "org": info["org"],
            "usernames": list(dict.fromkeys(info["usernames"]))[:6],
            "passwords": list(dict.fromkeys(info["passwords"]))[:6],
            "last_seen": info["last_seen"].strftime("%Y-%m-%d %H:%M:%S") if info["last_seen"] else ""
        })

    if changed:
        save_map_cache(cache)

    return jsonify({"now": int(time.time()), "data": results})

# ================================
# EXPORT: CSV / JSON / EXCEL
# ================================
@app.route("/export/csv")
@require_login
def export_csv():
    entries = read_logs()
    df = pd.DataFrame(entries)
    df.drop(columns=["_ts"], errors="ignore", inplace=True)

    out = BytesIO()
    df.to_csv(out, index=False)
    out.seek(0)
    return send_file(out, mimetype="text/csv", as_attachment=True, download_name="HoneyLogin.csv")

@app.route("/export/json")
@require_login
def export_json():
    entries = read_logs()
    out = BytesIO()
    out.write(json.dumps(entries, indent=2).encode())
    out.seek(0)
    return send_file(out, mimetype="application/json", as_attachment=True, download_name="HoneyLogin.json")

@app.route("/export/excel")
@require_login
def export_excel():
    entries = read_logs()
    df = pd.DataFrame(entries)
    df.drop(columns=["_ts"], errors="ignore", inplace=True)

    out = BytesIO()
    df.to_excel(out, index=False)
    out.seek(0)
    return send_file(
        out,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="HoneyLogin.xlsx"
    )

# ================================
# RUN SERVER
# ================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

