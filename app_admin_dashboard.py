from flask import Flask, render_template, request, redirect, url_for, session, flash
import re
import os
import plotly
import plotly.graph_objs as go
import json
import requests
import functools
from collections import Counter, defaultdict
from datetime import datetime

# ----- CONFIG -----
DASHBOARD_USER = "admin"
DASHBOARD_PASS = "Vincentaun123"
SSH_LOG = "ssh_honeypot.log"
WEB_LOG = "web_honeypot.log"

app = Flask(__name__)
app.secret_key = "a-very-secret-key"  # change in real use!

# ---- Helpers: Log Parsing ----

def parse_ssh_log():
    ip_attempts = Counter()
    cmd_attempts = Counter()
    login_attempts = []
    commands = []
    ips = set()
    timeline = []
    with open(SSH_LOG, "r", encoding="utf-8") as f:
        for line in f:
            # e.g. 2025-06-23 21:17:56,441 - INFO - SSH login attempt from 172.17.145.106 - Username: Vincent, Password: Password
            m_login = re.search(r"SSH login attempt from ([\d\.]+) - Username: ([^,]+), Password: (.+)", line)
            m_cmd = re.search(r"Command '(.+)' executed by ([\d\.]+)", line)
            m_conn = re.search(r"([0-9\-\:\, ]+) - INFO - ([\d\.]+) has connected to the SSH honeypot", line)
            if m_login:
                ip = m_login.group(1)
                user = m_login.group(2)
                passwd = m_login.group(3)
                login_attempts.append({"ip": ip, "user": user, "passwd": passwd})
                ip_attempts[ip] += 1
                ips.add(ip)
            elif m_cmd:
                cmd = m_cmd.group(1)
                ip = m_cmd.group(2)
                commands.append({"ip": ip, "cmd": cmd})
                cmd_attempts[cmd] += 1
                ip_attempts[ip] += 1
            elif m_conn:
                ip = m_conn.group(2)
                ip_attempts[ip] += 1
                ips.add(ip)
            # Timeline
            m_time = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),", line)
            if m_time:
                timeline.append(m_time.group(1))
    return {
        "ip_attempts": ip_attempts,
        "cmd_attempts": cmd_attempts,
        "login_attempts": login_attempts,
        "commands": commands,
        "ips": list(ips),
        "timeline": timeline,
    }

def parse_web_log():
    web_logins = []
    ip_attempts = Counter()
    credentials = Counter()
    timeline = []
    with open(WEB_LOG, "r", encoding="utf-8") as f:
        for line in f:
            # e.g. 2025-02-23 20:46:58,727 - INFO - Web login attempt from 127.0.0.1 - Email: vincentaun123@gmail.com, Password: dfghjdcfvbgnhjcvbnm
            m_login = re.search(r"Web login attempt from ([\d\.]+) - Email: ([^,]+), Password: (.+)", line)
            m_fail = re.search(r"Failed login attempt from ([\d\.]+) - Email: (.+)", line)
            m_success = re.search(r"Successful login from ([\d\.]+) using email: (.+)", line)
            m_time = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),", line)
            if m_login:
                ip = m_login.group(1)
                email = m_login.group(2)
                password = m_login.group(3)
                web_logins.append({"ip": ip, "email": email, "password": password})
                ip_attempts[ip] += 1
                credentials[(email, password)] += 1
            elif m_fail:
                ip = m_fail.group(1)
                ip_attempts[ip] += 1
            elif m_success:
                ip = m_success.group(1)
                ip_attempts[ip] += 1
            if m_time:
                timeline.append(m_time.group(1))
    return {
        "web_logins": web_logins,
        "ip_attempts": ip_attempts,
        "credentials": credentials,
        "timeline": timeline,
    }

# ---- GeoIP lookup ----
@functools.lru_cache(maxsize=128)
def ip_to_country(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = r.json()
        return data.get("countryCode", ""), data.get("country", "")
    except:
        return "", ""



# ---- ROUTES ----

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pw = request.form["password"]
        if user == DASHBOARD_USER and pw == DASHBOARD_PASS:
            session["user"] = user
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials", "danger")
    return render_template("login-admin.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route('/dashboard')
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    ssh = parse_ssh_log()
    web = parse_web_log()

    # Top SSH attacker IPs and their countries
    ssh_top_ips = ssh["ip_attempts"].most_common(5)
    ssh_top_geo = [
        (ip, count, *ip_to_country(ip)) for ip, count in ssh_top_ips
    ]
    # Top web attacker IPs
    web_top_ips = web["ip_attempts"].most_common(5)
    web_top_geo = [
        (ip, count, *ip_to_country(ip)) for ip, count in web_top_ips
    ]
    
    # When rendering dashboard:
    ssh_top_geo = [
        (ip, count, country_code, country)
        for ip, count in ssh_top_ips
        for country_code, country in [ip_to_country(ip)]
    ]
    web_top_geo = [
        (ip, count, country_code, country)
        for ip, count in web_top_ips
        for country_code, country in [ip_to_country(ip)]
    ]

    # Attack frequency over time (simple daily chart)
    ssh_times = [t.split()[0] for t in ssh["timeline"]]
    web_times = [t.split()[0] for t in web["timeline"]]
    ssh_time_count = Counter(ssh_times)
    web_time_count = Counter(web_times)

    # Charts with plotly
    ssh_ip_bar = go.Bar(
        x=[f"{ip} ({country})" for ip, count, country_code, country in ssh_top_geo],
        y=[count for ip, count, *_ in ssh_top_geo],
        name='SSH Attacks by IP'
    )
    web_ip_bar = go.Bar(
        x=[f"{ip} ({country})" for ip, count, country_code, country in web_top_geo],
        y=[count for ip, count, *_ in web_top_geo],
        name='Web Attacks by IP'
    )
    ssh_time_chart = go.Scatter(
        x=list(ssh_time_count.keys()),
        y=list(ssh_time_count.values()),
        name='SSH Attacks per Day'
    )
    web_time_chart = go.Scatter(
        x=list(web_time_count.keys()),
        y=list(web_time_count.values()),
        name='Web Attacks per Day'
    )

    # Render dashboard with visualizations
    return render_template(
        "dashboard-admin.html",
        ssh=ssh, web=web,
        ssh_ip_bar=json.dumps([ssh_ip_bar], cls=plotly.utils.PlotlyJSONEncoder),
        web_ip_bar=json.dumps([web_ip_bar], cls=plotly.utils.PlotlyJSONEncoder),
        ssh_time_chart=json.dumps([ssh_time_chart], cls=plotly.utils.PlotlyJSONEncoder),
        web_time_chart=json.dumps([web_time_chart], cls=plotly.utils.PlotlyJSONEncoder),
        ssh_top_geo=ssh_top_geo, web_top_geo=web_top_geo,
        ssh_top_cmds=ssh["cmd_attempts"].most_common(5),
        web_top_creds=web["credentials"].most_common(5),
        recent_ssh=ssh["commands"][-10:][::-1],
        recent_web=web["web_logins"][-10:][::-1]
    )

if __name__ == "__main__":
    app.run(debug=True, port=8000)
