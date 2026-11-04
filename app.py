# ============================================================
# EarthScape Climate Agency - Web Application
# eProject: Big Data - EarthScape Climate Agency
# Submitted by: Taha Kazmi (student1514118)
#
# Run:  pip install flask   then   python app.py
# Open: http://127.0.0.1:5000
# Demo logins:  admin / admin123  (Administrator)
#               analyst / analyst123  (Analyst)
# ============================================================

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json, os

app = Flask(__name__)
app.secret_key = "earthscape-secret-key"
BASE = os.path.dirname(os.path.abspath(__file__))

def load(name):
    with open(os.path.join(BASE, "data", name)) as f:
        return json.load(f)

YEARLY = load("yearly_by_country.json")
MODEL = load("pakistan_model.json")
ALERTS = load("alerts.json")
ANOM_PER_YEAR = load("anomalies_per_year.json")
CO2 = load("co2.json")

# ---------------- Users and roles ----------------
USERS = {
    "admin":   {"password": generate_password_hash("admin123"),   "role": "Administrator", "name": "System Administrator"},
    "analyst": {"password": generate_password_hash("analyst123"), "role": "Analyst",       "name": "Climate Analyst"},
}
ALERT_THRESHOLD = 1.5  # degrees C above the 1951-1980 baseline

def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if session.get("role") != "Administrator":
            return render_template("denied.html"), 403
        return f(*a, **kw)
    return wrap

# ---------------- Authentication ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        user = USERS.get(u)
        if user and check_password_hash(user["password"], p):
            session["user"] = u
            session["role"] = user["role"]
            session["name"] = user["name"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- Dashboard ----------------
@app.route("/")
@login_required
def dashboard():
    stats = {
        "total_records": "10,064,718",
        "cleaned_rows": "544,811",
        "countries": len(YEARLY),
        "anomalies": len(ALERTS),
        "correlation": "0.9655",
        "forecast_2050": MODEL["forecasts"]["2050"],
    }
    pak = YEARLY["Pakistan"]
    return render_template("dashboard.html", stats=stats, pakistan=pak,
                           model=MODEL, anom_per_year=ANOM_PER_YEAR)

# ---------------- Data explorer ----------------
@app.route("/explorer")
@login_required
def explorer():
    return render_template("explorer.html", countries=sorted(YEARLY.keys()))

@app.route("/api/country/<name>")
@login_required
def api_country(name):
    pts = YEARLY.get(name)
    if not pts:
        return jsonify({"error": "country not found"}), 404
    temps = [t for _, t in pts]
    return jsonify({
        "country": name, "points": pts,
        "records": len(pts), "from": pts[0][0], "to": pts[-1][0],
        "average": round(sum(temps) / len(temps), 2),
        "minimum": min(temps), "maximum": max(temps),
    })

# ---------------- Predictions ----------------
@app.route("/predictions")
@login_required
def predictions():
    return render_template("predictions.html", model=MODEL)

# ---------------- Alerts (anomaly detection output) ----------------
@app.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html", alerts=ALERTS, threshold=ALERT_THRESHOLD)

# ---------------- Correlation ----------------
@app.route("/correlation")
@login_required
def correlation():
    return render_template("correlation.html", co2=CO2)

# ---------------- Feedback and support ----------------
FEEDBACK_FILE = os.path.join(BASE, "data", "feedback.json")

def read_feedback():
    if os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE) as f:
            return json.load(f)
    return []

@app.route("/feedback", methods=["GET", "POST"])
@login_required
def feedback():
    if request.method == "POST":
        entry = {
            "name": request.form.get("name", "").strip(),
            "email": request.form.get("email", "").strip(),
            "type": request.form.get("type", "Feedback"),
            "message": request.form.get("message", "").strip(),
            "by": session.get("user"),
        }
        items = read_feedback()
        items.append(entry)
        with open(FEEDBACK_FILE, "w") as f:
            json.dump(items, f, indent=2)
        flash("Thank you. Your message has been submitted to the support team.")
        return redirect(url_for("feedback"))
    return render_template("feedback.html")

# ---------------- Admin ----------------
@app.route("/admin")
@login_required
@admin_required
def admin():
    users = [{"username": u, "role": d["role"], "name": d["name"]} for u, d in USERS.items()]
    return render_template("admin.html", users=users, feedback=read_feedback(),
                           threshold=ALERT_THRESHOLD)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=("PORT" not in os.environ))
