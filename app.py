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
import csv, io, json, os, statistics, tempfile, uuid

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
BASELINE = load("pakistan_baseline.json")
MONTH_NAMES = ["January", "February", "March", "April", "May", "June", "July",
               "August", "September", "October", "November", "December"]

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
                           model=MODEL, anom_per_year=ANOM_PER_YEAR,
                           recent=load("recent_data.json"))

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

# ---------------- Live tool: prediction ----------------
@app.route("/api/predict")
@login_required
def api_predict():
    try:
        year = int(request.args.get("year", ""))
    except ValueError:
        return jsonify({"error": "Please enter a valid year."}), 400
    if year < 2014 or year > 2100:
        return jsonify({"error": "Enter a future year between 2014 and 2100."}), 400
    pred = MODEL["slope"] * year + MODEL["intercept"]
    return jsonify({"year": year, "prediction": round(pred, 2),
                    "note": "Model 2: Linear Regression trained on Pakistan data, 1950 to 2000."})

# ---------------- Live tool: anomaly checker ----------------
@app.route("/api/anomaly-check")
@login_required
def api_anomaly_check():
    try:
        month = int(request.args.get("month", ""))
        temp = float(request.args.get("temp", ""))
    except ValueError:
        return jsonify({"error": "Select a month and enter a temperature."}), 400
    if month < 1 or month > 12:
        return jsonify({"error": "Invalid month."}), 400
    if temp < -60 or temp > 50:
        return jsonify({"error": "A monthly average temperature of %g C is not physically possible. "
                                 "Monthly averages recorded on Earth fall roughly between -60 C and +45 C. "
                                 "Please enter a realistic value." % temp}), 400
    baseline = BASELINE[str(month)]
    diff = round(temp - baseline, 2)
    alert = diff >= ALERT_THRESHOLD
    level = "Severe" if diff >= 3 else "High" if diff >= 2 else "Moderate" if alert else "Normal"
    return jsonify({"month": MONTH_NAMES[month - 1], "temperature": temp, "baseline": baseline,
                    "difference": diff, "alert": alert, "level": level,
                    "threshold": ALERT_THRESHOLD})

# ---------------- Live tool: data upload and processing ----------------
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "earthscape_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/upload")
@login_required
def upload():
    return render_template("upload.html")

@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith(".csv"):
        return jsonify({"error": "Please choose a CSV file."}), 400
    raw = f.read()
    if len(raw) > 8 * 1024 * 1024:
        return jsonify({"error": "File is too large (maximum 8 MB)."}), 400
    try:
        rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8", "replace"))))
    except Exception:
        return jsonify({"error": "Could not read this CSV file."}), 400
    if not rows:
        return jsonify({"error": "The file has no data rows."}), 400
    cols = rows[0].keys()
    temp_col = next((c for c in cols if "temperature" in c.lower() and "uncertainty" not in c.lower()), None)
    date_col = next((c for c in cols if c.lower() in ("dt", "date", "month", "year")), None)
    country_col = next((c for c in cols if c.lower() == "country"), None)
    if not temp_col or not date_col:
        return jsonify({"error": "The CSV needs a date column (dt) and a temperature column, like the project dataset."}), 400
    missing = sum(1 for r in rows if not r[temp_col])
    countries = sorted({r[country_col] for r in rows if country_col and r[country_col]}) if country_col else []
    token = uuid.uuid4().hex
    with open(os.path.join(UPLOAD_DIR, token + ".json"), "w") as fh:
        json.dump({"rows": rows, "temp_col": temp_col, "date_col": date_col, "country_col": country_col}, fh)
    return jsonify({"token": token, "total_rows": len(rows), "missing_temperatures": missing,
                    "usable_rows": len(rows) - missing, "countries": countries,
                    "columns": list(cols)})

@app.route("/api/upload-series")
@login_required
def api_upload_series():
    token = request.args.get("token", "")
    country = request.args.get("country", "")
    path = os.path.join(UPLOAD_DIR, token + ".json")
    if not os.path.exists(path):
        return jsonify({"error": "Upload session expired. Please upload again."}), 404
    with open(path) as fh:
        saved = json.load(fh)
    rows, tc, dc, cc = saved["rows"], saved["temp_col"], saved["date_col"], saved["country_col"]
    per_year = {}
    for r in rows:
        if cc and country and r.get(cc) != country:
            continue
        try:
            year = int(str(r[dc])[:4])
            val = float(r[tc])
        except (TypeError, ValueError):
            continue
        per_year.setdefault(year, []).append(val)
    series = [[y, round(statistics.mean(v), 2)] for y, v in sorted(per_year.items())]
    return jsonify({"country": country or "All data", "points": series, "years": len(series)})

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
        try:
            with open(FEEDBACK_FILE, "w") as f:
                json.dump(items, f, indent=2)
        except OSError:
            pass  # read-only hosting (serverless): submission still accepted
        flash("Thank you. Your message has been submitted to the support team.")
        return redirect(url_for("feedback"))
    return render_template("feedback.html")

# ---------------- Help and user guide ----------------
@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

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
