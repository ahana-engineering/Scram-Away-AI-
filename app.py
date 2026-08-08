"""
Flask app serving the web UI, login, and the /scan API.

API key setup (in order of priority):
1. Command line (overrides everything else, useful for quick testing):
     py app.py AIzaSy...your_real_key_here...
2. A .env file in this same folder containing one line:
     GEMINI_API_KEY=AIzaSy...your_real_key_here...
   This is the recommended approach -- the key never appears in your
   terminal history or command line this way.

If neither is present, the app still runs, but Tier 3 (Gemini reasoning)
will be skipped for every scan.

Then open http://localhost:5000 in your browser.
"""

import sys
import os
import re
import uuid
import functools
from datetime import datetime
from collections import defaultdict

from dotenv import load_dotenv
load_dotenv()  # loads GEMINI_API_KEY from a .env file in this folder, if present

if len(sys.argv) > 1:
    os.environ["GEMINI_API_KEY"] = sys.argv[1]
    print(f"Using API key passed on command line (length: {len(sys.argv[1])})")
elif os.environ.get("GEMINI_API_KEY"):
    print(f"Using API key loaded from .env file (length: {len(os.environ['GEMINI_API_KEY'])})")
else:
    print("No API key found (checked command line and .env) -- Tier 3 will be skipped for all scans.")

from dataclasses import asdict
from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from flask_cors import CORS

from detection_engine import scan_message

app = Flask(__name__, static_folder="static")
app.secret_key = "hackathon-demo-secret-key-change-if-this-goes-to-production"
CORS(app, supports_credentials=True)

# ---------------------------------------------------------------------------
# In-memory state (resets when the server restarts -- fine for a demo;
# a real deployment would use a database instead)
# ---------------------------------------------------------------------------

USERS = {}  # username -> password (plaintext, demo only -- never do this in production)

FEED = []                              # SHARED across all users -- community threat feed
MAX_FEED_ITEMS = 20

SENDER_HISTORY = defaultdict(lambda: defaultdict(int))    # per-user: username -> {sender: count}
ANALYTICS = defaultdict(lambda: {"total": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0})  # per-user
TIER_USAGE = defaultdict(lambda: {"tier1": 0, "tier2": 0, "tier3": 0})  # per-user
SCAN_LOGS = defaultdict(list)          # per-user: username -> list of past scans
SUPPORT_TICKETS = defaultdict(list)    # per-user: username -> list of complaints/questions


def anonymize_snippet(content: str, max_len: int = 100) -> str:
    snippet = content[:max_len].strip()
    snippet = re.sub(r"\b\d{10}\b", "XXXXX-XXXXX", snippet)
    snippet = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "user@***.com", snippet)
    return snippet


def _seed_feed():
    samples = [
        ("Dear customer, ur A/C will be BLOCKED today. Update KYC now: kyc-verify.example.in/upd", "High", 78),
        ("Congrats! You won Rs.25,000 in KBC lucky draw. Claim now: kbc-winner.example.win/claim", "High", 73),
        ("RWA Notice: Society maintenance now via UPI. Pay Rs.3500 before 10th: rwa.example.link/pay", "High", 70),
        ("Your parcel is held at customs. Pay Rs.249 customs fee to release: courier-fee.example.co", "Critical", 88),
    ]
    for text, level, score in samples:
        FEED.append({
            "id": str(uuid.uuid4())[:8],
            "timestamp": "seed",
            "snippet": anonymize_snippet(text),
            "warning_level": level,
            "risk_score": score,
            "language": "English",
        })


_seed_feed()


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            if request.path.startswith("/api") or request.method == "POST" or request.accept_mimetypes.best == "application/json":
                return jsonify({"error": "Not logged in"}), 401
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return send_from_directory("static", "login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return redirect(url_for("login_page", error="Username and password are required."))

    if username in USERS:
        if USERS[username] != password:
            return redirect(url_for("login_page", error="Incorrect password for that username."))
    else:
        USERS[username] = password  # auto-register new username

    session["username"] = username
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/whoami")
def whoami():
    return jsonify({"username": session.get("username")})


@app.route("/")
@login_required
def index():
    return send_from_directory("static", "index.html")


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    username = session["username"]
    data = request.get_json(force=True)
    content = data.get("content", "")
    sender = data.get("sender", "Unknown")
    language = data.get("language", "English")

    if not content.strip():
        return jsonify({"error": "content is required"}), 400

    result = scan_message(content, sender, language)
    result_dict = asdict(result)

    # --- Personalization: per-user sender history, and it now actually
    # affects the score, not just informs the user ---
    user_senders = SENDER_HISTORY[username]
    user_senders[sender] += 1
    seen_count = user_senders[sender]
    result_dict["sender_seen_count"] = seen_count
    result_dict["is_first_time_sender"] = seen_count == 1

    repeat_penalty_applied = False
    if seen_count >= 3 and sender != "Unknown" and result_dict["final_risk_score"] >= 20:
        bumped = min(100, result_dict["final_risk_score"] + 5)
        if bumped != result_dict["final_risk_score"]:
            result_dict["final_risk_score"] = bumped
            repeat_penalty_applied = True
            if bumped >= 85:
                result_dict["warning_level"] = "Critical"
            elif bumped >= 55:
                result_dict["warning_level"] = "High"
            elif bumped >= 25:
                result_dict["warning_level"] = "Medium"
    result_dict["repeat_sender_penalty_applied"] = repeat_penalty_applied

    # --- Zero-day catch indicator ---
    t1_score = result_dict["tier1"]["risk_score"]
    t2_score = result_dict["tier2"]["risk_score"]
    tier3_ran = result_dict["executed_tiers"]["tier3"]
    result_dict["zero_day_catch"] = bool(
        tier3_ran and t1_score < 25 and t2_score < 25 and result_dict["final_risk_score"] >= 55
    )

    # --- Per-user analytics + tier usage ---
    user_analytics = ANALYTICS[username]
    user_analytics["total"] += 1
    user_analytics[result_dict["warning_level"]] += 1

    user_tiers = TIER_USAGE[username]
    user_tiers["tier1"] += 1
    user_tiers["tier2"] += 1
    if tier3_ran:
        user_tiers["tier3"] += 1

    # --- Per-user scan log (persists across page reloads, unlike before) ---
    SCAN_LOGS[username].insert(0, {
        "time": datetime.now().strftime("%H:%M:%S"),
        "sender": sender,
        "snippet": content[:60],
        "level": result_dict["warning_level"],
        "score": result_dict["final_risk_score"],
    })
    del SCAN_LOGS[username][30:]

    # --- SHARED feed across all users -- a community scam-alert panel ---
    if result_dict["warning_level"] in ("High", "Critical"):
        FEED.insert(0, {
            "id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "snippet": anonymize_snippet(content),
            "warning_level": result_dict["warning_level"],
            "risk_score": result_dict["final_risk_score"],
            "language": language,
        })
        del FEED[MAX_FEED_ITEMS:]

    return jsonify(result_dict)


@app.route("/feed", methods=["GET"])
@login_required
def feed():
    return jsonify(FEED)


@app.route("/analytics", methods=["GET"])
@login_required
def analytics():
    username = session["username"]
    return jsonify({**ANALYTICS[username], "tier_usage": TIER_USAGE[username]})


@app.route("/logs", methods=["GET"])
@login_required
def logs():
    username = session["username"]
    return jsonify(SCAN_LOGS[username])


@app.route("/support", methods=["GET", "POST"])
@login_required
def support():
    username = session["username"]

    if request.method == "POST":
        data = request.get_json(force=True)
        subject = data.get("subject", "").strip()
        message = data.get("message", "").strip()

        if not subject or not message:
            return jsonify({"error": "Subject and message are required"}), 400

        ticket = {
            "id": str(uuid.uuid4())[:8],
            "time": datetime.now().strftime("%d %b, %H:%M"),
            "subject": subject,
            "message": message,
            "status": "Open",
        }
        SUPPORT_TICKETS[username].insert(0, ticket)
        return jsonify(ticket)

    return jsonify(SUPPORT_TICKETS[username])


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
