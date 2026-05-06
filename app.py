import os
import re
import sqlite3
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-this")

# Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

mail = Mail(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "cyberguard.db")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            verified BOOLEAN NOT NULL DEFAULT FALSE,
            verification_token TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            category TEXT NOT NULL,
            score INTEGER NOT NULL,
            confidence INTEGER NOT NULL,
            explanation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    db.commit()


with app.app_context():
    init_db()


@app.before_request
def load_current_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        user = get_db().execute(
            "SELECT id, email FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        g.user = user


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("signin"))
        return view(*args, **kwargs)

    return wrapped_view


def require_api_auth():
    if g.user is None:
        return jsonify({"success": False, "message": "Authentication required."}), 401
    return None


def validate_email(value):
    return bool(EMAIL_RE.match(value))


def scan_url(target_url):
    normalized = target_url.strip()
    if not normalized:
        raise ValueError("URL is required")

    if not normalized.startswith(("http://", "https://")):
        normalized = "https://" + normalized

    parsed = urlparse(normalized)
    host = parsed.netloc.lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    flags = []

    if parsed.scheme != "https":
        flags.append("Missing HTTPS")
    if "@" in normalized:
        flags.append("Credential redirect pattern")

    suspicious_keywords = [
        "login",
        "secure",
        "verify",
        "account",
        "update",
        "bank",
        "reset",
        "support",
        "confirm",
    ]

    if any(keyword in host for keyword in suspicious_keywords):
        flags.append("Suspicious domain keywords")
    if any(keyword in path for keyword in suspicious_keywords):
        flags.append("Suspicious path keywords")
    if any(keyword in query for keyword in suspicious_keywords):
        flags.append("Suspicious query parameters")
    if any(short in host for short in ["bit.ly", "tinyurl", "t.co", "goo.gl"]):
        flags.append("URL shortener used")
    if host.count("-") >= 2:
        flags.append("Hyphen-heavy domain")
    if re.search(r"\d", host):
        flags.append("Numeric domain")
    if host.endswith((".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq")):
        flags.append("High-risk TLD")
    if len(host) > 30:
        flags.append("Extra long host")

    score = 12 + len(flags) * 15
    if parsed.scheme != "https":
        score += 10
    score = min(max(score, 8), 95)

    if score < 40:
        category = "Safe"
    elif score < 70:
        category = "Suspicious"
    else:
        category = "Phishing"

    confidence = 98 if score < 35 else 86 if score < 70 else 74
    explanation = (
        "No obvious phishing signals were detected. The URL appears normal and uses a trusted structure."
        if score < 40
        else (
            "The URL contains several suspicious patterns such as misleading host names or credential-related paths. "
            "We recommend verifying the sender and avoiding inputting credentials."
            if score < 70
            else
            "The URL exhibits multiple phishing indicators including suspicious host tokens, unsafe redirects, or a high-risk top-level domain. "
            "Do not proceed and report it to your security team."
        )
    )

    if flags and score >= 40:
        explanation += " Detected: " + ", ".join(flags[:4]) + "."

    return {
        "url": normalized,
        "score": score,
        "confidence": confidence,
        "category": category,
        "explanation": explanation,
    }


def scan_content(payload_type, content):
    text = content.strip()
    if not text:
        raise ValueError("Input is required")

    normalized = text.lower()
    if payload_type == "logs":
        keywords = ["failed", "error", "unauthorized", "attack", "brute force", "invalid"]
        hits = sum(keyword in normalized for keyword in keywords)
        score = min(90, 18 + hits * 18)
        category = "Suspicious" if score < 70 else "Alert"
        explanation = (
            "Logs contain repeated failures or unauthorized access attempts. Review recent events and verify source IPs."
            if hits > 0
            else "Logs look normal; no obvious intrusion patterns were found."
        )
    else:
        urgency_signals = [
            "immediately",
            "urgent",
            "verify",
            "click here",
            "account",
            "password",
            "locked",
            "suspend",
            "update",
            "confirm",
        ]
        hits = sum(signal in normalized for signal in urgency_signals)
        score = min(92, 12 + hits * 20)
        category = "Safe" if score < 40 else "Suspicious" if score < 70 else "Social Engineering"
        explanation = (
            "This message uses urgent or fear-based language that is common in phishing and social engineering attacks."
            if hits > 0
            else "The message appears benign and does not contain obvious manipulation language."
        )

    confidence = 94 if score < 40 else 82 if score < 70 else 76
    return {
        "score": score,
        "confidence": confidence,
        "category": category,
        "explanation": explanation,
    }


def save_scan(user_id, url, payload):
    db = get_db()
    db.execute(
        "INSERT INTO scans (user_id, url, category, score, confidence, explanation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            payload["url"],
            payload["category"],
            payload["score"],
            payload["confidence"],
            payload["explanation"],
            datetime.utcnow().isoformat(),
        ),
    )
    db.commit()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/signup")
def signup():
    if g.user:
        return redirect(url_for("home"))
    return render_template("signup.html")


@app.route("/signin")
def signin():
    if g.user:
        return redirect(url_for("home"))
    return render_template("signin.html")


@app.route("/verify/<token>")
def verify_email(token):
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE verification_token = ? AND verified = FALSE", (token,)).fetchone()
    if user is None:
        return "Invalid or expired verification link.", 400

    db.execute("UPDATE users SET verified = TRUE, verification_token = NULL WHERE id = ?", (user["id"],))
    db.commit()

    return redirect(url_for("signin"))


@app.route("/api/auth/signup", methods=["POST"])
def api_signup():
    payload = request.get_json() or {}
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""

    if not validate_email(email):
        return jsonify({"success": False, "message": "Enter a valid email address."}), 400
    if len(password) < 8:
        return jsonify({"success": False, "message": "Password must be at least 8 characters."}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing is not None:
        return jsonify({"success": False, "message": "An account already exists with that email."}), 409

    import secrets
    verification_token = secrets.token_urlsafe(32)
    password_hash = generate_password_hash(password)
    created_at = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO users (email, password_hash, verified, verification_token, created_at) VALUES (?, ?, ?, ?, ?)",
        (email, password_hash, False, verification_token, created_at),
    )
    db.commit()

    # Send verification email
    try:
        verify_url = url_for('verify_email', token=verification_token, _external=True)
        msg = Message(
            subject="Verify your CyberGuard AI account",
            recipients=[email],
            body=f"Welcome to CyberGuard AI!\n\nPlease verify your email by clicking this link:\n{verify_url}\n\nIf you didn't create an account, ignore this email."
        )
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")
        # Continue anyway

    return jsonify({"success": True, "message": "Account created! Please check your email to verify your account."})


@app.route("/api/auth/signin", methods=["POST"])
def api_signin():
    payload = request.get_json() or {}
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""

    db = get_db()
    user = db.execute("SELECT id, password_hash, verified FROM users WHERE email = ?", (email,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "message": "Email or password is incorrect."}), 401

    if not user["verified"]:
        return jsonify({"success": False, "message": "Please verify your email before signing in."}), 403

    session.clear()
    session["user_id"] = user["id"]
    return jsonify({"success": True, "message": "Signed in successfully."})


@app.route("/api/auth/signout", methods=["POST"])
def api_signout():
    session.clear()
    return jsonify({"success": True, "message": "Signed out successfully."})


@app.route("/api/auth/me")
def api_me():
    if g.user is None:
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "email": g.user["email"]})


@app.route("/api/stats")
def api_stats():
    db = get_db()
    users_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    scans_count = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    return jsonify({"users": users_count, "scans": scans_count})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.get_json() or {}
    url = (payload.get("url") or "").strip()
    scan_type = payload.get("type", "url")
    if scan_type == "url":
        if not url:
            return jsonify({"success": False, "message": "URL is required."}), 400
        result = scan_url(url)
        if g.user:
            save_scan(g.user["id"], url, result)
        return jsonify({"success": True, "saved": g.user is not None, "result": result})

    if scan_type in ["logs", "msg"]:
        text = (payload.get("text") or "").strip()
        if not text:
            return jsonify({"success": False, "message": "Input text is required."}), 400
        result = scan_content(scan_type, text)
        return jsonify({"success": True, "saved": False, "result": result})

    return jsonify({"success": False, "message": "Invalid scan type."}), 400


@app.route("/api/history")
def api_history():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

    db = get_db()
    rows = db.execute(
        "SELECT url, category, score, confidence, explanation, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC",
        (g.user["id"],),
    ).fetchall()
    history = [
        {
            "url": row["url"],
            "category": row["category"],
            "score": row["score"],
            "confidence": row["confidence"],
            "explanation": row["explanation"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return jsonify({"history": history})


if __name__ == "__main__":
    app.run(debug=True)
