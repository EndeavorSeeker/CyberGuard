import base64
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse
try:
    from clerk_backend_api.security import AuthenticateRequestOptions, authenticate_request
    CLERK_AVAILABLE = True
except ImportError:
    CLERK_AVAILABLE = False

    class AuthenticateRequestOptions:
        def __init__(self, *args, **kwargs):
            pass

    def authenticate_request(*args, **kwargs):
        class DummyAuth:
            is_signed_in = False
            payload = None

        return DummyAuth()
from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_compress import Compress
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from db import DATABASE_PATH, close_db, get_db
from auth import is_owner, require_role
from blueprints.stats import stats_bp

app = Flask(__name__, static_folder="static", template_folder="templates")
# Compress responses (gzip) to reduce transfer time for assets
app.config.setdefault('COMPRESS_ALGORITHM', 'gzip')
app.config.setdefault('COMPRESS_LEVEL', 6)
Compress(app)
# Cache static files aggressively so repeat navigations load quickly.
# Adjust SEND_FILE_MAX_AGE_DEFAULT as appropriate for your deployment.
app.config.setdefault('SEND_FILE_MAX_AGE_DEFAULT', 86400)
secret_key = os.environ.get("SECRET_KEY")
flask_env = os.environ.get("FLASK_ENV", "").lower()
if not secret_key:
    if flask_env == "development":
        app.logger.warning(
            "SECRET_KEY is not set. Running in development mode with a temporary secret. "
            "Do not use this configuration in production."
        )
        secret_key = "dev-secret-key-change-this"
    else:
        raise RuntimeError(
            "SECRET_KEY environment variable is required for secure session management."
        )

app.secret_key = secret_key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('ENV', '').lower() == 'production'

# Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

mail = Mail(app)

app.register_blueprint(stats_bp)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
RATE_LIMIT_STATE = {}
FAILED_SIGNIN_ATTEMPTS = {}
MATERIAL_SYMBOL_NAMES = (
    "account_circle,apps,arrow_back,arrow_forward,arrow_right_alt,attachment,"
    "bolt,book,cancel,check_circle,chevron_left,chevron_right,close,"
    "cloud_upload,computer,dark_mode,dashboard,database,delete,devices,edit,"
    "error,expand_more,extension,filter_list,find_in_page,group,groups,"
    "history,home,https,image_search,insights,key,language,light_mode,link,"
    "lock,lock_person,login,logout,menu,navigate_next,open_in_new,person,"
    "person_pin,phishing,phone_callback,play_arrow,psychology,public,quiz,"
    "radar,refresh,replay,rule,safety_check,school,score,search,security,"
    "settings,shield_lock,sim_card,smartphone,support_agent,swap_horiz,"
    "terminal,tips_and_updates,trending_up,usb,verified,verified_user,"
    "visibility,visibility_off,warning,wifi_lock"
)
MATERIAL_SYMBOLS_URL = (
    "https://fonts.googleapis.com/css2?"
    "family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0"
    f"&icon_names={MATERIAL_SYMBOL_NAMES}&display=block"
)

CLERK_PUBLISHABLE_KEY = os.environ.get(
    "CLERK_PUBLISHABLE_KEY",
    os.environ.get("VITE_CLERK_PUBLISHABLE_KEY", "pk_test_Y2xhc3NpYy1mb3gtNi5jbGVyay5hY2NvdW50cy5kZXYk"),
)


from typing import Optional

def _clerk_domain_from_publishable_key(key: str) -> Optional[str]:
    try:
        parts = key.split("_")
        code = parts[2]
        padding = "=" * (-len(code) % 4)
        decoded = base64.b64decode(code + padding).decode("utf-8")
        return decoded.rstrip("$\n\r")
    except Exception:
        return None

CLERK_DOMAIN = _clerk_domain_from_publishable_key(CLERK_PUBLISHABLE_KEY)

def _clerk_url(env_name: str, path: str, fallback_domain: str) -> str:
    env_value = os.environ.get(env_name)
    if env_value:
        return env_value
    if path.startswith("http://") or path.startswith("https://"):
        return path
    domain = CLERK_DOMAIN or fallback_domain
    if domain.startswith("http://") or domain.startswith("https://"):
        return f"{domain.rstrip('/')}/{path.lstrip('/')}"
    return f"https://{domain.rstrip('/')}/{path.lstrip('/')}"


CLERK_JS_URL = _clerk_url(
    "CLERK_JS_URL",
    "npm/@clerk/clerk-js@6/dist/clerk.browser.js",
    "classic-fox-6.clerk.accounts.dev",
)
CLERK_SECRET_KEY = os.environ.get(
    "CLERK_SECRET_KEY",
    "sk_test_m4HZ56o1sqXkgvSkDhcVMXTLcGzXwCiPJdump1IjO2",
)
CLERK_JWT_KEY = os.environ.get("CLERK_JWT_KEY")


app.teardown_appcontext(close_db)


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
            role TEXT NOT NULL DEFAULT 'user',
            disabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            type TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT NOT NULL,
            score INTEGER NOT NULL,
            confidence INTEGER NOT NULL,
            explanation TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    scan_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(scans)").fetchall()
    }
    if "type" not in scan_columns:
        db.execute("ALTER TABLE scans ADD COLUMN type TEXT")
        db.execute("UPDATE scans SET type = 'url' WHERE type IS NULL")
    if "content" not in scan_columns:
        db.execute("ALTER TABLE scans ADD COLUMN content TEXT")
        if "url" in scan_columns:
            db.execute("UPDATE scans SET content = url WHERE content IS NULL")
    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "role" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS clerk_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            clerk_user_id TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            disabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    clerk_columns = {row["name"] for row in db.execute("PRAGMA table_info(clerk_users)").fetchall()}
    if "role" not in clerk_columns:
        db.execute(
            "ALTER TABLE clerk_users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'"
        )
    if "disabled" not in clerk_columns:
        db.execute(
            "ALTER TABLE clerk_users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0"
        )
    if "role_synced_at" not in clerk_columns:
        # Epoch timestamp (seconds) of the last successful Clerk metadata sync.
        # NULL means "never synced" -> the next protected-route access will
        # force a fresh pull from Clerk. See auth.sync_clerk_role().
        db.execute("ALTER TABLE clerk_users ADD COLUMN role_synced_at REAL")
    db.commit()


with app.app_context():
    init_db()


@app.context_processor
def inject_clerk_config():
    return {
        "clerk_publishable_key": CLERK_PUBLISHABLE_KEY,
        "clerk_js_url": CLERK_JS_URL,
        "material_symbols_url": MATERIAL_SYMBOLS_URL,
        "csrf_token": session.setdefault("csrf_token", secrets.token_urlsafe(24)),
    }


@app.before_request
def load_current_user():
    g.user = None
    if request.endpoint == "static" or request.path.startswith("/static/"):
        return

    # Clerk is checked FIRST and takes priority over any local session.
    #
    # Bug fixed here: this used to check session["user_id"] (local
    # email/password login) first and return immediately if found, without
    # ever looking at Clerk. That meant anyone who had ever signed in once
    # with a local account (e.g. during testing) kept a "local" session
    # cookie that permanently shadowed their real Clerk sign-in -- so even
    # the owner's own Clerk-authenticated session was never checked, and
    # require_role()/is_owner() always saw type="local" and denied access
    # to /admin and /dashboard. Checking Clerk first fixes that: a valid
    # Clerk session now always wins, regardless of any leftover local
    # session cookie.
    if CLERK_AVAILABLE and (CLERK_SECRET_KEY or CLERK_JWT_KEY):
        auth_state = authenticate_request(
            request,
            AuthenticateRequestOptions(
                secret_key=CLERK_SECRET_KEY,
                jwt_key=CLERK_JWT_KEY,
                accepts_token=["session_token", "oauth_token", "any"],
            ),
        )
        if auth_state.is_signed_in and auth_state.payload:
            clerk_user_id = auth_state.payload.get("sub") or auth_state.payload.get("user_id")
            clerk_email = auth_state.payload.get("email") or auth_state.payload.get("email_address")
            if clerk_user_id:
                db = get_db()
                clerk_user = db.execute(
                    "SELECT clerk_user_id, email, role FROM clerk_users WHERE clerk_user_id = ?",
                    (clerk_user_id,),
                ).fetchone()
                if clerk_user is None:
                    db.execute(
                        "INSERT INTO clerk_users (clerk_user_id, email, role, created_at) VALUES (?, ?, ?, ?)",
                        (clerk_user_id, clerk_email or "", "user", datetime.utcnow().isoformat()),
                    )
                    db.commit()
                    clerk_user = db.execute(
                        "SELECT clerk_user_id, email, role FROM clerk_users WHERE clerk_user_id = ?",
                        (clerk_user_id,),
                    ).fetchone()

                if clerk_user is not None:
                    g.user = {
                        "id": clerk_user["clerk_user_id"],
                        "email": clerk_user["email"],
                        "role": clerk_user["role"] or "user",
                        "type": "clerk",
                    }
                    return

    # Fall back to the local email/password session only if Clerk did not
    # resolve a signed-in user above.
    user_id = session.get("user_id")
    if user_id is not None:
        user = get_db().execute(
            "SELECT id, email, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is not None:
            g.user = {
                "id": str(user["id"]),
                "email": user["email"],
                "role": user["role"] or "user",
                "type": "local",
            }


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("signin"))
        return view(*args, **kwargs)

    return wrapped_view


def api_login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            app.logger.warning("API auth required but missing for %s %s", request.method, request.path)
            return jsonify({"success": False, "message": "Authentication required."}), 401
        return view(*args, **kwargs)

    return wrapped_view


def require_api_auth():
    if g.user is None:
        app.logger.warning("API auth required but missing for %s %s", request.method, request.path)
        return jsonify({"success": False, "message": "Authentication required."}), 401
    return None


def current_user_identifier():
    if g.user is None:
        return None
    return {
        "id": str(g.user["id"]),
        "role": g.user.get("role", "user"),
        "type": g.user.get("type", "local"),
    }


def validate_csrf_token():
    token = request.headers.get("X-CSRF-Token")
    if token:
        if token != session.get("csrf_token"):
            return jsonify({"success": False, "message": "Invalid CSRF token."}), 403
        return None

    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    expected = request.host_url
    if origin and not origin.startswith(expected):
        return jsonify({"success": False, "message": "Invalid request origin."}), 403
    if referer and not referer.startswith(expected):
        return jsonify({"success": False, "message": "Invalid request referer."}), 403
    if not origin and not referer:
        return jsonify({"success": False, "message": "Missing CSRF protection headers."}), 403
    return None


def csrf_protect(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        error = validate_csrf_token()
        if error:
            return error
        return view(*args, **kwargs)
    return wrapped_view


def get_remote_address():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit(limit, per_seconds):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            key = f"{request.endpoint}:{get_remote_address()}"
            now = time.time()
            window = [timestamp for timestamp in RATE_LIMIT_STATE.get(key, []) if timestamp > now - per_seconds]
            if len(window) >= limit:
                app.logger.warning("Rate limit exceeded for %s", key)
                return jsonify({"success": False, "message": "Too many requests. Try again later."}), 429
            window.append(now)
            RATE_LIMIT_STATE[key] = window
            return view(*args, **kwargs)
        return wrapped_view
    return decorator


def record_failed_signin(email):
    now = time.time()
    attempts = [ts for ts in FAILED_SIGNIN_ATTEMPTS.get(email, []) if ts > now - 900]
    attempts.append(now)
    FAILED_SIGNIN_ATTEMPTS[email] = attempts


def clear_failed_signin(email):
    FAILED_SIGNIN_ATTEMPTS.pop(email, None)


def is_signin_locked(email):
    now = time.time()
    attempts = [ts for ts in FAILED_SIGNIN_ATTEMPTS.get(email, []) if ts > now - 900]
    return len(attempts) >= 5


def enforce_api_csrf():
    if request.method == "POST" and request.path.startswith("/api/"):
        error = validate_csrf_token()
        if error:
            return error
    return None


@app.before_request
def protect_api_csrf():
    if request.method == "POST" and request.path.startswith("/api/"):
        return enforce_api_csrf()


@app.after_request
def apply_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if os.environ.get('ENV', '').lower() == 'production':
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    clerk_script_host = CLERK_DOMAIN or "classic-fox-6.clerk.accounts.dev"
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com https://cdnjs.cloudflare.com https://unpkg.com https://" + clerk_script_host + "; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' https://cdn.jsdelivr.net https://" + clerk_script_host + "; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    return response


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


def scan_image_metadata(file_name, file_size):
    name = (file_name or "Uploaded image").strip()
    size = int(file_size or 0)
    suspicious_tokens = ["qr", "login", "invoice", "receipt", "verify", "password", "account"]
    hits = sum(token in name.lower() for token in suspicious_tokens)
    score = min(88, 14 + hits * 18 + (18 if size and size < 160 * 1024 else 0))
    category = "Safe" if score < 40 else "Suspicious" if score < 70 else "Image Phishing"
    confidence = 90 if score < 40 else 80 if score < 70 else 72
    explanation = (
        "The image metadata does not show obvious phishing indicators. Review visible links or QR codes before acting."
        if score < 40
        else "The file name or image profile contains patterns commonly seen in phishing screenshots, fake receipts, or QR-code lures."
    )
    return {
        "score": score,
        "confidence": confidence,
        "category": category,
        "explanation": explanation,
    }


def save_scan(user_id, scan_type, content, payload):
    db = get_db()
    scan_columns = {row["name"] for row in db.execute("PRAGMA table_info(scans)").fetchall()}
    columns = ["user_id", "category", "score", "confidence", "explanation", "created_at"]
    values = [
        user_id,
        payload["category"],
        payload["score"],
        payload["confidence"],
        payload["explanation"],
        datetime.utcnow().isoformat(),
    ]
    if "type" in scan_columns:
        columns.insert(1, "type")
        values.insert(1, scan_type)
    if "content" in scan_columns:
        columns.insert(2, "content")
        values.insert(2, content)
    if "url" in scan_columns:
        columns.insert(3, "url")
        values.insert(3, content)

    placeholders = ", ".join("?" for _ in columns)
    db.execute(
        f"INSERT INTO scans ({', '.join(columns)}) VALUES ({placeholders})",
        values,
    )
    db.commit()


def get_public_stats():
    db = get_db()
    password_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    clerk_users = db.execute("SELECT COUNT(*) FROM clerk_users").fetchone()[0]
    scans = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    return {
        "users": password_users + clerk_users,
        "scans": scans,
    }


@app.route("/")
def home():
    return render_template("index.html", stats=get_public_stats())


@app.route("/history")
def history():
    return render_template("history.html")


@app.route("/academy")
def academy():
    return render_template("academy.html")


@app.route("/academy/games")
def academy_games():
    return render_template("game.html")


@app.route("/academy/topic/<page>")
def academy_topic(page):
    allowed_pages = {
        "phone-security.html",
        "browser-security.html",
        "pc-security.html",
        "password-security.html",
        "phishing-prevention.html",
        "data-protection.html",
    }
    if page not in allowed_pages:
        return redirect(url_for("academy"))
    # FIX: templates are stored in the Flask templates/ directory.
    # Using render_template avoids directory ambiguity.
    return render_template(
        page,
        clerk_publishable_key=CLERK_PUBLISHABLE_KEY,
        clerk_js_url=CLERK_JS_URL
    )


@app.route("/signin")
def signin():
    if g.user:
        return redirect(url_for("home"))
    return render_template("signin.html", 
                         clerk_publishable_key=CLERK_PUBLISHABLE_KEY,
                         clerk_js_url=CLERK_JS_URL)


@app.route("/signup")
def signup():
    if g.user:
        return redirect(url_for("home"))
    return render_template("signup.html",
                         clerk_publishable_key=CLERK_PUBLISHABLE_KEY,
                         clerk_js_url=CLERK_JS_URL)


@app.route("/sso-callback")
def sso_callback():
    return render_template("sso_callback.html",
                         clerk_publishable_key=CLERK_PUBLISHABLE_KEY,
                         clerk_js_url=CLERK_JS_URL)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
@require_role(["owner"])
def dashboard():
    return render_template("dashboard.html")


@app.route("/admin")
@require_role(["owner"])
def admin():
    return render_template("admin.html")


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
@rate_limit(6, 60)
@csrf_protect
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
@rate_limit(6, 60)
@csrf_protect
def api_signin():
    payload = request.get_json() or {}
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""

    if is_signin_locked(email):
        return jsonify({"success": False, "message": "Too many failed sign-in attempts. Try again later."}), 429

    db = get_db()
    user = db.execute("SELECT id, password_hash, verified, role FROM users WHERE email = ?", (email,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        record_failed_signin(email)
        return jsonify({"success": False, "message": "Email or password is incorrect."}), 401

    if not user["verified"]:
        return jsonify({"success": False, "message": "Please verify your email before signing in."}), 403

    clear_failed_signin(email)
    session.clear()
    session["user_id"] = user["id"]
    return jsonify({"success": True, "message": "Signed in successfully."})


@app.route("/api/auth/signout", methods=["POST"])
@csrf_protect
def api_signout():
    session.clear()
    return jsonify({"success": True, "message": "Signed out successfully."})


@app.route("/api/auth/me")
def api_me():
    if g.user is None:
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "email": g.user["email"]})


@app.route("/api/csrf-token")
def api_csrf_token():
    token = session.setdefault("csrf_token", secrets.token_urlsafe(24))
    return jsonify({"csrf_token": token})


@app.route("/api/stats")
def api_stats():
    db = get_db()
    password_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    clerk_users = db.execute("SELECT COUNT(*) FROM clerk_users").fetchone()[0]
    users_count = password_users + clerk_users
    scans_count = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    threats_count = db.execute(
        "SELECT COUNT(*) FROM scans WHERE category IN ('Phishing','Social Engineering','Image Phishing','Alert')"
    ).fetchone()[0]
    safe_count = db.execute(
        "SELECT COUNT(*) FROM scans WHERE category = 'Safe'"
    ).fetchone()[0]
    suspicious_count = db.execute(
        "SELECT COUNT(*) FROM scans WHERE category = 'Suspicious'"
    ).fetchone()[0]
    last_scan_row = db.execute(
        "SELECT created_at FROM scans ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    last_scan = last_scan_row[0] if last_scan_row else None
    threat_index = round((threats_count / scans_count * 100)) if scans_count > 0 else 0
    return jsonify({
        "users": users_count,
        "scans": scans_count,
        "threats": threats_count,
        "safe": safe_count,
        "suspicious": suspicious_count,
        "last_scan": last_scan,
        "threat_index": threat_index
    })


@app.route("/api/scan", methods=["POST"])
@rate_limit(10, 60)
@csrf_protect
def api_scan():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

    payload = request.get_json() or {}
    url = (payload.get("url") or "").strip()
    text = (payload.get("text") or "").strip()
    scan_type = payload.get("type", "url")
    user = current_user_identifier()
    if user is None:
        return jsonify({"success": False, "message": "Authentication required."}), 401

    user_id = user["id"]

    if scan_type == "url":
        if not url:
            return jsonify({"success": False, "message": "URL is required."}), 400
        result = scan_url(url)
        save_scan(user_id, "url", url, result)
        return jsonify({"success": True, "saved": True, "result": result})

    if scan_type == "msg":
        if not text:
            return jsonify({"success": False, "message": "Input text is required."}), 400
        result = scan_content("msg", text)
        save_scan(user_id, "msg", text, result)
        return jsonify({"success": True, "saved": True, "result": result})

    if scan_type == "image":
        image_name = (payload.get("image_name") or "").strip()
        image_size = payload.get("image_size") or 0
        if not image_name:
            return jsonify({"success": False, "message": "Image name is required."}), 400
        result = scan_image_metadata(image_name, image_size)
        save_scan(user_id, "image", image_name, result)
        return jsonify({"success": True, "saved": True, "result": result})

    return jsonify({"success": False, "message": "Invalid scan type."}), 400


@app.route("/api/history")
@api_login_required
def api_history():
    current = current_user_identifier()
    if current is None:
        return jsonify({"success": False, "message": "Authentication required."}), 401

    requested_user_id = request.args.get("user_id")
    if requested_user_id and is_owner():
        target_user_id = requested_user_id
    else:
        target_user_id = current["id"]

    db = get_db()
    rows = db.execute(
        "SELECT type, content, category, score, confidence, explanation, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC",
        (target_user_id,),
    ).fetchall()
    history = [
        {
            "type": row["type"],
            "content": row["content"],
            "category": row["category"],
            "score": row["score"],
            "confidence": row["confidence"],
            "explanation": row["explanation"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return jsonify({"success": True, "history": history})


@app.route("/api/sync-user", methods=["POST"])
@api_login_required
@csrf_protect
def api_sync_user():
    current = current_user_identifier()
    if current is None or current["type"] != "clerk":
        return jsonify({"success": False, "message": "Clerk authentication required."}), 403

    payload = request.get_json() or {}
    clerk_user_id = (payload.get("user_id") or "").strip()
    email = (payload.get("email") or "").strip().lower()
    if not clerk_user_id or not validate_email(email):
        return jsonify({"success": False, "message": "A valid user_id and email are required."}), 400
    if clerk_user_id != current["id"]:
        app.logger.warning("Clerk sync rejected: mismatched user id %s != %s", clerk_user_id, current["id"])
        return jsonify({"success": False, "message": "Clerk user ID does not match authenticated session."}), 403

    db = get_db()
    created_at = datetime.utcnow().isoformat()
    db.execute(
        """
        INSERT INTO clerk_users (clerk_user_id, email, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(clerk_user_id) DO UPDATE SET email = excluded.email
        """,
        (clerk_user_id, email, created_at),
    )
    db.commit()
    return jsonify({"success": True})


@app.route("/api/admin/users")
@require_role(["owner"])
def api_admin_users():
    db = get_db()
    rows = db.execute(
        """
        SELECT c.clerk_user_id, c.email, c.created_at,
            COALESCE(SUM(CASE WHEN s.user_id = c.clerk_user_id THEN 1 ELSE 0 END), 0) AS scan_count
        FROM clerk_users c
        LEFT JOIN scans s ON s.user_id = c.clerk_user_id
        GROUP BY c.clerk_user_id
        ORDER BY c.created_at DESC
        """
    ).fetchall()

    users = [
        {
            "clerk_user_id": row["clerk_user_id"],
            "email": row["email"],
            "created_at": row["created_at"],
            "scan_count": row["scan_count"],
        }
        for row in rows
    ]
    return jsonify({"success": True, "users": users})


@app.route("/api/admin/user/<user_id>/role", methods=["POST"])
@require_role(["owner"])
def api_admin_set_role(user_id):
    payload = request.get_json() or {}
    new_role = (payload.get("role") or "").strip().lower()
    if not new_role:
        return jsonify({"success": False, "message": "role is required"}), 400

    db = get_db()
    # Determine whether this is a local numeric id or a clerk user id
    target_table = "users" if user_id.isdigit() else "clerk_users"
    col = "id" if target_table == "users" else "clerk_user_id"
    db.execute(f"UPDATE {target_table} SET role = ? WHERE {col} = ?", (new_role, user_id))
    db.commit()
    return jsonify({"success": True, "user_id": user_id, "role": new_role})


@app.route("/api/admin/user/<user_id>/disable", methods=["POST"])
@require_role(["owner"])
def api_admin_disable_user(user_id):
    payload = request.get_json() or {}
    disabled = bool(payload.get("disabled", True))

    db = get_db()
    target_table = "users" if user_id.isdigit() else "clerk_users"
    col = "id" if target_table == "users" else "clerk_user_id"
    db.execute(f"UPDATE {target_table} SET disabled = ? WHERE {col} = ?", (1 if disabled else 0, user_id))
    db.commit()
    return jsonify({"success": True, "user_id": user_id, "disabled": disabled})


@app.route("/api/admin/user/<user_id>", methods=["DELETE"])
@require_role(["owner"])
def api_admin_delete_user(user_id):
    db = get_db()
    target_table = "users" if user_id.isdigit() else "clerk_users"
    col = "id" if target_table == "users" else "clerk_user_id"

    # Delete scans for this user id (scans.user_id is stored as TEXT)
    db.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
    db.execute(f"DELETE FROM {target_table} WHERE {col} = ?", (user_id,))
    db.commit()
    return jsonify({"success": True, "deleted": user_id})

if __name__ == "__main__":
    app.run(debug=True)
