"""
Remediated & Hardened Enterprise Web Application
Author: CodeAlpha Cybersecurity Intern
Task: Task 3 - Secure Coding Review

REMEDIATION MATRIX:
1.  SQL Injection (CWE-89)             -> Parameterized Prepared Statements (DB-API)
2.  Cross-Site Scripting (CWE-79)        -> Auto-Escaped Jinja Templates + Content-Security-Policy
3.  CSRF (CWE-352)                       -> Cryptographic Session Synchronizer Tokens
4.  Weak Password Storage (CWE-327)      -> Scrypt / PBKDF2 Salted Key Derivation
5.  Hardcoded Credentials (CWE-798)      -> Environment Variables & Cryptographic Generation
6.  Insecure Session Cookies (CWE-614)   -> HttpOnly=True, Secure=True, SameSite='Lax'
7.  Missing Input Validation (CWE-20)    -> Strict Regex & Numerical Bounds Validation
8.  Insecure Error Handling (CWE-209)    -> debug=False, Custom Generic Error Handlers
9.  Missing Security Headers (CWE-693)   -> Full Defense-in-Depth Headers Middleware
10. Vulnerable Dependencies (CWE-1395)   -> Pinned Modern, Secure Dependencies
"""

import logging
import os
import re
import secrets
from flask import (
    Flask, request, session, redirect, url_for, render_template_string,
    jsonify, abort, make_response
)
import database

app = Flask(__name__)

# ---------------------------------------------------------------------------
# REMEDIATION 5 (CWE-798): Secret keys loaded strictly from environment
# Bandit Rule: B105 / B106 mitigated
# ---------------------------------------------------------------------------
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
ADMIN_API_TOKEN = os.environ.get("ADMIN_API_TOKEN") or secrets.token_urlsafe(32)

# ---------------------------------------------------------------------------
# REMEDIATION 6 (CWE-614, CWE-1004): Secure Session Cookie Hardening
# HttpOnly prevents JavaScript access, thwarting XSS session theft
# SameSite='Lax' defends against cross-site request forgery
# Secure ensures cookies travel exclusively across TLS/HTTPS
# ---------------------------------------------------------------------------
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Configure secure internal logging (never exposed to client)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ---------------------------------------------------------------------------
# REMEDIATION 9 (CWE-693): HTTP Defense-in-Depth Security Headers Middleware
# Injects CSP, HSTS, X-Frame-Options, X-Content-Type-Options
# ---------------------------------------------------------------------------
@app.after_request
def apply_security_headers(response):
    # Content Security Policy (CSP): Restricts script execution to local origin
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    # Prevent MIME-type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking / frame injection
    response.headers["X-Frame-Options"] = "DENY"
    # Enable XSS filter in legacy browsers
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Strict Transport Security (HSTS) - enforce TLS
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Referrer privacy policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ---------------------------------------------------------------------------
# REMEDIATION 3 (CWE-352): Cryptographic CSRF Synchronizer Token Protection
# ---------------------------------------------------------------------------
def generate_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf_token


def validate_csrf():
    """Validates submitted CSRF token against active session token."""
    token = request.form.get("csrf_token")
    expected = session.get("_csrf_token")
    if not expected or not token or not secrets.compare_digest(token, expected):
        logging.warning(f"CSRF validation failed for IP {request.remote_addr} on {request.path}")
        abort(403)


# ---------------------------------------------------------------------------
# REMEDIATION 7 (CWE-20): Strict Input Validation & Type Sanitization
# ---------------------------------------------------------------------------
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{3,30}$")


def validate_username(username: str) -> bool:
    return bool(USERNAME_REGEX.match(username))


def validate_transfer_amount(amount_str: str) -> float:
    try:
        val = float(amount_str)
        if val <= 0:
            raise ValueError("Transfer amount must be strictly greater than $0.00.")
        if val > 10000.0:
            raise ValueError("Transfer exceeds per-transaction limit of $10,000.00.")
        return round(val, 2)
    except (ValueError, TypeError) as err:
        raise ValueError(f"Invalid monetary value: {err}")


# ---------------------------------------------------------------------------
# ROUTES & LOGIC
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    user = session.get("user")
    balance = database.get_account_balance(user) if user else 0.0
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Banking Portal - Hardened Demo</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }
                .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 24px; max-width: 650px; margin: 0 auto; }
                a { color: #38bdf8; text-decoration: none; }
                a:hover { text-decoration: underline; }
                .badge { background: #10b981; color: #000; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>🛡️ CodeAlpha Secure Banking Portal <span class="badge">SECURED</span></h2>
                <p>Status: {% if user %}Logged in as <strong>{{ user }}</strong> | Balance: <strong>${{ "%.2f"|format(balance) }}</strong> (<a href="/logout">Logout</a>){% else %}Guest (<a href="/login">Login</a>){% endif %}</p>
                <hr style="border: 0; border-top: 1px solid #334155; margin: 20px 0;">
                <h3>Hardened Features:</h3>
                <ul>
                    <li><a href="/login">Secure Login</a> (Parameterized SQL + Scrypt password hash)</li>
                    <li><a href="/search?q=alice">Secure User Directory</a> (Auto-escaped Jinja template + CSP)</li>
                    <li><a href="/transfer">Secure Fund Transfer</a> (CSRF Token + Strict Input Validation)</li>
                    <li><a href="/admin/config">Protected Admin Config</a> (Environment Token Auth)</li>
                    <li><a href="/cause-error">Error Test</a> (Sanitized 500 Generic Error Page)</li>
                </ul>
            </div>
        </body>
        </html>
    """, user=user, balance=balance)


# ---------------------------------------------------------------------------
# REMEDIATION 1 & 4: Secure Authentication with Scrypt & Parameterized SQL
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Input sanitization
        if not validate_username(username):
            error = "Invalid username format. Allowed: 3-30 alphanumeric characters."
        else:
            user = database.authenticate_user(username, password)
            if user:
                # Session fixation prevention: reset session on login
                session.clear()
                session["user"] = user["username"]
                session["role"] = user["role"]
                logging.info(f"Successful authenticated login for: {username}")
                return redirect(url_for("index"))
            else:
                logging.warning(f"Failed authentication attempt for: {username}")
                error = "Invalid username or password"

    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>Secure Login</title></head>
        <body style="font-family: Arial; background: #0f172a; color: #f8fafc; padding: 30px;">
            <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 24px; max-width: 400px; margin: 0 auto;">
                <h2>Secure Login</h2>
                {% if error %}<p style="color: #f87171;">{{ error }}</p>{% endif %}
                <form method="POST">
                    <p>Username: <input type="text" name="username" style="width: 100%; padding: 8px;" required></p>
                    <p>Password: <input type="password" name="password" style="width: 100%; padding: 8px;" required></p>
                    <button type="submit" style="padding: 10px 18px; background: #38bdf8; border: none; border-radius: 4px; font-weight: bold; cursor: pointer;">Log In</button>
                </form>
                <p><a href="/" style="color: #38bdf8;">Back to Home</a></p>
            </div>
        </body>
        </html>
    """, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# REMEDIATION 2 (CWE-79): XSS Eliminated via Auto-Escaped Jinja Templates
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    raw_query = request.args.get("q", "").strip()
    # Limit search query length
    query = raw_query[:50]
    results = database.search_users_secure(query) if query else []

    # Safe: render_template_string utilizes Jinja2 auto-escaping by default
    # Context variable {{ query }} is sanitized before HTML insertion
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>Search Directory</title></head>
        <body style="font-family: Arial; background: #0f172a; color: #f8fafc; padding: 30px;">
            <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 24px; max-width: 600px; margin: 0 auto;">
                <h2>Secure User Directory</h2>
                <form method="GET" action="/search">
                    <input type="text" name="q" value="{{ query }}" style="padding: 8px; width: 70%;">
                    <button type="submit" style="padding: 8px 14px; background: #38bdf8; border: none; border-radius: 4px; font-weight: bold;">Search</button>
                </form>
                <hr style="border-top: 1px solid #334155; margin: 20px 0;">
                <h3>Search Query Echo: <code>{{ query }}</code></h3>
                <p>Found {{ results|length }} result(s):</p>
                <ul>
                    {% for r in results %}
                        <li>User: <strong>{{ r.username }}</strong> (Role: {{ r.role }})</li>
                    {% else %}
                        <li>No users matched your criteria.</li>
                    {% endfor %}
                </ul>
                <p><a href="/" style="color: #38bdf8;">Back to Home</a></p>
            </div>
        </body>
        </html>
    """, query=query, results=results)


# ---------------------------------------------------------------------------
# REMEDIATION 3 & 7: CSRF Token Enforcement & Numeric Bounds Validation
# ---------------------------------------------------------------------------
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if "user" not in session:
        return redirect(url_for("login"))

    msg = None
    msg_type = "info"

    if request.method == "POST":
        # Validate CSRF Token
        validate_csrf()

        recipient = request.form.get("recipient", "").strip()
        amount_raw = request.form.get("amount", "").strip()

        # Input Validation (Recipient format and positive amount constraint)
        if not validate_username(recipient):
            msg = "Recipient username format is invalid."
            msg_type = "error"
        elif recipient == session["user"]:
            msg = "Cannot transfer funds to yourself."
            msg_type = "error"
        else:
            try:
                amount = validate_transfer_amount(amount_raw)
                success = database.transfer_funds_secure(session["user"], recipient, amount)
                if success:
                    msg = f"Successfully transferred ${amount:.2f} to {recipient}."
                    msg_type = "success"
                    logging.info(f"Audit: Transfer ${amount} from {session['user']} to {recipient}")
                else:
                    msg = "Transfer failed. Insufficient funds or recipient does not exist."
                    msg_type = "error"
            except ValueError as ve:
                msg = str(ve)
                msg_type = "error"

    csrf = generate_csrf_token()
    balance = database.get_account_balance(session["user"])

    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>Secure Transfer</title></head>
        <body style="font-family: Arial; background: #0f172a; color: #f8fafc; padding: 30px;">
            <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 24px; max-width: 500px; margin: 0 auto;">
                <h2>Secure Fund Transfer</h2>
                <p>Available Balance: <strong>${{ "%.2f"|format(balance) }}</strong></p>
                {% if msg %}
                    <p style="color: {% if msg_type == 'success' %}#10b981{% else %}#f87171{% endif %}; font-weight: bold;">
                        {{ msg }}
                    </p>
                {% endif %}
                <form method="POST">
                    <!-- REMEDIATION 3: Cryptographic CSRF Synchronizer Token -->
                    <input type="hidden" name="csrf_token" value="{{ csrf }}">
                    <p>Recipient: <input type="text" name="recipient" placeholder="bob" style="width: 100%; padding: 8px;" required></p>
                    <p>Amount ($): <input type="number" step="0.01" min="0.01" max="10000" name="amount" placeholder="50.00" style="width: 100%; padding: 8px;" required></p>
                    <button type="submit" style="padding: 10px 18px; background: #10b981; border: none; border-radius: 4px; font-weight: bold; cursor: pointer;">Confirm & Send</button>
                </form>
                <p><a href="/" style="color: #38bdf8;">Back to Home</a></p>
            </div>
        </body>
        </html>
    """, msg=msg, msg_type=msg_type, csrf=csrf, balance=balance)


# ---------------------------------------------------------------------------
# REMEDIATION 5: Protected Admin Route using Secure Constant-Time Token Compare
# ---------------------------------------------------------------------------
@app.route("/admin/config")
def admin_config():
    auth_header = request.headers.get("Authorization", "")
    key = request.args.get("key", "")

    # Compare tokens securely against timing attacks
    authenticated = False
    if key and secrets.compare_digest(key, ADMIN_API_TOKEN):
        authenticated = True
    elif auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        if secrets.compare_digest(token, ADMIN_API_TOKEN):
            authenticated = True

    if authenticated:
        return jsonify({
            "status": "authorized",
            "security_mode": "hardened",
            "environment": os.environ.get("FLASK_ENV", "secure_audit")
        })

    logging.warning(f"Unauthorized admin config attempt from IP {request.remote_addr}")
    abort(401)


# ---------------------------------------------------------------------------
# REMEDIATION 8 (CWE-209): Sanitized Custom Error Handlers
# Generic error responses without leaking internal file paths or stack traces
# ---------------------------------------------------------------------------
@app.route("/cause-error")
def cause_error():
    # Trigger an internal exception to verify generic error handling
    raise RuntimeError("Internal test exception")


@app.errorhandler(401)
def handle_401(e):
    return jsonify({"error": "Unauthorized Access", "code": 401}), 401


@app.errorhandler(403)
def handle_403(e):
    return jsonify({"error": "Forbidden: CSRF or Access Violation", "code": 403}), 403


@app.errorhandler(404)
def handle_404(e):
    return render_template_string("""
        <body style="background:#0f172a; color:#f8fafc; font-family:Arial; padding:40px; text-align:center;">
            <h2>404 - Resource Not Found</h2>
            <p>The requested URL was not found on this secure server.</p>
            <a href="/" style="color:#38bdf8;">Return Home</a>
        </body>
    """), 404


@app.errorhandler(500)
@app.errorhandler(Exception)
def handle_500(e):
    # Log the real stack trace internally for SOC/developer debugging
    logging.error(f"Internal Application Error [SANITIZED]: {e}", exc_info=True)
    # Return generic, safe message to the client (NO STACK TRACES)
    return render_template_string("""
        <body style="background:#0f172a; color:#f8fafc; font-family:Arial; padding:40px; text-align:center;">
            <h2 style="color:#f87171;">500 - Internal Server Error</h2>
            <p>An unexpected condition occurred. Our security operations center has logged this incident.</p>
            <p><em>Security Notice: Diagnostic tracebacks are suppressed in accordance with safe engineering policies.</em></p>
            <a href="/" style="color:#38bdf8;">Return Home</a>
        </body>
    """), 500


def run_app():
    database.init_db()
    # REMEDIATION 8: debug=False, bound to loopback address (127.0.0.1)
    logging.info("Starting hardened secure application on http://127.0.0.1:5002")
    app.run(host="127.0.0.1", port=5002, debug=False)


if __name__ == "__main__":
    run_app()
