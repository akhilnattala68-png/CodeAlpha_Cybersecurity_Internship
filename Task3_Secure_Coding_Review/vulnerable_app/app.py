"""
Intentionally Vulnerable Demonstration Web Application
Author: CodeAlpha Cybersecurity Intern
Task: Task 3 - Secure Coding Review

PURPOSE:
This web application is deliberately engineered with 10 classic web security vulnerabilities
for SAST scanning demonstration, code auditing, and security review comparison.

VULNERABILITIES DEMONSTRATED:
1.  SQL Injection (CWE-89)
2.  Cross-Site Scripting (XSS) (CWE-79)
3.  Cross-Site Request Forgery (CSRF) (CWE-352)
4.  Weak Password Storage (MD5 / unsalted) (CWE-327 / CWE-256)
5.  Hardcoded Secrets & API Keys (CWE-798)
6.  Insecure Session Cookie Configuration (CWE-614 / CWE-1004)
7.  Missing Input Validation & Bounds Checking (CWE-20)
8.  Insecure Error Handling & Verbose Debugger (CWE-209)
9.  Missing HTTP Security Headers (CWE-693)
10. Known Vulnerable Dependencies (CWE-1395)
"""

import hashlib
import os
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify
import database

app = Flask(__name__)

# ---------------------------------------------------------------------------
# VULNERABILITY 5 (CWE-798): Hardcoded Sensitive Credentials & Secret Keys
# Bandit Rule: B105 (hardcoded_password_string), B106 (hardcoded_secret_key)
# ---------------------------------------------------------------------------
app.config["SECRET_KEY"] = "HARDCODED_INSECURE_FLASK_SECRET_KEY_998877"
ADMIN_API_TOKEN = "SUPER_SECRET_INTERNAL_API_KEY_XYZZY"
DATABASE_ROOT_PASSWORD = "root_admin_password_12345"

# ---------------------------------------------------------------------------
# VULNERABILITY 6 (CWE-614, CWE-1004): Insecure Session Cookie Configuration
# Missing HttpOnly allows JavaScript access to session cookie (XSS -> Session Hijacking)
# Missing Secure allows cookie transmission over unencrypted HTTP
# SameSite='None' allows cross-site transmission (facilitates CSRF)
# ---------------------------------------------------------------------------
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "None"


# ---------------------------------------------------------------------------
# VULNERABILITY 9 (CWE-693): Missing HTTP Security Headers
# Application does not set Content-Security-Policy, X-Frame-Options,
# X-Content-Type-Options, or Strict-Transport-Security headers.
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    user = session.get("user")
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>Vulnerable Banking Portal</title></head>
        <body style="font-family: Arial; padding: 20px;">
            <h1>Vulnerable Banking Demo Portal [AUDIT TARGET]</h1>
            <p>Status: {% if user %}Logged in as: <strong>{{ user }}</strong> (<a href="/logout">Logout</a>){% else %}Guest (<a href="/login">Login</a>){% endif %}</p>
            <hr>
            <h3>Features:</h3>
            <ul>
                <li><a href="/login">Login (Vulnerable to SQL Injection)</a></li>
                <li><a href="/search?q=alice">User Search (Vulnerable to Reflected XSS)</a></li>
                <li><a href="/transfer">Transfer Funds (Vulnerable to CSRF & Missing Input Validation)</a></li>
                <li><a href="/admin/config?key=SUPER_SECRET_INTERNAL_API_KEY_XYZZY">Admin Config (Hardcoded Secret)</a></li>
                <li><a href="/cause-error">Trigger Exception (Verbose Debugger Leak)</a></li>
            </ul>
        </body>
        </html>
    """, user=user)


# ---------------------------------------------------------------------------
# VULNERABILITY 1 (CWE-89): SQL Injection in Authentication
# VULNERABILITY 4 (CWE-327): Weak MD5 Cryptographic Hash
# Bandit Rule: B608 (hardcoded_sql_expressions), B324 (hashlib md5)
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        raw_password = request.form.get("password", "")

        # CWE-327: Use of weak, broken MD5 hash
        password_md5 = hashlib.md5(raw_password.encode()).hexdigest()

        # CWE-89: Raw string formatted SQL query
        user = database.query_user_vulnerable(username, password_md5)

        if user:
            session["user"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("index"))
        else:
            error = "Invalid username or password"

    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>Login - Vulnerable Demo</title></head>
        <body style="font-family: Arial; padding: 20px;">
            <h2>Login</h2>
            {% if error %}<p style="color:red;">{{ error }}</p>{% endif %}
            <form method="POST">
                <p>Username: <input type="text" name="username"></p>
                <p>Password: <input type="password" name="password"></p>
                <button type="submit">Log In</button>
            </form>
            <p><em>Audit Note: Try username payload: <code>admin' --</code> to bypass password verification!</em></p>
        </body>
        </html>
    """, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# VULNERABILITY 2 (CWE-79): Reflected Cross-Site Scripting (XSS)
# User input from query parameter 'q' is rendered directly into HTML without escaping.
# Bandit Rule: B701 (jinja2_autoescape_false / unescaped template)
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Results fetched via vulnerable search
    results = database.search_users_vulnerable(query) if query else []

    # CWE-79: Reflected XSS by interpolating raw unescaped input into HTML string
    # Attack payload: <script>alert('XSS-Injected!')</script>
    html_response = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h2>User Search</h2>
        <form method="GET" action="/search">
            <input type="text" name="q" value="{query}">
            <button type="submit">Search</button>
        </form>
        <hr>
        <h3>Search Query Echo: {query}</h3>
        <p>Found {len(results)} match(es):</p>
        <ul>
    """
    for r in results:
        html_response += f"<li>User: {r['username']} (Role: {r['role']})</li>"
    html_response += """
        </ul>
        <a href="/">Back to Home</a>
    </body>
    </html>
    """
    return html_response


# ---------------------------------------------------------------------------
# VULNERABILITY 3 (CWE-352): Cross-Site Request Forgery (CSRF)
# VULNERABILITY 7 (CWE-20): Missing Input Validation & Negative Balance Bounds
# State-changing endpoint lacks CSRF token validation and accepts negative amounts.
# ---------------------------------------------------------------------------
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if "user" not in session:
        return redirect(url_for("login"))

    msg = None
    if request.method == "POST":
        recipient = request.form.get("recipient", "")
        # CWE-20: Missing input validation and type bounds checking
        # Attacker can submit negative amount (-500) to steal money, or invalid non-numeric inputs!
        amount_raw = request.form.get("amount", "0")
        try:
            amount = float(amount_raw)
            # CWE-352: No CSRF token verification!
            # Any malicious website hosting <form action="http://localhost:5001/transfer" method="POST">
            # can execute unauthorized transfers on behalf of authenticated users!
            conn = database.get_db()
            cursor = conn.cursor()
            cursor.execute(f"UPDATE accounts SET balance = balance - {amount} WHERE username = '{session['user']}'")
            cursor.execute(f"UPDATE accounts SET balance = balance + {amount} WHERE username = '{recipient}'")
            conn.commit()
            conn.close()
            msg = f"Successfully transferred ${amount} to {recipient}!"
        except Exception as e:
            msg = f"Transfer failed: {e}"

    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>Transfer Funds</title></head>
        <body style="font-family: Arial; padding: 20px;">
            <h2>Fund Transfer (CSRF & Input Validation Target)</h2>
            {% if msg %}<p style="color:green;">{{ msg }}</p>{% endif %}
            <form method="POST">
                <!-- CWE-352: NO CSRF TOKEN FIELD HERE -->
                <p>Recipient: <input type="text" name="recipient" value="bob"></p>
                <p>Amount: <input type="text" name="amount" value="100"></p>
                <button type="submit">Execute Transfer</button>
            </form>
            <p><a href="/">Back to Home</a></p>
        </body>
        </html>
    """, msg=msg)


# ---------------------------------------------------------------------------
# VULNERABILITY 5 (CWE-798): Hardcoded API Key check
# ---------------------------------------------------------------------------
@app.route("/admin/config")
def admin_config():
    key = request.args.get("key", "")
    if key == ADMIN_API_TOKEN:
        return jsonify({
            "status": "authorized",
            "db_password": DATABASE_ROOT_PASSWORD,
            "secret_key": app.config["SECRET_KEY"]
        })
    return jsonify({"error": "Unauthorized"}), 401


# ---------------------------------------------------------------------------
# VULNERABILITY 8 (CWE-209): Insecure Error Handling & Information Disclosure
# Detailed system exception stack traces exposed to end-users.
# ---------------------------------------------------------------------------
@app.route("/cause-error")
def cause_error():
    # Intentionally trigger division by zero to expose stack trace and environment state
    x = 1 / 0
    return str(x)


# ---------------------------------------------------------------------------
# VULNERABILITY 8 (CWE-209): Insecure Debugger Enabled
# Bandit Rule: B201 (flask_debug_true)
# debug=True exposes interactive Werkzeug console allowing remote code execution!
# ---------------------------------------------------------------------------
def run_app():
    database.init_db()
    # CWE-209: debug=True in production / host='0.0.0.0'
    app.run(host="0.0.0.0", port=5001, debug=True)


if __name__ == "__main__":
    run_app()
