# TECHNICAL PROJECT REPORT: TASK 3 - SECURE CODING REVIEW & SECURITY AUDIT

**Internship Program**: CodeAlpha Cybersecurity Internship  
**Task Number**: Task 3  
**Project Title**: Practical Security Audit, Static Application Security Testing (SAST) & Remediation  
**Author**: CodeAlpha Cybersecurity Intern  
**Date**: November 2026  
**Status**: Completed & Verified  

---

## 1. Executive Summary

In contemporary application security, shifting security left into the early phases of the Software Development Life Cycle (SDLC) is essential for mitigating catastrophic data breaches and regulatory non-compliance. Under Task 3 of the CodeAlpha Cybersecurity Internship, a practical, rigorous source code security audit was performed on a sample Python/Flask web application.

A deliberately vulnerable demonstration system (`vulnerable_app`) was constructed to model ten prevalent web security weaknesses. Using **Bandit** (an automated SAST scanner), dependency audit tools, and manual threat modeling, the codebase was audited. Every finding was cataloged, assigned standardized Common Weakness Enumeration (CWE) identifiers and severity ratings, and analyzed for real-world exploit impact.

Subsequently, a production-grade, hardened counterpart (`secure_app`) was engineered. Re-scanning the remediated codebase with Bandit verified a **100% resolution rate (reducing SAST issues from 15 to 0)** while eliminating all manual audit findings through defense-in-depth engineering.

---

## 2. Audit Scope & Methodological Framework

### 2.1 Audited Components
- **Application Logic**: Authentication routes, user search directory, fund transfer state changes, configuration endpoints, and error handling.
- **Database Layer**: SQLite relational queries, user schema, password hashing mechanisms, and transaction integrity.
- **Session & Transport**: Cookie configuration (HttpOnly, Secure, SameSite) and browser security headers (CSP, HSTS, X-Frame-Options).
- **Supply Chain**: Dependency manifests and third-party library versions.

### 2.2 Security Tools & Standards
- **Static Application Security Testing (SAST)**: Bandit 1.9.4.
- **Dependency Audit**: Python software supply chain inspection (CVE vulnerability correlation).
- **Standards & Baselines**: OWASP Top 10 (2021), MITRE CWE, SANS Top 25 Most Dangerous Software Errors.

---

## 3. Detailed Audit Findings & Impact Analysis

| ID | Finding Name | CWE | CVSS v3.1 | Severity | Vulnerable Mechanism | Exploit Impact |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| **SEC-01** | **SQL Injection (SQLi)** | CWE-89 | **9.8** | **CRITICAL** | Raw f-string SQL query formatting in `query_user_vulnerable()` and `search_users_vulnerable()`. | Complete authentication bypass (e.g. `admin' --`), arbitrary database exfiltration, and unauthorized record modification. |
| **SEC-02** | **Reflected Cross-Site Scripting (XSS)** | CWE-79 | **7.5** | **HIGH** | Unescaped search parameter `q` interpolated into HTML response. | Execution of malicious JavaScript in victim's browser, session token theft, and DOM defacement. |
| **SEC-03** | **Cross-Site Request Forgery (CSRF)** | CWE-352 | **8.1** | **HIGH** | State-changing `/transfer` POST route lacks anti-forgery synchronizer tokens. | Unauthorized execution of fund transfers or account state modifications on behalf of authenticated victims. |
| **SEC-04** | **Weak Cryptographic Password Storage** | CWE-327 | **7.5** | **HIGH** | Passwords stored as unsalted MD5 hashes (`hashlib.md5()`). | Instant password cracking via precomputed rainbow tables and high-speed GPU hash exhaustion. |
| **SEC-05** | **Hardcoded Credentials & Secrets** | CWE-798 | **7.4** | **HIGH** | Plaintext `SECRET_KEY`, `ADMIN_API_TOKEN`, and database passwords committed to source code. | Compromise of session signing integrity, unauthorized administrative access, and credential harvesting from repositories. |
| **SEC-06** | **Insecure Session Cookie Flags** | CWE-614 | **6.5** | **MEDIUM** | `SESSION_COOKIE_HTTPONLY = False`, `SECURE = False`, `SAMESITE = 'None'`. | Session cookies exposed to client-side scripts during XSS attacks, sniffing over cleartext HTTP, and cross-site form transmission. |
| **SEC-07** | **Missing Input & Bounds Validation** | CWE-20 | **6.5** | **MEDIUM** | Transfer route accepts negative amounts without type or numerical bounds validation. | Negative balance exploitation (stealing funds via inverse transfers) and database corruption from malformed data. |
| **SEC-08** | **Insecure Error Handling & Debug Mode** | CWE-209 | **7.5** | **HIGH** | `app.run(debug=True, host='0.0.0.0')` with interactive Werkzeug console enabled. | Exposure of stack traces, internal source paths, environment variables, and remote code execution (RCE) via Werkzeug interactive debugger PIN console. |
| **SEC-09** | **Missing HTTP Security Headers** | CWE-693 | **5.3** | **MEDIUM** | Application emits zero browser defense headers (CSP, HSTS, X-Frame-Options, X-Content-Type). | Susceptibility to clickjacking frame embedding, MIME-sniffing drive-by downloads, and downgrade attacks. |
| **SEC-10** | **Known Vulnerable Dependencies** | CWE-1395 | **6.5** | **MEDIUM** | Pinned obsolete versions: Flask 2.0.1, Werkzeug 2.0.1 (CVE-2023-46136 DoS, CVE-2022-3491 Path Traversal). | Denial of service via multipart form payload exhaustion and potential path traversal in legacy utilities. |

---

## 4. Secure Remediation Engineering

In `secure_app/`, every confirmed weakness was re-engineered using defense-in-depth principles:

### 4.1 SQL Injection Remediation (CWE-89)
- **Fix**: Replaced all string concatenations with DB-API prepared statements using `?` placeholders.
- **Code**:
  ```python
  cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
  ```
- **Result**: User input is strictly treated as literal data, rendering SQL syntax manipulation impossible.

### 4.2 Cross-Site Scripting Remediation (CWE-79)
- **Fix**: Implemented contextual HTML auto-escaping within Jinja2 templates without raw string formatting, supported by strict Content-Security-Policy (CSP).
- **Code**:
  ```python
  return render_template_string("<h3>Search Query Echo: <code>{{ query }}</code></h3>", query=query)
  ```
- **Result**: HTML metacharacters (`<`, `>`, `&`, `"`, `'`) are converted to safe entity equivalents (`&lt;`, `&gt;`).

### 4.3 CSRF Remediation (CWE-352)
- **Fix**: Generated cryptographically random synchronizer tokens (`secrets.token_hex(32)`) tied to the user's session. Every state-changing POST form requires a matching hidden `csrf_token` validated via `secrets.compare_digest()`.

### 4.4 Cryptographic Hashing Remediation (CWE-327 & CWE-256)
- **Fix**: Replaced MD5 with **Scrypt / PBKDF2** with individual salts and high iteration work factors using `werkzeug.security.generate_password_hash()`.
- **Result**: Offline brute-force and rainbow table attacks are rendered computationally unfeasible.

### 4.5 Secret Management Remediation (CWE-798)
- **Fix**: Stripped hardcoded keys from codebase. Secrets are loaded dynamically from environment variables (`os.environ.get("FLASK_SECRET_KEY")`) with secure cryptographic fallbacks (`secrets.token_hex(32)`).

### 4.6 Session Cookie Hardening (CWE-614 & CWE-1004)
- **Fix**:
  ```python
  app.config["SESSION_COOKIE_HTTPONLY"] = True
  app.config["SESSION_COOKIE_SECURE"] = True
  app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
  ```
- **Result**: Disallows JavaScript DOM access to session cookies, enforces TLS transmission, and prevents cross-origin cookie leakage.

### 4.7 Input Validation & Numerical Bounds (CWE-20)
- **Fix**: Enforced regex format constraints on usernames (`^[a-zA-Z0-9_\-]{3,30}$`) and strict float validation restricting transfers to `$0.01 <= amount <= $10,000.00`.

### 4.8 Error Handling & Server Configuration (CWE-209)
- **Fix**: Disabled debug mode (`debug=False`), bound socket exclusively to localhost (`127.0.0.1`), and established generic `@app.errorhandler(500)` routines that log stack traces internally while presenting non-disclosing messages to clients.

### 4.9 HTTP Security Headers Middleware (CWE-693)
- **Fix**: Configured `@app.after_request` filter injecting:
  - `Content-Security-Policy: default-src 'self'`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `Referrer-Policy: strict-origin-when-cross-origin`

### 4.10 Dependency Hardening (CWE-1395)
- **Fix**: Upgraded dependencies to secure release branches (Flask >= 3.1.0, Werkzeug >= 3.1.0, Jinja2 >= 3.1.5, Requests >= 2.32.0), resolving all known CVE advisories.

---

## 5. Before vs. After Comparative Verification

### 5.1 Quantitative SAST Metrics (Bandit)

| Metric | Vulnerable Application (`vulnerable_app`) | Remediated Application (`secure_app`) | Improvement |
| :--- | :---: | :---: | :---: |
| **High Severity Issues** | 4 | **0** | **-100%** |
| **Medium Severity Issues** | 8 | **0** | **-100%** |
| **Low Severity Issues** | 3 | **0** | **-100%** |
| **Total SAST Findings** | **15** | **0** | **-100% CLEAN** |
| **Total Lines Scanned** | 231 LOC | 383 LOC | +65% (Security Controls) |

### 5.2 Verification Artifacts
- **`reports/bandit_vulnerable.txt`**: Logs 15 distinct issues across B104, B105, B201, B324, and B608.
- **`reports/bandit_secure.txt`**: Confirms `"No issues identified"` across all 383 lines of code.
- **`reports/audit_findings_matrix.csv`**: Complete 10-point remediation matrix with verified CWE mappings.

---

## 6. Mentor Demonstration Guide

To demonstrate Task 3 to your internship coordinator:
1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd CodeAlpha_Cybersecurity_Internship\Task3_Secure_Coding_Review
   ```
2. Execute the automated security audit suite:
   ```powershell
   python run_audit.py
   ```
   Show the mentor the console summary: **15 Bandit issues detected in vulnerable_app vs. 0 in secure_app**.
3. Open `reports/audit_comparison.md` and `reports/audit_findings_matrix.csv` to showcase the structured 10-point vulnerability breakdown.
4. Demonstrate code differences between `vulnerable_app/app.py` and `secure_app/app.py` (prepared statements, CSRF tokens, secure password hashing, and security headers).
5. Run the secure application to demonstrate runtime stability:
   ```powershell
   python secure_app/app.py
   ```

---

## 7. Conclusion

Task 3 successfully demonstrated the end-to-end security audit lifecycle: static vulnerability analysis, threat modeling, defensive remediation engineering, and automated regression verification. The project exemplifies professional secure coding standards and satisfies all CodeAlpha internship criteria.
