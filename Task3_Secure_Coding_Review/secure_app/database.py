"""
Remediated & Hardened Database Management Module
Author: CodeAlpha Cybersecurity Intern
Task: Task 3 - Secure Coding Review

REMEDIATION CONTROLS:
- Parameterized SQL Prepared Statements (CWE-89 Mitigation)
- Modern Salted Password Hashing via Scrypt/PBKDF2 (CWE-327 & CWE-256 Mitigation)
- Atomic Transactions & SQL Constraints
"""

import os
import sqlite3
from typing import Optional, Dict, Any, List
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "secure.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS accounts")

    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    cursor.execute("""
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            balance REAL NOT NULL CHECK(balance >= 0)
        )
    """)

    # Remediation 4: Salted, slow key-derivation password hashing (PBKDF2/Scrypt)
    admin_pw_hash = generate_password_hash("AdminSecurePass!2026", method="scrypt")
    alice_pw_hash = generate_password_hash("AliceSecurePass#99", method="scrypt")
    bob_pw_hash = generate_password_hash("BobSecurePass$88", method="scrypt")

    # Remediation 1: Parameterized prepared insert statements
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   ("admin", admin_pw_hash, "admin"))
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   ("alice", alice_pw_hash, "user"))
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   ("bob", bob_pw_hash, "user"))

    cursor.execute("INSERT INTO accounts (username, balance) VALUES (?, ?)", ("alice", 1500.0))
    cursor.execute("INSERT INTO accounts (username, balance) VALUES (?, ?)", ("bob", 850.0))

    conn.commit()
    conn.close()


# Remediation 1: SQL Injection eliminated via parameterized queries
def authenticate_user(username: str, password_candidate: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    # Parameterized query with '?' placeholder
    cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row["password_hash"], password_candidate):
        return dict(row)
    return None


def search_users_secure(term: str) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    # Parameterized wildcard search
    cursor.execute("SELECT id, username, role FROM users WHERE username LIKE ?", (f"%{term}%",))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_account_balance(username: str) -> float:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM accounts WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return float(row["balance"]) if row else 0.0


def transfer_funds_secure(sender: str, recipient: str, amount: float) -> bool:
    """
    Executes an atomic transfer using database transactions and balance verification.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        # Verify sender balance
        cursor.execute("SELECT balance FROM accounts WHERE username = ?", (sender,))
        sender_row = cursor.fetchone()
        if not sender_row or sender_row["balance"] < amount:
            conn.close()
            return False

        # Verify recipient exists
        cursor.execute("SELECT id FROM accounts WHERE username = ?", (recipient,))
        if not cursor.fetchone():
            conn.close()
            return False

        # Atomic debit and credit
        cursor.execute("UPDATE accounts SET balance = balance - ? WHERE username = ?", (amount, sender))
        cursor.execute("UPDATE accounts SET balance = balance + ? WHERE username = ?", (amount, recipient))
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.rollback()
        conn.close()
        return False
