"""
Intentionally Vulnerable Demonstration Database
Author: CodeAlpha Cybersecurity Intern
Task: Task 3 - Secure Coding Review
VULNERABILITY: Raw SQL string concatenation (CWE-89), weak MD5 hashing (CWE-327)
"""

import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnerable.db")


def get_db():
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
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            balance REAL NOT NULL
        )
    """)

    # Seed vulnerable users with weak MD5 passwords
    # CWE-327: Use of broken cryptographic hash (MD5) without salt
    admin_pw = hashlib.md5("admin123".encode()).hexdigest()
    user_pw = hashlib.md5("password".encode()).hexdigest()

    cursor.execute(f"INSERT INTO users (username, password, role) VALUES ('admin', '{admin_pw}', 'admin')")
    cursor.execute(f"INSERT INTO users (username, password, role) VALUES ('alice', '{user_pw}', 'user')")
    cursor.execute(f"INSERT INTO users (username, password, role) VALUES ('bob', '{user_pw}', 'user')")

    cursor.execute("INSERT INTO accounts (username, balance) VALUES ('alice', 1500.0)")
    cursor.execute("INSERT INTO accounts (username, balance) VALUES ('bob', 850.0)")

    conn.commit()
    conn.close()


# CWE-89: SQL Injection via raw string formatting
def query_user_vulnerable(username, password_md5):
    conn = get_db()
    cursor = conn.cursor()
    # Direct string interpolation - VULNERABLE TO SQLi!
    # Example attack payload: ' OR '1'='1
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_md5}'"
    print(f"[DEBUG EXEC SQL]: {query}")
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user


def search_users_vulnerable(term):
    conn = get_db()
    cursor = conn.cursor()
    # SQLi vulnerability in search query
    query = f"SELECT id, username, role FROM users WHERE username LIKE '%{term}%'"
    print(f"[DEBUG EXEC SQL]: {query}")
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows
