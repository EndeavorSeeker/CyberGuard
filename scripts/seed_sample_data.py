#!/usr/bin/env python3
"""Seed the local SQLite DB with sample users (local + clerk) and scans.
Run: python scripts/seed_sample_data.py
"""
import os
import sqlite3
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'cyberguard.db')

from werkzeug.security import generate_password_hash

now = datetime.utcnow()

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
c = conn.cursor()

print('Seeding DB at', DB_PATH)

# Insert a local password user
local_email = 'alice@example.com'
password_hash = generate_password_hash('password123')
created = now.isoformat()
try:
    c.execute(
        "INSERT INTO users (email, password_hash, verified, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (local_email, password_hash, True, 'user', 0, created),
    )
    local_id = c.lastrowid
    print('Inserted local user', local_email, 'id', local_id)
except Exception as e:
    print('Local user insert failed (maybe exists):', e)
    row = c.execute('SELECT id FROM users WHERE email = ?', (local_email,)).fetchone()
    local_id = row['id'] if row else None

# Insert a clerk user (simulate external identity)
clerk_id = 'clerk_test_user_1'
clerk_email = 'ayman.benkardoud@gmail.com'  # this email is allowlisted in auth.py
try:
    c.execute(
        "INSERT INTO clerk_users (clerk_user_id, email, role, disabled, created_at) VALUES (?, ?, ?, ?, ?)",
        (clerk_id, clerk_email, 'owner', 0, created),
    )
    print('Inserted clerk user', clerk_email, 'id', clerk_id)
except Exception as e:
    print('Clerk user insert failed (maybe exists):', e)

# Insert some scans for both users
samples = [
    (str(clerk_id), 'url', 'http://suspicious-login.example.com/login', 'Phishing', 82, 74),
    (str(clerk_id), 'msg', 'Please verify your account immediately', 'Social Engineering', 78, 76),
    (str(local_id), 'url', 'https://example.com', 'Safe', 12, 94),
]
for user_id, ttype, content, category, score, conf in samples:
    try:
        c.execute(
            "INSERT INTO scans (user_id, type, content, category, score, confidence, explanation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, ttype, content, category, score, conf, 'Seeded example', (now - timedelta(minutes=5)).isoformat()),
        )
    except Exception as e:
        print('Scan insert failed:', e)

conn.commit()
conn.close()
print('Seeding complete.')
