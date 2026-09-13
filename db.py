"""Shared SQLite connection helpers.

Extracted out of app.py so both the main app and the blueprints
(e.g. blueprints/stats.py) can access the database without circular imports.
"""
import os
import sqlite3

from flask import g

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "cyberguard.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()
