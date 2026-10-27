import sqlite3
from datetime import datetime

DB_FILE = "fim.db"


def connect():
    return sqlite3.connect(DB_FILE)


def init_db():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                file_hash TEXT,
                severity TEXT DEFAULT 'normal'
            )
        """)


def add_event(event_type, path, file_hash="", severity="normal"):
    with connect() as conn:
        conn.execute(
            "INSERT INTO events (time, event_type, path, file_hash, severity) "
            "VALUES (?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             event_type, path, file_hash, severity),
        )


def get_events(limit=50):
    with connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def count_by_type():
    with connect() as conn:
        rows = conn.execute(
            "SELECT event_type, COUNT(*) FROM events GROUP BY event_type"
        ).fetchall()
    return dict(rows)