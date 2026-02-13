import os
import sqlite3
import time
import hashlib
import secrets

DB_PATH = os.getenv("DB_PATH", "data.db")

def _conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL;")
    return c

def init_db():
    with _conn() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS otp (
            email TEXT NOT NULL,
            target TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (email, target)
        );
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS session (
            token TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            target TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS ratelimit (
            k TEXT PRIMARY KEY,
            window_start INTEGER NOT NULL,
            count INTEGER NOT NULL
        );
        """)
        con.commit()

def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def upsert_otp(email: str, target: str, code: str, ttl_seconds: int = 600):
    now = int(time.time())
    expires = now + ttl_seconds
    ch = hash_code(code)
    with _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO otp(email,target,code_hash,created_at,expires_at,attempts) VALUES (?,?,?,?,?,0)",
            (email, target, ch, now, expires),
        )
        con.commit()

def verify_otp(email: str, target: str, code: str, max_attempts: int = 5) -> bool:
    now = int(time.time())
    with _conn() as con:
        row = con.execute(
            "SELECT code_hash, expires_at, attempts FROM otp WHERE email=? AND target=?",
            (email, target),
        ).fetchone()
        if not row:
            return False
        code_hash, expires_at, attempts = row
        if now > int(expires_at):
            return False
        if int(attempts) >= max_attempts:
            return False

        ok = (hash_code(code) == code_hash)
        con.execute(
            "UPDATE otp SET attempts=? WHERE email=? AND target=?",
            (int(attempts) + 1, email, target),
        )
        if ok:
            con.execute("DELETE FROM otp WHERE email=? AND target=?", (email, target))
        con.commit()
        return ok

def create_session(email: str, target: str, ttl_seconds: int = 1800) -> str:
    now = int(time.time())
    expires = now + ttl_seconds
    token = secrets.token_urlsafe(32)
    with _conn() as con:
        con.execute(
            "INSERT INTO session(token,email,target,created_at,expires_at) VALUES (?,?,?,?,?)",
            (token, email, target, now, expires),
        )
        con.commit()
    return token

def validate_session(token: str, email: str, target: str) -> bool:
    now = int(time.time())
    with _conn() as con:
        row = con.execute(
            "SELECT expires_at FROM session WHERE token=? AND email=? AND target=?",
            (token, email, target),
        ).fetchone()
        if not row:
            return False
        expires_at = int(row[0])
        if now > expires_at:
            con.execute("DELETE FROM session WHERE token=?", (token,))
            con.commit()
            return False
        return True

def ratelimit_hit(key: str, window_seconds: int, max_requests: int) -> bool:
    now = int(time.time())
    window_start = now - (now % window_seconds)

    with _conn() as con:
        row = con.execute("SELECT window_start, count FROM ratelimit WHERE k=?", (key,)).fetchone()
        if not row:
            con.execute("INSERT INTO ratelimit(k,window_start,count) VALUES (?,?,?)", (key, window_start, 1))
            con.commit()
            return False

        ws, count = int(row[0]), int(row[1])
        if ws != window_start:
            con.execute("UPDATE ratelimit SET window_start=?, count=? WHERE k=?", (window_start, 1, key))
            con.commit()
            return False

        if count >= max_requests:
            return True

        con.execute("UPDATE ratelimit SET count=? WHERE k=?", (count + 1, key))
        con.commit()
        return False
