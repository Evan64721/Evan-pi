#!/usr/bin/env python3
"""Evan-pi API — accounts + per-game win/loss stats.

Zero third-party dependencies: Python stdlib + SQLite only, so it runs on a
stock Ubuntu box with no pip install. Designed to sit behind nginx, which
proxies /api/* to this process (see deploy/). Passwords are stored as
PBKDF2-HMAC-SHA256 hashes with a per-user salt; sessions are random tokens
kept in an HttpOnly cookie.

Config via environment:
  EV_PORT           port to listen on          (default 8787)
  EV_HOST           bind address               (default 127.0.0.1)
  EV_DB             SQLite file path           (default ./data.db)
  EV_SECURE_COOKIE  send Secure cookie flag    (default 1; set 0 for local http)
"""

import hashlib
import hmac
import http.cookies
import json
import os
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("EV_PORT", "8787"))
HOST = os.environ.get("EV_HOST", "127.0.0.1")
DB_PATH = os.environ.get("EV_DB", os.path.join(os.path.dirname(__file__), "data.db"))
SECURE_COOKIE = os.environ.get("EV_SECURE_COOKIE", "1") not in ("0", "false", "")
COOKIE_NAME = "ev_session"
PBKDF2_ROUNDS = 200_000

# Games we track. Keys must match what the front end reports.
GAMES = [
    {"key": "triangles", "label": "Triangles"},
    {"key": "five-crowns", "label": "Five Crowns"},
]
GAME_KEYS = {g["key"] for g in GAMES}
VALID_OUTCOMES = {"win", "loss", "tie"}


# ----------------------------- database ---------------------------------

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id        INTEGER PRIMARY KEY,
              username  TEXT UNIQUE NOT NULL,
              pass_hash TEXT NOT NULL,
              salt      TEXT NOT NULL,
              created   REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token   TEXT PRIMARY KEY,
              user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              created REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS results (
              id      INTEGER PRIMARY KEY,
              user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              game    TEXT NOT NULL,
              outcome TEXT NOT NULL,
              ts      REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_results_user ON results(user_id, game);
            """
        )


# ----------------------------- auth helpers ------------------------------

def hash_password(password, salt):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             bytes.fromhex(salt), PBKDF2_ROUNDS)
    return dk.hex()


def create_user(conn, username, password):
    salt = secrets.token_hex(16)
    conn.execute(
        "INSERT INTO users (username, pass_hash, salt, created) VALUES (?,?,?,?)",
        (username, hash_password(password, salt), salt, time.time()),
    )
    return conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]


def verify_user(conn, username, password):
    row = conn.execute(
        "SELECT id, pass_hash, salt FROM users WHERE username=?", (username,)
    ).fetchone()
    if not row:
        return None
    expected = row["pass_hash"]
    got = hash_password(password, row["salt"])
    # constant-time compare
    if hmac.compare_digest(expected, got):
        return row["id"]
    return None


def new_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO sessions (token, user_id, created) VALUES (?,?,?)",
                 (token, user_id, time.time()))
    return token


def user_for_token(conn, token):
    if not token:
        return None
    row = conn.execute(
        "SELECT u.id AS id, u.username AS username "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?",
        (token,),
    ).fetchone()
    return row


def stats_for_user(conn, user_id):
    rows = conn.execute(
        "SELECT game, "
        "SUM(CASE WHEN outcome='win' THEN 1 ELSE 0 END) AS wins, "
        "COUNT(*) AS games FROM results WHERE user_id=? GROUP BY game",
        (user_id,),
    ).fetchall()
    by_game = {r["game"]: (r["wins"], r["games"]) for r in rows}
    out = []
    for g in GAMES:
        wins, games = by_game.get(g["key"], (0, 0))
        rate = (wins / games * 100) if games else 0
        out.append({"key": g["key"], "label": g["label"],
                    "wins": wins, "games": games, "winRate": rate})
    return out


# ----------------------------- HTTP layer --------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "EvanPiAPI/1.0"

    # --- small helpers ---
    def _send_json(self, status, payload, set_cookie=None, clear_cookie=False):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if set_cookie is not None:
            self.send_header("Set-Cookie", self._cookie_header(set_cookie))
        if clear_cookie:
            self.send_header("Set-Cookie", self._cookie_header("", max_age=0))
        self.end_headers()
        self.wfile.write(body)

    def _cookie_header(self, value, max_age=None):
        parts = ["%s=%s" % (COOKIE_NAME, value), "Path=/", "HttpOnly", "SameSite=Lax"]
        if SECURE_COOKIE:
            parts.append("Secure")
        if max_age is not None:
            parts.append("Max-Age=%d" % max_age)
        return "; ".join(parts)

    def _cookie_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(raw)
        except http.cookies.CookieError:
            return None
        m = jar.get(COOKIE_NAME)
        return m.value if m else None

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (ValueError, UnicodeDecodeError):
            return {}

    def log_message(self, fmt, *args):  # quieter logging
        pass

    # --- routing ---
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/me":
            return self.handle_me()
        if path == "/api/health":
            return self._send_json(200, {"ok": True})
        return self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/signup":
            return self.handle_signup()
        if path == "/api/login":
            return self.handle_login()
        if path == "/api/logout":
            return self.handle_logout()
        if path == "/api/record":
            return self.handle_record()
        return self._send_json(404, {"error": "Not found"})

    # --- endpoints ---
    def handle_signup(self):
        data = self._read_json()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if not username:
            return self._send_json(400, {"error": "Please choose a username."})
        if len(username) > 32:
            return self._send_json(400, {"error": "Username must be 32 characters or fewer."})
        if len(password) < 4:
            return self._send_json(400, {"error": "Password must be at least 4 characters."})
        with db() as conn:
            exists = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
            if exists:
                return self._send_json(409, {"error": "That username is already taken."})
            uid = create_user(conn, username, password)
            token = new_session(conn, uid)
            stats = stats_for_user(conn, uid)
        return self._send_json(200, {"user": username, "stats": stats}, set_cookie=token)

    def handle_login(self):
        data = self._read_json()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        with db() as conn:
            uid = verify_user(conn, username, password)
            if not uid:
                return self._send_json(401, {"error": "Incorrect username or password."})
            token = new_session(conn, uid)
            stats = stats_for_user(conn, uid)
        return self._send_json(200, {"user": username, "stats": stats}, set_cookie=token)

    def handle_logout(self):
        token = self._cookie_token()
        if token:
            with db() as conn:
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        return self._send_json(200, {"user": None}, clear_cookie=True)

    def handle_me(self):
        with db() as conn:
            row = user_for_token(conn, self._cookie_token())
            if not row:
                return self._send_json(200, {"user": None, "stats": None})
            stats = stats_for_user(conn, row["id"])
        return self._send_json(200, {"user": row["username"], "stats": stats})

    def handle_record(self):
        data = self._read_json()
        game = data.get("game")
        outcome = data.get("outcome")
        if game not in GAME_KEYS or outcome not in VALID_OUTCOMES:
            return self._send_json(400, {"error": "Invalid game or outcome."})
        with db() as conn:
            row = user_for_token(conn, self._cookie_token())
            if not row:
                return self._send_json(401, {"error": "Not signed in."})
            conn.execute(
                "INSERT INTO results (user_id, game, outcome, ts) VALUES (?,?,?,?)",
                (row["id"], game, outcome, time.time()),
            )
            stats = stats_for_user(conn, row["id"])
        return self._send_json(200, {"stats": stats})


def main():
    init_db()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print("Evan-pi API listening on http://%s:%d  (db=%s, secure_cookie=%s)"
          % (HOST, PORT, DB_PATH, SECURE_COOKIE))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
