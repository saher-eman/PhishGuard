import json
import os
import re
import sqlite3
import subprocess
from collections import Counter
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(
    BASE_DIR, "..", "engine", "analyzer.exe" if os.name == "nt" else "analyzer"
)
DB_PATH = os.path.join(BASE_DIR, "phishguard.db")

# Basic URL check: http/https se shuru, koi space nahi
URL_RE = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.IGNORECASE)
MAX_URL_LEN = 2048

app = Flask(__name__, static_folder="static")
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])


# ---------------- Database ----------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                indicators TEXT NOT NULL,
                features TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )"""
        )


def row_to_dict(row):
    return {
        "id": row["id"],
        "url": row["url"],
        "risk": row["risk_level"],
        "indicators": json.loads(row["indicators"]),
        "features": json.loads(row["features"]),
        "timestamp": row["timestamp"],
    }


def error(message, code):
    return jsonify({"error": message}), code


# ---------------- Routes ----------------
@app.get("/")
def home():
    return send_from_directory(app.static_folder, "index.html")


@app.post("/analyze")
@limiter.limit("20 per minute")
def analyze():
    # --- Step 8: validation ---
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("Request body must be JSON", 400)
    url = data.get("url")
    if not isinstance(url, str):
        return error("'url' must be a string", 400)
    url = url.strip()
    if not url:
        return error("URL cannot be empty", 400)
    if len(url) > MAX_URL_LEN:
        return error("URL too long", 400)
    if not URL_RE.match(url):
        return error("Invalid URL format (must start with http:// or https://)", 400)

    # --- Step 9: C++ engine call (shell=True kabhi nahi) ---
    try:
        proc = subprocess.run(
            [ENGINE, url], capture_output=True, text=True, timeout=5
        )
        if proc.returncode != 0:
            raise RuntimeError("engine failed")
        result = json.loads(proc.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError,
            RuntimeError, json.JSONDecodeError):
        return error("Analysis engine unavailable", 500)

    # --- Step 13: DB mein save ---
    try:
        with get_db() as db:
            cur = db.execute(
                "INSERT INTO analysis (url, risk_level, indicators, features, timestamp)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    url,
                    result["risk"],
                    json.dumps(result["indicators"]),
                    json.dumps(result["features"]),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            result["id"] = cur.lastrowid
    except (sqlite3.Error, KeyError):
        return error("Could not save analysis", 500)

    result["url"] = url
    return jsonify(result)


@app.get("/history")
def history():
    try:
        limit = min(max(int(request.args.get("limit", 20)), 1), 100)
    except ValueError:
        return error("limit must be a number", 400)
    try:
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM analysis ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    except sqlite3.Error:
        return error("Database unavailable", 500)
    return jsonify([row_to_dict(r) for r in rows])


@app.get("/analysis/<int:analysis_id>")
def analysis_detail(analysis_id):
    try:
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM analysis WHERE id = ?", (analysis_id,)
            ).fetchone()
    except sqlite3.Error:
        return error("Database unavailable", 500)
    if row is None:
        return error("Analysis not found", 404)
    return jsonify(row_to_dict(row))


@app.get("/stats")   # Step 24: dashboard ke liye
def stats():
    try:
        with get_db() as db:
            rows = db.execute("SELECT risk_level, indicators FROM analysis").fetchall()
    except sqlite3.Error:
        return error("Database unavailable", 500)
    risk_counts = Counter(r["risk_level"] for r in rows)
    ind_counts = Counter()
    for r in rows:
        ind_counts.update(json.loads(r["indicators"]))
    return jsonify({
        "total": len(rows),
        "risk_distribution": dict(risk_counts),
        "common_indicators": ind_counts.most_common(5),
    })


@app.errorhandler(429)
def too_many(_e):
    return error("Too many requests, slow down", 429)


@app.errorhandler(500)
def server_error(_e):
    return error("Internal server error", 500)


init_db()

if __name__ == "__main__":
    app.run(debug=False)
