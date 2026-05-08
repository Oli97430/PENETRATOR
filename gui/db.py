"""SQLite persistence for PENETRATOR findings, sessions, and scope.

Designed to be lightweight — uses only the stdlib ``sqlite3`` module.
All functions are safe to call from any thread (a new connection is created
per call).  The DB file defaults to ``data/penetrator.db`` next to the
project root.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

_DB_PATH: Path | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    target     TEXT    DEFAULT '',
    started    TEXT    NOT NULL,
    ended      TEXT    DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER DEFAULT 0,
    timestamp   TEXT    NOT NULL,
    tool        TEXT    NOT NULL,
    target      TEXT    DEFAULT '',
    severity    TEXT    DEFAULT 'info',
    cvss_score  REAL    DEFAULT 0.0,
    cvss_vector TEXT    DEFAULT '',
    data_json   TEXT    DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS scope (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_pattern TEXT NOT NULL UNIQUE,
    in_scope       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


def _db_path() -> Path:
    if _DB_PATH is not None:
        return _DB_PATH
    return Path(__file__).resolve().parent.parent / "data" / "penetrator.db"


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ------------------------------------------------------------------
# Initialisation
# ------------------------------------------------------------------

def init_db(path: str | Path | None = None) -> Path:
    """Create the database file + tables if they don't exist.
    Returns the resolved path."""
    global _DB_PATH
    if path is not None:
        _DB_PATH = Path(path)
    db = _db_path()
    conn = _connect()
    conn.executescript(SCHEMA)
    conn.close()
    return db


# ------------------------------------------------------------------
# Sessions
# ------------------------------------------------------------------

def create_session(name: str, target: str = "") -> int:
    conn = _connect()
    cur = conn.execute(
        "INSERT INTO sessions (name, target, started) VALUES (?, ?, ?)",
        (name, target, time.strftime("%Y-%m-%dT%H:%M:%S")),
    )
    conn.commit()
    sid = cur.lastrowid
    conn.close()
    return sid  # type: ignore[return-value]


def end_session(session_id: int) -> None:
    conn = _connect()
    conn.execute(
        "UPDATE sessions SET ended = ? WHERE id = ?",
        (time.strftime("%Y-%m-%dT%H:%M:%S"), session_id),
    )
    conn.commit()
    conn.close()


def list_sessions(limit: int = 50) -> list[dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------
# Findings
# ------------------------------------------------------------------

def store_finding(
    tool: str,
    target: str = "",
    severity: str = "info",
    data: Any = None,
    cvss_score: float = 0.0,
    cvss_vector: str = "",
    session_id: int = 0,
) -> int:
    conn = _connect()
    cur = conn.execute(
        "INSERT INTO findings (session_id, timestamp, tool, target, severity, "
        "cvss_score, cvss_vector, data_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            session_id,
            time.strftime("%Y-%m-%dT%H:%M:%S"),
            tool,
            target,
            severity,
            cvss_score,
            cvss_vector,
            json.dumps(data, default=str) if data is not None else "{}",
        ),
    )
    conn.commit()
    fid = cur.lastrowid
    conn.close()
    return fid  # type: ignore[return-value]


def query_findings(
    tool: str | None = None,
    target: str | None = None,
    severity: str | None = None,
    session_id: int | None = None,
    limit: int = 200,
) -> list[dict]:
    clauses: list[str] = []
    params: list[Any] = []
    if tool:
        clauses.append("tool = ?")
        params.append(tool)
    if target:
        clauses.append("target LIKE ?")
        params.append(f"%{target}%")
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if session_id is not None:
        clauses.append("session_id = ?")
        params.append(session_id)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = _connect()
    rows = conn.execute(
        f"SELECT * FROM findings{where} ORDER BY id DESC LIMIT ?",
        (*params, limit),
    ).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        try:
            d["data"] = json.loads(d.pop("data_json", "{}"))
        except (json.JSONDecodeError, TypeError):
            d["data"] = {}
        results.append(d)
    return results


def delete_findings(session_id: int | None = None) -> int:
    conn = _connect()
    if session_id is not None:
        cur = conn.execute("DELETE FROM findings WHERE session_id = ?", (session_id,))
    else:
        cur = conn.execute("DELETE FROM findings")
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count


# ------------------------------------------------------------------
# Scope
# ------------------------------------------------------------------

def add_scope(target_pattern: str, in_scope: bool = True) -> None:
    conn = _connect()
    conn.execute(
        "INSERT OR REPLACE INTO scope (target_pattern, in_scope) VALUES (?, ?)",
        (target_pattern, 1 if in_scope else 0),
    )
    conn.commit()
    conn.close()


def remove_scope(target_pattern: str) -> None:
    conn = _connect()
    conn.execute("DELETE FROM scope WHERE target_pattern = ?", (target_pattern,))
    conn.commit()
    conn.close()


def get_scope() -> list[dict]:
    conn = _connect()
    rows = conn.execute("SELECT * FROM scope ORDER BY id").fetchall()
    conn.close()
    return [{"pattern": r["target_pattern"], "in_scope": bool(r["in_scope"])} for r in rows]


def check_scope(target: str) -> bool | None:
    """Check if *target* is in scope.  Returns True/False or None if no
    scope rules exist (= everything allowed)."""
    import fnmatch
    scope = get_scope()
    if not scope:
        return None
    for rule in scope:
        if fnmatch.fnmatch(target, rule["pattern"]) or target == rule["pattern"]:
            return rule["in_scope"]
        # Also check if the pattern is a substring
        if rule["pattern"] in target:
            return rule["in_scope"]
    return False  # No matching rule → out of scope
