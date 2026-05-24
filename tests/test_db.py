"""Tests for the PENETRATOR SQLite database layer (gui/db.py)."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from gui import db


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    """Each test gets a fresh database in a temp directory."""
    db_path = tmp_path / "test.db"
    db.init_db(db_path)
    yield db_path


# ---------------------------------------------------------------------------
# Schema & initialization
# ---------------------------------------------------------------------------
class TestInit:
    def test_creates_tables(self, fresh_db):
        import sqlite3
        conn = sqlite3.connect(str(fresh_db))
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        names = {t[0] for t in tables}
        assert "sessions" in names
        assert "findings" in names
        assert "scope" in names
        conn.close()

    def test_wal_mode(self, fresh_db):
        import sqlite3
        conn = sqlite3.connect(str(fresh_db))
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        conn.close()

    def test_idempotent(self, fresh_db):
        """Calling init_db twice doesn't fail."""
        db.init_db(fresh_db)  # Second call


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
class TestSessions:
    def test_create_and_list(self):
        sid = db.create_session("test-scan", target="example.com")
        assert sid > 0
        sessions = db.list_sessions()
        assert len(sessions) >= 1
        last = sessions[0]
        assert last["name"] == "test-scan"
        assert last["target"] == "example.com"
        assert last["started"] != ""

    def test_end_session(self):
        sid = db.create_session("ending", target="x.com")
        db.end_session(sid)
        sessions = db.list_sessions()
        found = next(s for s in sessions if s["id"] == sid)
        assert found["ended"] != ""

    def test_list_limit(self):
        for i in range(5):
            db.create_session(f"s{i}")
        result = db.list_sessions(limit=3)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
class TestFindings:
    def test_store_and_query(self):
        fid = db.store_finding(
            tool="port_scan",
            target="10.0.0.1",
            severity="high",
            data={"ports": [80, 443]},
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
        assert fid > 0
        results = db.query_findings(tool="port_scan")
        assert len(results) >= 1
        f = results[0]
        assert f["target"] == "10.0.0.1"
        assert f["severity"] == "high"
        assert f["data"]["ports"] == [80, 443]

    def test_query_by_severity(self):
        db.store_finding(tool="a", severity="critical")
        db.store_finding(tool="b", severity="info")
        critical = db.query_findings(severity="critical")
        assert all(f["severity"] == "critical" for f in critical)

    def test_query_by_target(self):
        db.store_finding(tool="x", target="sub.example.com")
        db.store_finding(tool="x", target="other.net")
        results = db.query_findings(target="example")
        assert len(results) == 1
        assert "example" in results[0]["target"]

    def test_query_by_session_id(self):
        sid = db.create_session("sess1")
        db.store_finding(tool="t", session_id=sid)
        db.store_finding(tool="t", session_id=0)
        results = db.query_findings(session_id=sid)
        assert len(results) == 1

    def test_delete_findings_by_session(self):
        sid = db.create_session("del_test")
        db.store_finding(tool="a", session_id=sid)
        db.store_finding(tool="b", session_id=sid)
        db.store_finding(tool="c", session_id=0)
        deleted = db.delete_findings(session_id=sid)
        assert deleted == 2
        # Others remain
        assert len(db.query_findings(session_id=0)) >= 1

    def test_delete_all_findings(self):
        db.store_finding(tool="x")
        db.store_finding(tool="y")
        deleted = db.delete_findings()
        assert deleted >= 2
        assert db.query_findings() == []

    def test_store_none_data(self):
        fid = db.store_finding(tool="t", data=None)
        results = db.query_findings(tool="t")
        assert results[0]["data"] == {}


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------
class TestScope:
    def test_add_and_get(self):
        db.add_scope("*.example.com", in_scope=True)
        scope = db.get_scope()
        assert any(s["pattern"] == "*.example.com" for s in scope)

    def test_remove_scope(self):
        db.add_scope("remove.me")
        db.remove_scope("remove.me")
        scope = db.get_scope()
        assert not any(s["pattern"] == "remove.me" for s in scope)

    def test_check_scope_no_rules(self, tmp_path):
        """No rules → None (everything allowed)."""
        fresh = tmp_path / "empty.db"
        db.init_db(fresh)
        assert db.check_scope("anything.com") is None

    def test_check_scope_exact_match(self):
        db.add_scope("target.com", in_scope=True)
        assert db.check_scope("target.com") is True

    def test_check_scope_subdomain(self):
        db.add_scope("*.example.com", in_scope=True)
        assert db.check_scope("sub.example.com") is True
        # But NOT "notexample.com"
        assert db.check_scope("notexample.com") is False

    def test_check_scope_out_of_scope(self):
        db.add_scope("blocked.com", in_scope=False)
        assert db.check_scope("blocked.com") is False

    def test_upsert_scope(self):
        """Adding the same pattern updates instead of duplicating."""
        db.add_scope("x.com", in_scope=True)
        db.add_scope("x.com", in_scope=False)
        scope = db.get_scope()
        x_rules = [s for s in scope if s["pattern"] == "x.com"]
        assert len(x_rules) == 1
        assert x_rules[0]["in_scope"] is False
