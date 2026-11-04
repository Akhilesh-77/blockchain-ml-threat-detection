"""
Unit tests for SQLite database manager.
"""

import pytest
from database.db import DatabaseManager


@pytest.fixture
def temp_db(tmp_path):
    """Create an isolated SQLite database using pytest's tmp_path."""
    db_file = tmp_path / "test_ledger.db"
    db = DatabaseManager(db_path=db_file)
    return db


def test_db_initialization(temp_db):
    """Ensure database tables are initialized properly."""
    with temp_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row["name"] for row in cursor.fetchall()]
        assert "blockchain_blocks" in tables
        assert "traffic_sessions" in tables
        assert "audit_logs" in tables


def test_insert_and_get_block(temp_db):
    """Test block insertion and retrieval."""
    block = {
        "index_num": 1,
        "event_id": "EVT-TEST-001",
        "timestamp": "2026-11-04T12:00:00Z",
        "prediction": "Normal",
        "confidence": 0.985,
        "metadata_json": {"flow_duration": 1.2, "dst_port": 443},
        "prev_hash": "0" * 64,
        "current_hash": "abcdef1234567890" * 4,
        "nonce": 42,
        "status": "VALID"
    }
    temp_db.insert_block(block)
    assert temp_db.get_block_count() == 1

    latest = temp_db.get_latest_block()
    assert latest is not None
    assert latest["index_num"] == 1
    assert latest["event_id"] == "EVT-TEST-001"
    assert latest["prediction"] == "Normal"
    assert latest["metadata_json"]["dst_port"] == 443


def test_session_batch_and_stats(temp_db):
    """Test session batch insertion and calculated SOC statistics."""
    sessions = [
        {
            "session_id": f"SES-00{i}",
            "timestamp": "2026-11-04T12:00:00Z",
            "src_ip_hash": "IP-AAAA1111",
            "dst_ip_hash": "IP-BBBB2222",
            "dst_port": 443,
            "protocol": "TCP/TLS",
            "features": {"flow_duration": 2.0},
            "prediction": "Normal" if i < 3 else "Malicious",
            "confidence": 0.95,
            "audited": 1 if i == 0 else 0,
            "block_index": 1 if i == 0 else None
        }
        for i in range(5)
    ]
    temp_db.insert_sessions_batch(sessions)

    stats = temp_db.get_session_stats()
    assert stats["total_sessions"] == 5
    assert stats["normal_sessions"] == 3
    assert stats["malicious_sessions"] == 2
    assert stats["suspicious_sessions"] == 0
    assert stats["threat_sessions"] == 2
    assert stats["threat_pct"] == 40.0
    assert stats["audited_sessions"] == 1


def test_tamper_simulation_and_repair(temp_db):
    """Test deliberate database tampering simulation and subsequent repair."""
    block = {
        "index_num": 1,
        "event_id": "EVT-TEST-002",
        "timestamp": "2026-11-04T12:00:00Z",
        "prediction": "Malicious",
        "confidence": 0.99,
        "metadata_json": {"flow_duration": 5.0},
        "prev_hash": "0" * 64,
        "current_hash": "1122334455667788" * 4,
        "nonce": 10,
        "status": "VALID"
    }
    temp_db.insert_block(block)

    # Simulate unauthorized tampering
    tampered = temp_db.tamper_block_for_testing(1, "Normal")
    assert tampered is True

    altered_block = temp_db.get_latest_block()
    assert altered_block["prediction"] == "Normal"

    # Repair block
    repaired = temp_db.repair_block(1, "Malicious")
    assert repaired is True
    restored_block = temp_db.get_latest_block()
    assert restored_block["prediction"] == "Malicious"
