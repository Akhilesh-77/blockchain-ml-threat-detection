"""
Database management module for SQLite persistence of traffic sessions and blockchain audit ledger.
"""

import json
from pathlib import Path
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import DB_PATH


class DatabaseManager:
    """Manages SQLite persistent storage for sessions and blockchain blocks."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Create a connection with row factory enabled."""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initialize required database tables."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Table for Blockchain Audit Ledger
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blockchain_blocks (
                    index_num INTEGER PRIMARY KEY,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    metadata_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL,
                    nonce INTEGER NOT NULL,
                    status TEXT DEFAULT 'VALID'
                )
            """)

            # Table for Network Traffic Sessions
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_sessions (
                    session_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    src_ip_hash TEXT NOT NULL,
                    dst_ip_hash TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    features_json TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    audited INTEGER DEFAULT 0,
                    block_index INTEGER
                )
            """)

            # Table for Audit Log Trail
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL
                )
            """)

            conn.commit()

    # --- Blockchain Block Operations ---

    def insert_block(self, block: Dict[str, Any]) -> None:
        """Insert a newly mined block into the ledger."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO blockchain_blocks (
                    index_num, event_id, timestamp, prediction,
                    confidence, metadata_json, prev_hash, current_hash, nonce, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                block["index_num"],
                block["event_id"],
                block["timestamp"],
                block["prediction"],
                float(block["confidence"]),
                json.dumps(block["metadata_json"]) if isinstance(block["metadata_json"], dict) else str(block["metadata_json"]),
                block["prev_hash"],
                block["current_hash"],
                int(block.get("nonce", 0)),
                block.get("status", "VALID")
            ))
            conn.commit()

    def get_latest_block(self) -> Optional[Dict[str, Any]]:
        """Retrieve the latest block in the ledger."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM blockchain_blocks ORDER BY index_num DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                d = dict(row)
                d["metadata_json"] = json.loads(d["metadata_json"])
                return d
            return None

    def get_all_blocks(self) -> List[Dict[str, Any]]:
        """Retrieve all blocks in sequential index order."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM blockchain_blocks ORDER BY index_num ASC")
            rows = cursor.fetchall()
            blocks = []
            for row in rows:
                d = dict(row)
                try:
                    d["metadata_json"] = json.loads(d["metadata_json"])
                except Exception:
                    pass
                blocks.append(d)
            return blocks

    def get_block_count(self) -> int:
        """Get the total number of blocks in the ledger."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM blockchain_blocks")
            return cursor.fetchone()[0]

    def tamper_block_for_testing(self, index_num: int, modified_prediction: str) -> bool:
        """
        Deliberately alter an audit record in the database WITHOUT updating its cryptographic hash.
        This provides a legitimate simulation mechanism to demonstrate tamper detection in the SOC.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE blockchain_blocks
                SET prediction = ?
                WHERE index_num = ?
            """, (modified_prediction, index_num))
            affected = cursor.rowcount > 0
            if affected:
                cursor.execute("""
                    INSERT INTO audit_logs (timestamp, event_type, message)
                    VALUES (?, ?, ?)
                """, (
                    datetime.now(timezone.utc).isoformat(),
                    "TAMPER_SIMULATION",
                    f"Block #{index_num} prediction altered to '{modified_prediction}' for audit testing."
                ))
            conn.commit()
            return affected

    def repair_block(self, index_num: int, correct_prediction: str) -> bool:
        """Restore an altered block back to its authentic prediction."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE blockchain_blocks
                SET prediction = ?
                WHERE index_num = ?
            """, (correct_prediction, index_num))
            affected = cursor.rowcount > 0
            if affected:
                cursor.execute("""
                    INSERT INTO audit_logs (timestamp, event_type, message)
                    VALUES (?, ?, ?)
                """, (
                    datetime.now(timezone.utc).isoformat(),
                    "TAMPER_REPAIR",
                    f"Block #{index_num} restored to '{correct_prediction}'."
                ))
            conn.commit()
            return affected

    def clear_blockchain(self) -> None:
        """Reset the blockchain ledger (used for reset/testing)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blockchain_blocks")
            cursor.execute("UPDATE traffic_sessions SET audited = 0, block_index = NULL")
            cursor.execute("""
                INSERT INTO audit_logs (timestamp, event_type, message)
                VALUES (?, ?, ?)
            """, (datetime.now(timezone.utc).isoformat(), "BLOCKCHAIN_RESET", "Ledger cleared and session audit links reset."))
            conn.commit()

    # --- Traffic Session Operations ---

    def insert_session(self, session: Dict[str, Any]) -> None:
        """Insert or replace a traffic session."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO traffic_sessions (
                    session_id, timestamp, src_ip_hash, dst_ip_hash,
                    dst_port, protocol, features_json, prediction, confidence, audited, block_index
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session["session_id"],
                session["timestamp"],
                session["src_ip_hash"],
                session["dst_ip_hash"],
                int(session.get("dst_port", 443)),
                session.get("protocol", "TCP/TLS"),
                json.dumps(session["features"]),
                session["prediction"],
                float(session["confidence"]),
                int(session.get("audited", 0)),
                session.get("block_index")
            ))
            conn.commit()

    def insert_sessions_batch(self, sessions: List[Dict[str, Any]]) -> None:
        """Insert multiple sessions in a single transaction."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            data = [
                (
                    s["session_id"],
                    s["timestamp"],
                    s["src_ip_hash"],
                    s["dst_ip_hash"],
                    int(s.get("dst_port", 443)),
                    s.get("protocol", "TCP/TLS"),
                    json.dumps(s["features"]),
                    s["prediction"],
                    float(s["confidence"]),
                    int(s.get("audited", 0)),
                    s.get("block_index")
                )
                for s in sessions
            ]
            cursor.executemany("""
                INSERT OR REPLACE INTO traffic_sessions (
                    session_id, timestamp, src_ip_hash, dst_ip_hash,
                    dst_port, protocol, features_json, prediction, confidence, audited, block_index
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, data)
            conn.commit()

    def get_all_sessions(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieve sessions with optional limit."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM traffic_sessions ORDER BY timestamp DESC"
            if limit:
                query += f" LIMIT {int(limit)}"
            cursor.execute(query)
            rows = cursor.fetchall()
            sessions = []
            for row in rows:
                d = dict(row)
                try:
                    d["features"] = json.loads(d["features_json"])
                except Exception:
                    d["features"] = {}
                sessions.append(d)
            return sessions

    def get_session_stats(self) -> Dict[str, Any]:
        """Compute aggregated traffic statistics directly from the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM traffic_sessions")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM traffic_sessions WHERE prediction = 'Normal'")
            normal = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM traffic_sessions WHERE prediction = 'Suspicious'")
            suspicious = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM traffic_sessions WHERE prediction = 'Malicious'")
            malicious = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM traffic_sessions WHERE audited = 1")
            audited = cursor.fetchone()[0]

            threat_count = suspicious + malicious
            threat_pct = (threat_count / total * 100.0) if total > 0 else 0.0

            return {
                "total_sessions": total,
                "normal_sessions": normal,
                "suspicious_sessions": suspicious,
                "malicious_sessions": malicious,
                "threat_sessions": threat_count,
                "threat_pct": round(threat_pct, 2),
                "audited_sessions": audited
            }

    def mark_session_audited(self, session_id: str, block_index: int) -> None:
        """Mark a session as audited and link it to its ledger block."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE traffic_sessions
                SET audited = 1, block_index = ?
                WHERE session_id = ?
            """, (block_index, session_id))
            conn.commit()

    # --- System Logs ---

    def log_event(self, event_type: str, message: str) -> None:
        """Record an audit log entry."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (timestamp, event_type, message)
                VALUES (?, ?, ?)
            """, (datetime.now(timezone.utc).isoformat(), event_type, message))
            conn.commit()

    def get_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent system audit logs."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT ?", (limit,))
            return [dict(r) for r in cursor.fetchall()]


# Singleton instance
_db_instance: Optional[DatabaseManager] = None


def get_db() -> DatabaseManager:
    """Retrieve or initialize the singleton database manager."""
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseManager()
    return _db_instance
