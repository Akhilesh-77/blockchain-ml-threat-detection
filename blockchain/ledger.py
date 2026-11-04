"""
Blockchain Ledger module for cryptographic, tamper-evident audit records of ML threat detections.
"""

import hashlib
import json
from pathlib import Path
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import BLOCKCHAIN_DIFFICULTY, GENESIS_PREV_HASH
from database.db import DatabaseManager, get_db


class AuditBlock:
    """Represents a single cryptographic audit block in the hash-chain."""

    def __init__(
        self,
        index_num: int,
        event_id: str,
        timestamp: str,
        prediction: str,
        confidence: float,
        metadata_json: Dict[str, Any],
        prev_hash: str,
        current_hash: Optional[str] = None,
        nonce: int = 0,
        status: str = "VALID"
    ):
        self.index_num = index_num
        self.event_id = event_id
        self.timestamp = timestamp
        self.prediction = prediction
        self.confidence = float(confidence)
        self.metadata_json = metadata_json if isinstance(metadata_json, dict) else {}
        self.prev_hash = prev_hash
        self.nonce = nonce
        self.status = status
        self.current_hash = current_hash or self.calculate_hash()

    def serialize_payload(self) -> str:
        """Create a deterministic payload string for cryptographic hashing."""
        clean_metadata = json.dumps(self.metadata_json, sort_keys=True, separators=(',', ':'))
        return (
            f"{self.index_num}|"
            f"{self.prev_hash}|"
            f"{self.timestamp}|"
            f"{self.event_id}|"
            f"{self.prediction}|"
            f"{self.confidence:.4f}|"
            f"{clean_metadata}|"
            f"{self.nonce}"
        )

    def calculate_hash(self) -> str:
        """Compute SHA-256 cryptographic digest of the block's canonical payload."""
        payload = self.serialize_payload()
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def mine_block(self, difficulty: int = BLOCKCHAIN_DIFFICULTY) -> None:
        """
        Proof-of-work mechanism: Finds a nonce where the SHA-256 hash
        starts with 'difficulty' number of leading zeros.
        """
        target_prefix = "0" * difficulty
        while not self.current_hash.startswith(target_prefix):
            self.nonce += 1
            self.current_hash = self.calculate_hash()

    def to_dict(self) -> Dict[str, Any]:
        """Convert block instance to dictionary format."""
        return {
            "index_num": self.index_num,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "prediction": self.prediction,
            "confidence": round(self.confidence, 4),
            "metadata_json": self.metadata_json,
            "prev_hash": self.prev_hash,
            "current_hash": self.current_hash,
            "nonce": self.nonce,
            "status": self.status
        }


class BlockchainLedger:
    """
    Manages the local SHA-256 hash-chain audit ledger.
    Note: This is a local tamper-evident cryptographic hash-chain ledger designed
    for immutable SOC forensics, not a public decentralized cryptocurrency network.
    """

    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or get_db()
        self._ensure_genesis_block()

    def _ensure_genesis_block(self) -> None:
        """Verify existence of Genesis block (index 0); create if ledger is empty."""
        latest = self.db.get_latest_block()
        if latest is None:
            genesis = AuditBlock(
                index_num=0,
                event_id="GENESIS-0000-0000-0000-000000000000",
                timestamp="2026-01-01T00:00:00Z",
                prediction="SYSTEM_INIT",
                confidence=1.0,
                metadata_json={
                    "system": "Blockchain-Audited ML Threat Detection",
                    "version": "2.0.0",
                    "hash_algorithm": "SHA-256",
                    "encryption_policy": "Zero-Payload Decryption"
                },
                prev_hash=GENESIS_PREV_HASH,
                nonce=0
            )
            genesis.mine_block(difficulty=BLOCKCHAIN_DIFFICULTY)
            self.db.insert_block(genesis.to_dict())
            self.db.log_event("GENESIS_CREATED", f"Genesis block initialized with hash {genesis.current_hash[:16]}...")

    def create_detection_record(
        self,
        prediction: str,
        confidence: float,
        metadata_summary: Dict[str, Any],
        event_id: Optional[str] = None
    ) -> AuditBlock:
        """
        Create, mine, and persistently commit a new audit block for an ML classification event.
        """
        latest = self.db.get_latest_block()
        if latest is None:
            self._ensure_genesis_block()
            latest = self.db.get_latest_block()

        next_index = latest["index_num"] + 1
        prev_hash = latest["current_hash"]
        event_id = event_id or f"EVT-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Sanitize metadata to exclude PII or raw payload content
        sanitized_metadata = {
            "flow_duration_s": round(float(metadata_summary.get("flow_duration", 0)), 4),
            "total_packets": int(metadata_summary.get("total_fwd_packets", 0) + metadata_summary.get("total_bwd_packets", 0)),
            "total_bytes": int(metadata_summary.get("total_fwd_bytes", 0) + metadata_summary.get("total_bwd_bytes", 0)),
            "dst_port": int(metadata_summary.get("dst_port", 443)),
            "protocol": str(metadata_summary.get("protocol", "TCP/TLS")),
            "flow_byte_rate": round(float(metadata_summary.get("flow_bytes_per_sec", 0)), 2),
            "flow_packet_rate": round(float(metadata_summary.get("flow_packets_per_sec", 0)), 2),
        }

        block = AuditBlock(
            index_num=next_index,
            event_id=event_id,
            timestamp=timestamp,
            prediction=prediction,
            confidence=confidence,
            metadata_json=sanitized_metadata,
            prev_hash=prev_hash
        )

        block.mine_block(difficulty=BLOCKCHAIN_DIFFICULTY)
        self.db.insert_block(block.to_dict())
        self.db.log_event(
            "BLOCK_COMMITTED",
            f"Block #{block.index_num} [{block.prediction}] committed with hash {block.current_hash[:16]}..."
        )
        return block

    def get_chain(self) -> List[AuditBlock]:
        """Fetch all blocks from the persistent database."""
        raw_blocks = self.db.get_all_blocks()
        blocks = []
        for b in raw_blocks:
            blocks.append(
                AuditBlock(
                    index_num=b["index_num"],
                    event_id=b["event_id"],
                    timestamp=b["timestamp"],
                    prediction=b["prediction"],
                    confidence=b["confidence"],
                    metadata_json=b["metadata_json"],
                    prev_hash=b["prev_hash"],
                    current_hash=b["current_hash"],
                    nonce=b["nonce"],
                    status=b.get("status", "VALID")
                )
            )
        return blocks

    def get_latest_block(self) -> Optional[AuditBlock]:
        """Get the most recent block in the ledger."""
        raw = self.db.get_latest_block()
        if raw:
            return AuditBlock(
                index_num=raw["index_num"],
                event_id=raw["event_id"],
                timestamp=raw["timestamp"],
                prediction=raw["prediction"],
                confidence=raw["confidence"],
                metadata_json=raw["metadata_json"],
                prev_hash=raw["prev_hash"],
                current_hash=raw["current_hash"],
                nonce=raw["nonce"],
                status=raw.get("status", "VALID")
            )
        return None


# Singleton instance
_ledger_instance: Optional[BlockchainLedger] = None


def get_ledger() -> BlockchainLedger:
    """Retrieve or initialize the singleton BlockchainLedger."""
    global _ledger_instance
    if _ledger_instance is None:
        _ledger_instance = BlockchainLedger()
    return _ledger_instance
