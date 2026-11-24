"""
CyberNex Blockchain Audit Ledger Service.
Provides persistent SHA-256 hash-chaining, canonical payload serialization,
Proof-of-Work mining, cryptographic integrity verification, and safe isolated tamper testing.
"""

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.config import BLOCKCHAIN_DIFFICULTY, GENESIS_PREV_HASH
from backend.models import AuditBlock


class BlockchainService:
    def __init__(self, difficulty: int = BLOCKCHAIN_DIFFICULTY):
        self.difficulty = difficulty

    @staticmethod
    def serialize_payload(
        block_index: int,
        prev_hash: str,
        timestamp_str: str,
        record_id: str,
        event_type: str,
        payload_dict: Dict[str, Any],
        nonce: int
    ) -> str:
        """Deterministic canonical string serialization for SHA-256 digest calculation."""
        canonical_json = json.dumps(payload_dict, sort_keys=True, separators=(',', ':'))
        return f"{block_index}|{prev_hash}|{timestamp_str}|{record_id}|{event_type}|{canonical_json}|{nonce}"

    @classmethod
    def calculate_hash(
        cls,
        block_index: int,
        prev_hash: str,
        timestamp_str: str,
        record_id: str,
        event_type: str,
        payload_dict: Dict[str, Any],
        nonce: int
    ) -> str:
        """Compute SHA-256 cryptographic digest of canonical serialized payload."""
        pre_image = cls.serialize_payload(
            block_index, prev_hash, timestamp_str, record_id, event_type, payload_dict, nonce
        )
        return hashlib.sha256(pre_image.encode("utf-8")).hexdigest()

    def mine_block(
        self,
        block_index: int,
        prev_hash: str,
        timestamp_str: str,
        record_id: str,
        event_type: str,
        payload_dict: Dict[str, Any]
    ) -> Tuple[str, int]:
        """Mine block nonce until hash satisfies Proof-of-Work difficulty prefix."""
        target_prefix = "0" * self.difficulty
        nonce = 0
        while True:
            cur_hash = self.calculate_hash(
                block_index, prev_hash, timestamp_str, record_id, event_type, payload_dict, nonce
            )
            if cur_hash.startswith(target_prefix):
                return cur_hash, nonce
            nonce += 1

    def ensure_genesis_block(self, db: Session) -> AuditBlock:
        """Ensure the Genesis block exists at index 0."""
        latest = db.query(AuditBlock).filter(AuditBlock.block_index == 0).first()
        if latest is not None:
            return latest

        record_id = "GENESIS-0000-0000-0000-000000000000"
        ts_str = "2026-01-01T00:00:00Z"
        event_type = "GENESIS_ROOT"
        payload = {
            "system": "CyberNex Security Platform",
            "version": "2.0.0",
            "hash_algorithm": "SHA-256",
            "ledger_type": "Tamper-Evident Hash-Chain",
            "policy": "Zero-Payload Decryption & Authorized Simulation"
        }

        cur_hash, nonce = self.mine_block(0, GENESIS_PREV_HASH, ts_str, record_id, event_type, payload)

        genesis = AuditBlock(
            block_index=0,
            record_id=record_id,
            timestamp=ts_str,
            event_type=event_type,
            description="CyberNex Ledger Root Genesis Block Initialized",
            device_id=None,
            incident_id=None,
            prev_hash=GENESIS_PREV_HASH,
            current_hash=cur_hash,
            nonce=nonce,
            payload_json=json.dumps(payload),
            status="VALID",
            data_source="GENESIS"
        )
        db.add(genesis)
        db.commit()
        db.refresh(genesis)
        return genesis

    def record_event(
        self,
        db: Session,
        event_type: str,
        description: str,
        payload: Dict[str, Any],
        device_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        data_source: str = "SIMULATION_ENGINE"
    ) -> AuditBlock:
        """Create, mine, and commit a new cryptographic block to the hash-chain."""
        self.ensure_genesis_block(db)
        latest = db.query(AuditBlock).order_by(AuditBlock.block_index.desc()).first()

        next_index = (latest.block_index + 1) if latest else 0
        prev_hash = latest.current_hash if latest else GENESIS_PREV_HASH
        record_id = f"REC-{uuid.uuid4().hex[:12].upper()}"
        ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Sanitize and serialize payload
        cur_hash, nonce = self.mine_block(
            next_index, prev_hash, ts_str, record_id, event_type, payload
        )

        block = AuditBlock(
            block_index=next_index,
            record_id=record_id,
            timestamp=ts_str,
            event_type=event_type,
            description=description,
            device_id=device_id,
            incident_id=incident_id,
            prev_hash=prev_hash,
            current_hash=cur_hash,
            nonce=nonce,
            payload_json=json.dumps(payload),
            status="VALID",
            data_source=data_source
        )
        db.add(block)
        db.commit()
        db.refresh(block)
        return block

    def verify_chain(self, db: Session) -> Dict[str, Any]:
        """Verify unbroken cryptographic sequential linkage across all blocks."""
        blocks = db.query(AuditBlock).order_by(AuditBlock.block_index.asc()).all()
        if not blocks:
            return {
                "is_valid": True,
                "total_blocks": 0,
                "verified_blocks": 0,
                "tampered_block_index": None,
                "error_type": None,
                "error_message": None,
                "last_verification_time": datetime.now(timezone.utc),
                "latest_hash": None
            }

        target_prefix = "0" * self.difficulty
        for i, b in enumerate(blocks):
            # Parse payload
            try:
                p_dict = json.loads(b.payload_json)
            except Exception:
                p_dict = {}

            ts_str = str(b.timestamp)
            expected_hash = self.calculate_hash(
                b.block_index, b.prev_hash, ts_str, b.record_id, b.event_type, p_dict, b.nonce
            )

            # Check 1: recalculate hash
            if b.current_hash != expected_hash:
                return {
                    "is_valid": False,
                    "total_blocks": len(blocks),
                    "verified_blocks": i,
                    "tampered_block_index": b.block_index,
                    "error_type": "HASH_MISMATCH",
                    "error_message": f"Block #{b.block_index} current_hash {b.current_hash[:16]}... does not match recalculated hash {expected_hash[:16]}...",
                    "last_verification_time": datetime.now(timezone.utc),
                    "latest_hash": blocks[-1].current_hash
                }

            # Check 2: Genesis linkage or previous block pointer
            if i == 0:
                if b.prev_hash != GENESIS_PREV_HASH:
                    return {
                        "is_valid": False,
                        "total_blocks": len(blocks),
                        "verified_blocks": 0,
                        "tampered_block_index": 0,
                        "error_type": "GENESIS_CORRUPTION",
                        "error_message": "Genesis block prev_hash is corrupted.",
                        "last_verification_time": datetime.now(timezone.utc),
                        "latest_hash": blocks[-1].current_hash
                    }
            else:
                prev_b = blocks[i - 1]
                if b.prev_hash != prev_b.current_hash:
                    return {
                        "is_valid": False,
                        "total_blocks": len(blocks),
                        "verified_blocks": i,
                        "tampered_block_index": b.block_index,
                        "error_type": "BROKEN_LINKAGE",
                        "error_message": f"Block #{b.block_index} prev_hash does not match Block #{prev_b.block_index} current_hash.",
                        "last_verification_time": datetime.now(timezone.utc),
                        "latest_hash": blocks[-1].current_hash
                    }

            # Check 3: proof of work
            if not b.current_hash.startswith(target_prefix):
                return {
                    "is_valid": False,
                    "total_blocks": len(blocks),
                    "verified_blocks": i,
                    "tampered_block_index": b.block_index,
                    "error_type": "PROOF_OF_WORK_FAILURE",
                    "error_message": f"Block #{b.block_index} hash does not meet difficulty target '{target_prefix}'.",
                    "last_verification_time": datetime.now(timezone.utc),
                    "latest_hash": blocks[-1].current_hash
                }

        return {
            "is_valid": True,
            "total_blocks": len(blocks),
            "verified_blocks": len(blocks),
            "tampered_block_index": None,
            "error_type": None,
            "error_message": None,
            "last_verification_time": datetime.now(timezone.utc),
            "latest_hash": blocks[-1].current_hash
        }


blockchain_service = BlockchainService()
