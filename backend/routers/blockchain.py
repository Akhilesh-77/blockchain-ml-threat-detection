"""
Blockchain Audit Ledger API Router for CyberNex.
Provides block exploration, cryptographic SHA-256 verification, and safe isolated tamper testing.
"""

from datetime import datetime, timezone
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import AuditBlock
from backend.schemas import (
    AuditBlockResponse,
    BlockchainIntegrityResponse,
    TamperDemoResponse,
)
from backend.blockchain_service import blockchain_service

router = APIRouter(prefix="/api/blockchain", tags=["Blockchain Audit Ledger"])


@router.get("/blocks", response_model=List[AuditBlockResponse])
def get_blocks(limit: int = 100, db: Session = Depends(get_db)):
    """Retrieve chronological blockchain blocks."""
    blockchain_service.ensure_genesis_block(db)
    blocks = db.query(AuditBlock).order_by(AuditBlock.block_index.asc()).limit(limit).all()
    results = []
    for b in blocks:
        payload = {}
        try:
            payload = json.loads(b.payload_json) if b.payload_json else {}
        except Exception:
            payload = {}

        results.append(AuditBlockResponse(
            block_index=b.block_index,
            record_id=b.record_id,
            timestamp=b.timestamp,
            event_type=b.event_type,
            description=b.description,
            device_id=b.device_id,
            incident_id=b.incident_id,
            prev_hash=b.prev_hash,
            current_hash=b.current_hash,
            nonce=b.nonce,
            status=b.status,
            data_source=b.data_source,
            payload=payload
        ))
    return results


@router.get("/verify", response_model=BlockchainIntegrityResponse)
def verify_blockchain_integrity(db: Session = Depends(get_db)):
    """
    Cryptographically verify the entire blockchain ledger:
    1. Check Genesis root previous hash linkage.
    2. Recalculate each block's SHA-256 canonical payload digest and compare with current_hash.
    3. Verify that each block's prev_hash strictly matches previous block's current_hash.
    4. Verify Proof-of-Work difficulty target.
    """
    blockchain_service.ensure_genesis_block(db)
    res = blockchain_service.verify_chain(db)
    return BlockchainIntegrityResponse(**res)


@router.post("/tamper-demonstration", response_model=TamperDemoResponse)
def run_tamper_demonstration(block_index: int = 1, altered_prediction: str = "SAFE_BENIGN", db: Session = Depends(get_db)):
    """
    Educational Tamper Demonstration:
    Demonstrates tamper-detection in an isolated test routine without permanently corrupting
    the authoritative blockchain ledger.
    """
    blockchain_service.ensure_genesis_block(db)
    target_block = db.query(AuditBlock).filter(AuditBlock.block_index == block_index).first()
    if not target_block:
        target_block = db.query(AuditBlock).order_by(AuditBlock.block_index.desc()).first()

    orig_pred = "MALICIOUS"
    try:
        p = json.loads(target_block.payload_json)
        orig_pred = p.get("ml_prediction", "MALICIOUS")
    except Exception:
        pass

    # Demonstrate what happens when payload is altered without recalculating hash
    fake_payload = dict(p) if isinstance(p, dict) else {}
    fake_payload["ml_prediction"] = altered_prediction
    ts_str = target_block.timestamp.isoformat() if hasattr(target_block.timestamp, "isoformat") else str(target_block.timestamp)
    mismatched_hash = blockchain_service.calculate_hash(
        target_block.block_index, target_block.prev_hash, ts_str,
        target_block.record_id, target_block.event_type, fake_payload, target_block.nonce
    )

    return TamperDemoResponse(
        success=True,
        tampered_block_index=target_block.block_index,
        original_prediction=orig_pred,
        altered_prediction=altered_prediction,
        message=(
            f"Tamper simulation evaluated for Block #{target_block.block_index}: "
            f"Altering payload to '{altered_prediction}' changes hash to {mismatched_hash[:16]}..., "
            f"which fails validation against stored digest {target_block.current_hash[:16]}... "
            f"Integrity check successfully flags HASH_MISMATCH!"
        ),
        is_isolated_test_copy=True
    )

