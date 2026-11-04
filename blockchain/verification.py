"""
Blockchain Integrity Verification module for cryptographic hash-chain validation and tamper detection.
"""

from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import BLOCKCHAIN_DIFFICULTY, GENESIS_PREV_HASH
from blockchain.ledger import AuditBlock


class VerificationReport:
    """Encapsulates the comprehensive results of an audit verification run."""

    def __init__(
        self,
        is_valid: bool,
        total_blocks: int,
        tampered_block_index: Optional[int] = None,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        block_diagnostics: Optional[List[Dict[str, Any]]] = None
    ):
        self.is_valid = is_valid
        self.total_blocks = total_blocks
        self.tampered_block_index = tampered_block_index
        self.error_type = error_type
        self.error_message = error_message
        self.block_diagnostics = block_diagnostics or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary format."""
        return {
            "is_valid": self.is_valid,
            "total_blocks": self.total_blocks,
            "tampered_block_index": self.tampered_block_index,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "block_diagnostics": self.block_diagnostics
        }


def verify_chain_integrity(blocks: List[AuditBlock], difficulty: int = BLOCKCHAIN_DIFFICULTY) -> VerificationReport:
    """
    Cryptographically verify the entire blockchain ledger:
    1. Check Genesis block linkage (prev_hash == "000...000").
    2. Recalculate each block's cryptographic SHA-256 hash from its canonical payload and compare against current_hash.
    3. Verify that each block's prev_hash strictly matches the previous block's current_hash.
    4. Confirm proof-of-work compliance (leading zeros prefix).

    Returns a VerificationReport indicating validity, pinpointing any tampered blocks, and providing diagnostics.
    """
    if not blocks:
        return VerificationReport(
            is_valid=True,
            total_blocks=0,
            error_message="Ledger is empty. No blocks to verify."
        )

    diagnostics: List[Dict[str, Any]] = []
    target_prefix = "0" * difficulty

    # 1. Validate Genesis Block
    genesis = blocks[0]
    recalculated_genesis_hash = genesis.calculate_hash()

    if genesis.index_num != 0:
        return VerificationReport(
            is_valid=False,
            total_blocks=len(blocks),
            tampered_block_index=0,
            error_type="INVALID_GENESIS_INDEX",
            error_message=f"Genesis block has index {genesis.index_num}, expected 0."
        )

    if genesis.prev_hash != GENESIS_PREV_HASH:
        return VerificationReport(
            is_valid=False,
            total_blocks=len(blocks),
            tampered_block_index=0,
            error_type="CORRUPTED_GENESIS_LINK",
            error_message="Genesis block does not link to the canonical zero root."
        )

    if genesis.current_hash != recalculated_genesis_hash:
        return VerificationReport(
            is_valid=False,
            total_blocks=len(blocks),
            tampered_block_index=0,
            error_type="CORRUPTED_GENESIS_DATA",
            error_message=(
                f"Genesis block hash mismatch! Recorded: {genesis.current_hash[:16]}..., "
                f"Computed: {recalculated_genesis_hash[:16]}..."
            )
        )

    diagnostics.append({
        "index_num": 0,
        "status": "VALID",
        "hash": genesis.current_hash,
        "prev_hash": genesis.prev_hash,
        "detail": "Genesis block authentic."
    })

    # 2. Iterate through subsequent blocks
    for i in range(1, len(blocks)):
        prev_block = blocks[i - 1]
        curr_block = blocks[i]

        # 1. Check chain link continuity first (pointer to previous block)
        if curr_block.prev_hash != prev_block.current_hash:
            diagnostics.append({
                "index_num": curr_block.index_num,
                "status": "BROKEN_LINK",
                "hash": curr_block.current_hash,
                "prev_hash": curr_block.prev_hash,
                "expected_prev_hash": prev_block.current_hash,
                "detail": f"Chain link broken between Block #{prev_block.index_num} and #{curr_block.index_num}."
            })
            return VerificationReport(
                is_valid=False,
                total_blocks=len(blocks),
                tampered_block_index=curr_block.index_num,
                error_type="CHAIN_LINK_BROKEN",
                error_message=(
                    f"CHAIN LINK BROKEN at Block #{curr_block.index_num}! "
                    f"Block's prev_hash ({curr_block.prev_hash[:16]}...) does not match "
                    f"Block #{prev_block.index_num}'s current_hash ({prev_block.current_hash[:16]}...)."
                ),
                block_diagnostics=diagnostics
            )

        # 2. Recalculate current block hash from payload
        recomputed_hash = curr_block.calculate_hash()

        # Check payload integrity (tampered data within block)
        if curr_block.current_hash != recomputed_hash:
            diagnostics.append({
                "index_num": curr_block.index_num,
                "status": "TAMPERED_DATA",
                "hash": curr_block.current_hash,
                "recomputed_hash": recomputed_hash,
                "prev_hash": curr_block.prev_hash,
                "detail": f"Tampering detected! Payload does not match cryptographic digest."
            })
            return VerificationReport(
                is_valid=False,
                total_blocks=len(blocks),
                tampered_block_index=curr_block.index_num,
                error_type="BLOCK_TAMPERED",
                error_message=(
                    f"TAMPER DETECTED in Block #{curr_block.index_num}! "
                    f"The block data was modified without a valid cryptographic re-mine. "
                    f"Stored Hash: {curr_block.current_hash[:20]}..., "
                    f"Recomputed Hash: {recomputed_hash[:20]}..."
                ),
                block_diagnostics=diagnostics
            )

        # Check proof-of-work difficulty condition
        if difficulty > 0 and not curr_block.current_hash.startswith(target_prefix):
            diagnostics.append({
                "index_num": curr_block.index_num,
                "status": "INVALID_POW",
                "hash": curr_block.current_hash,
                "detail": f"Block hash does not meet difficulty requirement ({difficulty} leading zeroes)."
            })
            return VerificationReport(
                is_valid=False,
                total_blocks=len(blocks),
                tampered_block_index=curr_block.index_num,
                error_type="INVALID_PROOF_OF_WORK",
                error_message=f"Block #{curr_block.index_num} hash lacks the required {difficulty} leading zeros.",
                block_diagnostics=diagnostics
            )

        diagnostics.append({
            "index_num": curr_block.index_num,
            "status": "VALID",
            "hash": curr_block.current_hash,
            "prev_hash": curr_block.prev_hash,
            "detail": "Block integrity and chain linkage verified."
        })

    return VerificationReport(
        is_valid=True,
        total_blocks=len(blocks),
        error_message=f"All {len(blocks)} blocks in the chain are cryptographically valid and untampered.",
        block_diagnostics=diagnostics
    )
