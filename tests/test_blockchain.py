"""
Unit tests for SHA-256 Blockchain Ledger and Cryptographic Verification.
"""

import pytest
from blockchain.ledger import AuditBlock, BlockchainLedger
from blockchain.verification import verify_chain_integrity
from config import GENESIS_PREV_HASH
from database.db import DatabaseManager


@pytest.fixture
def temp_ledger(tmp_path):
    """Create an isolated BlockchainLedger backed by a temporary database."""
    db_file = tmp_path / "test_chain.db"
    db = DatabaseManager(db_path=db_file)
    ledger = BlockchainLedger(db=db)
    return ledger


def test_audit_block_hash_reproducibility():
    """Verify that hashing is strictly deterministic across identical payloads."""
    b1 = AuditBlock(
        index_num=1,
        event_id="EVT-001",
        timestamp="2026-11-04T12:00:00Z",
        prediction="Suspicious",
        confidence=0.8950,
        metadata_json={"dst_port": 443, "flow_duration": 1.5},
        prev_hash="0" * 64,
        nonce=10
    )
    b2 = AuditBlock(
        index_num=1,
        event_id="EVT-001",
        timestamp="2026-11-04T12:00:00Z",
        prediction="Suspicious",
        confidence=0.8950,
        metadata_json={"flow_duration": 1.5, "dst_port": 443},  # Reversed order
        prev_hash="0" * 64,
        nonce=10
    )
    assert b1.calculate_hash() == b2.calculate_hash()


def test_genesis_block_creation(temp_ledger):
    """Verify automatic creation and validity of the Genesis block."""
    chain = temp_ledger.get_chain()
    assert len(chain) >= 1
    genesis = chain[0]
    assert genesis.index_num == 0
    assert genesis.prev_hash == GENESIS_PREV_HASH
    assert genesis.prediction == "SYSTEM_INIT"

    report = verify_chain_integrity(chain, difficulty=1)
    assert report.is_valid is True
    assert report.tampered_block_index is None


def test_ledger_append_and_verification(temp_ledger):
    """Verify mining multiple detection events and validating the full chain."""
    temp_ledger.create_detection_record(
        prediction="Normal",
        confidence=0.97,
        metadata_summary={"flow_duration": 1.2, "dst_port": 443, "total_fwd_packets": 10}
    )
    temp_ledger.create_detection_record(
        prediction="Malicious",
        confidence=0.99,
        metadata_summary={"flow_duration": 8.5, "dst_port": 8443, "total_fwd_packets": 80}
    )

    chain = temp_ledger.get_chain()
    assert len(chain) == 3  # Genesis + 2 events

    # Verify link continuity
    assert chain[1].prev_hash == chain[0].current_hash
    assert chain[2].prev_hash == chain[1].current_hash

    report = verify_chain_integrity(chain, difficulty=temp_ledger.db.get_latest_block()["current_hash"][:0] and 0 or 2)
    assert report.is_valid is True


def test_tamper_detection_on_altered_record(temp_ledger):
    """
    CRITICAL TEST: Verify that modifying any existing audit record (e.g. changing
    prediction from 'Malicious' to 'Normal') immediately breaks hash integrity
    and is flagged by the verification system.
    """
    temp_ledger.create_detection_record(
        prediction="Malicious",
        confidence=0.99,
        metadata_summary={"flow_duration": 10.0, "dst_port": 443}
    )

    chain = temp_ledger.get_chain()
    assert len(chain) == 2

    # Simulate tampering by directly modifying the block's prediction in the database
    temp_ledger.db.tamper_block_for_testing(1, "Normal")

    tampered_chain = temp_ledger.get_chain()
    assert tampered_chain[1].prediction == "Normal"

    # Integrity verification MUST fail
    report = verify_chain_integrity(tampered_chain, difficulty=2)
    assert report.is_valid is False
    assert report.tampered_block_index == 1
    assert report.error_type == "BLOCK_TAMPERED"
    assert "TAMPER DETECTED" in report.error_message


def test_tamper_detection_on_broken_chain_pointer(temp_ledger):
    """Verify detection when a block's prev_hash pointer is broken."""
    temp_ledger.create_detection_record(
        prediction="Normal",
        confidence=0.95,
        metadata_summary={"flow_duration": 1.0}
    )
    temp_ledger.create_detection_record(
        prediction="Suspicious",
        confidence=0.88,
        metadata_summary={"flow_duration": 2.0}
    )

    chain = temp_ledger.get_chain()
    assert len(chain) == 3

    # Corrupt the prev_hash link of block #2
    chain[2].prev_hash = "deadbeef" * 8

    report = verify_chain_integrity(chain, difficulty=0)
    assert report.is_valid is False
    assert report.tampered_block_index == 2
    assert report.error_type == "CHAIN_LINK_BROKEN"
