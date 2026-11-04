"""
Unit tests for Real-World Testing & Validation modules:
- Live network socket session measurement
- Controlled loopback testing patterns
- CIC-IDS2017 public dataset mapping and evaluation
- Model provenance validation
- Experiment registry persistence in SQLite
"""

from pathlib import Path
import tempfile
import pandas as pd
import pytest
from config import FEATURE_COLUMNS, SAMPLE_DATA_DIR
from database.db import DatabaseManager
from ml.validation import get_model_validation_status
from network.cic_ids_loader import CICDatasetValidator, map_cic_ground_truth
from network.live_collector import (
    capture_live_http_session,
    run_controlled_loopback_test,
)


def test_model_validation_provenance():
    """Verify that model provenance metadata is legitimately present and validated."""
    status = get_model_validation_status()
    assert status["is_trained"] is True
    assert status["status_text"] == "GENUINELY TRAINED & VALIDATED"
    assert "Random Forest" in status["algorithm"]
    assert status["train_samples"] > 0
    assert status["test_samples"] > 0
    assert "metrics" in status
    assert "accuracy" in status["metrics"]


def test_controlled_loopback_patterns():
    """Verify that controlled laboratory tests generate valid 21-feature schemas."""
    patterns = ["tor_cell_tunnel", "c2_beacon", "rapid_burst", "normal_local"]
    for pat in patterns:
        res = run_controlled_loopback_test(pat)
        assert res["data_source"] == "CONTROLLED_LAB"
        assert res["src_ip"] == "127.0.0.1"
        assert res["dst_ip"] == "127.0.0.1"
        assert res["flow_duration"] > 0
        assert res["total_fwd_packets"] > 0
        assert set(FEATURE_COLUMNS).issubset(res.keys())


def test_cic_ids_dataset_mapper():
    """Verify CIC-IDS2017 dataset header mapping and feature coverage."""
    sample_csv = SAMPLE_DATA_DIR / "cic_ids2017_sample.csv"
    assert sample_csv.exists(), "Sample CIC-IDS2017 CSV must exist"

    df = pd.read_csv(sample_csv)
    validator = CICDatasetValidator(df)
    summary = validator.get_summary()

    assert summary["has_ground_truth"] is True
    assert summary["matched_features_count"] == 21
    assert summary["feature_coverage_pct"] == 100.0

    eval_res = validator.evaluate_against_ground_truth()
    assert "metrics" in eval_res
    assert 0.0 <= eval_res["metrics"]["accuracy"] <= 1.0
    assert eval_res["matches"] + eval_res["mismatches"] == len(df)


def test_cic_ground_truth_label_mapping():
    """Verify raw attack strings are normalized correctly."""
    assert map_cic_ground_truth("BENIGN") == "Normal"
    assert map_cic_ground_truth("DDoS") == "Malicious"
    assert map_cic_ground_truth("PortScan") == "Suspicious"
    assert map_cic_ground_truth("Bot") == "Suspicious"
    assert map_cic_ground_truth("DoS Hulk") == "Malicious"


def test_experiments_db_persistence(tmp_path):
    """Verify experiment records are stored and retrieved from SQLite."""
    db_file = tmp_path / "test_exp.db"
    db = DatabaseManager(db_path=db_file)

    exp_data = {
        "experiment_id": "EXP-UNIT-01",
        "timestamp": "2026-11-05T00:00:00Z",
        "experiment_name": "Test Experiment",
        "data_source": "PUBLIC_DATASET",
        "total_sessions": 20,
        "normal_count": 10,
        "suspicious_count": 5,
        "malicious_count": 5,
        "ground_truth_available": 1,
        "metrics": {"accuracy": 0.95},
        "notes": "Unit test run"
    }
    db.insert_experiment(exp_data)

    exps = db.get_all_experiments()
    assert len(exps) == 1
    assert exps[0]["experiment_id"] == "EXP-UNIT-01"
    assert exps[0]["metrics"]["accuracy"] == 0.95


def test_data_source_filtering(tmp_path):
    """Verify session stats filtering by data source."""
    db_file = tmp_path / "test_ds.db"
    db = DatabaseManager(db_path=db_file)

    # Insert 1 LIVE and 2 PUBLIC
    db.insert_session({
        "session_id": "SES-LIVE-1",
        "timestamp": "2026-11-05T00:00:00Z",
        "src_ip_hash": "IP-001",
        "dst_ip_hash": "IP-002",
        "dst_port": 443,
        "protocol": "TCP/TLS",
        "features": {},
        "prediction": "Normal",
        "confidence": 0.95,
        "audited": 0,
        "data_source": "LIVE_NETWORK"
    })
    db.insert_session({
        "session_id": "SES-PUB-1",
        "timestamp": "2026-11-05T00:00:00Z",
        "src_ip_hash": "IP-003",
        "dst_ip_hash": "IP-004",
        "dst_port": 443,
        "protocol": "TCP/TLS",
        "features": {},
        "prediction": "Malicious",
        "confidence": 0.98,
        "audited": 0,
        "data_source": "PUBLIC_DATASET"
    })

    live_stats = db.get_session_stats(data_source="LIVE_NETWORK")
    assert live_stats["total_sessions"] == 1
    assert live_stats["normal_sessions"] == 1

    pub_stats = db.get_session_stats(data_source="PUBLIC_DATASET")
    assert pub_stats["total_sessions"] == 1
    assert pub_stats["malicious_sessions"] == 1

    counts = db.get_data_source_counts()
    assert counts["LIVE_NETWORK"] == 1
    assert counts["PUBLIC_DATASET"] == 1
