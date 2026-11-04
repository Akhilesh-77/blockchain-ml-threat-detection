"""
Unit tests for Machine Learning pipeline, preprocessing, and inference.
"""

import numpy as np
import pandas as pd
import pytest
from config import FEATURE_COLUMNS
from ml.predict import ThreatPredictor, get_predictor
from ml.preprocessing import Preprocessor
from ml.train import generate_cic_style_synthetic_dataset, train_model


def test_preprocessor_clean_features():
    """Verify that infinite and missing values are safely sanitized."""
    raw_df = pd.DataFrame([{
        "flow_duration": np.inf,
        "total_fwd_packets": np.nan,
        "total_bwd_packets": -np.inf,
        "fwd_packet_length_mean": 500.0
    }])
    clean_df = Preprocessor.clean_features(raw_df)

    assert not clean_df.isin([np.inf, -np.inf]).any().any()
    assert not clean_df.isna().any().any()
    assert set(FEATURE_COLUMNS).issubset(clean_df.columns)
    assert clean_df.loc[0, "flow_duration"] == 0.0
    assert clean_df.loc[0, "total_fwd_packets"] == 0.0
    assert clean_df.loc[0, "fwd_packet_length_mean"] == 500.0


def test_label_encoding():
    """Verify label encoding converts textual categories to integers properly."""
    labels = ["Normal", "Suspicious", "Malicious", "benign", "TOR_TRAFFIC", "Unknown_Threat"]
    encoded = Preprocessor.encode_labels(labels)
    assert encoded[0] == 0  # Normal
    assert encoded[1] == 1  # Suspicious
    assert encoded[2] == 2  # Malicious
    assert encoded[3] == 0  # benign -> 0
    assert encoded[4] == 1  # tor -> 1
    assert encoded[5] == 2  # other -> 2


def test_model_training_and_artifacts():
    """Verify training generates valid metrics and evaluations."""
    df = generate_cic_style_synthetic_dataset(n_samples=300, random_state=42)
    meta = train_model(data_source=df, test_size=0.2, random_state=42, save_artifacts=False)

    assert "metrics" in meta
    metrics = meta["metrics"]
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert 0.0 <= metrics["f1_macro"] <= 1.0
    assert len(metrics["confusion_matrix"]) == 3
    assert len(meta["feature_importances"]) == len(FEATURE_COLUMNS)


def test_predictor_inference():
    """Verify inference produces valid predictions and probability distributions."""
    predictor = get_predictor()
    assert predictor.is_ready()

    sample_features = {
        "flow_duration": 2.5,
        "total_fwd_packets": 10,
        "total_bwd_packets": 20,
        "total_fwd_bytes": 1500.0,
        "total_bwd_bytes": 22000.0,
        "fwd_packet_length_mean": 150.0,
        "bwd_packet_length_mean": 1100.0,
        "flow_bytes_per_sec": 9400.0,
        "flow_packets_per_sec": 12.0,
        "flow_iat_mean": 0.1,
        "flow_iat_std": 0.15,
        "fwd_iat_mean": 0.2,
        "bwd_iat_mean": 0.1,
        "packet_length_mean": 783.3,
        "packet_length_std": 450.0,
        "syn_flag_count": 1,
        "rst_flag_count": 0,
        "psh_flag_count": 4,
        "ack_flag_count": 29,
        "fin_flag_count": 1,
        "down_up_ratio": 2.0
    }

    res = predictor.predict_single(sample_features)
    assert res["prediction"] in ["Normal", "Suspicious", "Malicious"]
    assert 0.0 <= res["confidence"] <= 1.0
    assert "probabilities" in res
    assert round(sum(res["probabilities"].values()), 1) == 1.0

