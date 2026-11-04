"""
Preprocessing pipeline for encrypted network traffic metadata.
Handles feature normalization, handling inf/nan values, column mapping, and scaling.
"""

from pathlib import Path
import sys
from typing import Dict, List, Optional, Tuple, Union

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from config import FEATURE_COLUMNS, LABEL_TO_ID

# Mapping for standard CIC-IDS2017 and Zeek header variations
COLUMN_ALIASES = {
    "flow duration": "flow_duration",
    "flow_duration": "flow_duration",
    "duration": "flow_duration",
    "total fwd packets": "total_fwd_packets",
    "tot fwd pkts": "total_fwd_packets",
    "total_fwd_packets": "total_fwd_packets",
    "total backward packets": "total_bwd_packets",
    "tot bwd pkts": "total_bwd_packets",
    "total_bwd_packets": "total_bwd_packets",
    "total length of fwd packets": "total_fwd_bytes",
    "totlen fwd pkts": "total_fwd_bytes",
    "total_fwd_bytes": "total_fwd_bytes",
    "orig_bytes": "total_fwd_bytes",
    "total length of bwd packets": "total_bwd_bytes",
    "totlen bwd pkts": "total_bwd_bytes",
    "total_bwd_bytes": "total_bwd_bytes",
    "resp_bytes": "total_bwd_bytes",
    "fwd packet length mean": "fwd_packet_length_mean",
    "fwd pkt len mean": "fwd_packet_length_mean",
    "fwd_packet_length_mean": "fwd_packet_length_mean",
    "bwd packet length mean": "bwd_packet_length_mean",
    "bwd pkt len mean": "bwd_packet_length_mean",
    "bwd_packet_length_mean": "bwd_packet_length_mean",
    "flow bytes/s": "flow_bytes_per_sec",
    "flow byts/s": "flow_bytes_per_sec",
    "flow_bytes_per_sec": "flow_bytes_per_sec",
    "flow packets/s": "flow_packets_per_sec",
    "flow pkts/s": "flow_packets_per_sec",
    "flow_packets_per_sec": "flow_packets_per_sec",
    "flow iat mean": "flow_iat_mean",
    "flow_iat_mean": "flow_iat_mean",
    "flow iat std": "flow_iat_std",
    "flow_iat_std": "flow_iat_std",
    "fwd iat mean": "fwd_iat_mean",
    "fwd_iat_mean": "fwd_iat_mean",
    "bwd iat mean": "bwd_iat_mean",
    "bwd_iat_mean": "bwd_iat_mean",
    "packet length mean": "packet_length_mean",
    "pkt len mean": "packet_length_mean",
    "packet_length_mean": "packet_length_mean",
    "packet length std": "packet_length_std",
    "pkt len std": "packet_length_std",
    "packet_length_std": "packet_length_std",
    "syn flag count": "syn_flag_count",
    "syn_flag_count": "syn_flag_count",
    "rst flag count": "rst_flag_count",
    "rst_flag_count": "rst_flag_count",
    "psh flag count": "psh_flag_count",
    "psh_flag_count": "psh_flag_count",
    "ack flag count": "ack_flag_count",
    "ack_flag_count": "ack_flag_count",
    "fin flag count": "fin_flag_count",
    "fin_flag_count": "fin_flag_count",
    "down/up ratio": "down_up_ratio",
    "down_up_ratio": "down_up_ratio",
    "label": "label",
    "class": "label",
    "category": "label"
}


class Preprocessor:
    """Encapsulates cleaning, feature alignment, and scaling for network metadata."""

    def __init__(self, scaler: Optional[StandardScaler] = None):
        self.scaler = scaler or StandardScaler()
        self.is_fitted = scaler is not None

    @staticmethod
    def standardize_column_names(df: pd.DataFrame) -> pd.DataFrame:
        """Map heterogeneous CSV column names to canonical internal names."""
        df_copy = df.copy()
        renamed = {}
        for col in df_copy.columns:
            normalized = col.strip().lower()
            if normalized in COLUMN_ALIASES:
                renamed[col] = COLUMN_ALIASES[normalized]
        df_copy = df_copy.rename(columns=renamed)
        return df_copy

    @staticmethod
    def clean_features(df: pd.DataFrame) -> pd.DataFrame:
        """
        Handle missing values, infinite rates from 0 duration, and negative values.
        """
        df_clean = df.copy()

        # Ensure all required feature columns exist, defaulting missing to 0
        for col in FEATURE_COLUMNS:
            if col not in df_clean.columns:
                df_clean[col] = 0.0

        # Select only canonical feature columns
        df_clean = df_clean[FEATURE_COLUMNS].copy()

        # Replace infinite values resulting from zero flow durations
        df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)

        # Fill NaNs with column medians or 0
        df_clean.fillna(0.0, inplace=True)

        # Ensure all types are float32/float64
        df_clean = df_clean.astype(np.float64)

        return df_clean

    def fit(self, X: Union[pd.DataFrame, np.ndarray]) -> "Preprocessor":
        """Fit scaler on clean feature matrix."""
        if isinstance(X, pd.DataFrame):
            X_clean = self.clean_features(self.standardize_column_names(X))
        else:
            X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        self.scaler.fit(X_clean)
        self.is_fitted = True
        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Transform features using fitted scaler."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor has not been fitted yet.")

        if isinstance(X, pd.DataFrame):
            X_clean = self.clean_features(self.standardize_column_names(X))
            return self.scaler.transform(X_clean)
        else:
            X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            return self.scaler.transform(X_clean)

    def fit_transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Fit and transform in a single call."""
        return self.fit(X).transform(X)

    @staticmethod
    def encode_labels(labels: Union[pd.Series, List[str]]) -> np.ndarray:
        """Map text labels ('Normal', 'Suspicious', 'Malicious') to integers [0, 1, 2]."""
        encoded = []
        for lbl in labels:
            clean_lbl = str(lbl).strip().capitalize()
            if clean_lbl in LABEL_TO_ID:
                encoded.append(LABEL_TO_ID[clean_lbl])
            elif "benign" in clean_lbl.lower() or "normal" in clean_lbl.lower():
                encoded.append(0)
            elif "suspicious" in clean_lbl.lower() or "tor" in clean_lbl.lower() or "doh" in clean_lbl.lower():
                encoded.append(1)
            else:
                encoded.append(2)  # Malicious
        return np.array(encoded, dtype=int)
