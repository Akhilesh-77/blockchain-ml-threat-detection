"""
CIC-IDS2017 Public Cybersecurity Dataset Integration and Validation Module.
Handles official UNB CIC-IDS2017 CSV schema parsing, feature alignment,
ground-truth preservation, and validation assessment.
"""

from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import FEATURE_COLUMNS
from ml.evaluation import evaluate_model
from ml.predict import ThreatPredictor, get_predictor
from ml.preprocessing import Preprocessor

# Canonical mapping for CIC-IDS2017 variations
CIC_COLUMN_MAP = {
    "flow duration": "flow_duration",
    "total fwd packets": "total_fwd_packets",
    "total backward packets": "total_bwd_packets",
    "total length of fwd packets": "total_fwd_bytes",
    "total length of bwd packets": "total_bwd_bytes",
    "fwd packet length mean": "fwd_packet_length_mean",
    "bwd packet length mean": "bwd_packet_length_mean",
    "flow bytes/s": "flow_bytes_per_sec",
    "flow packets/s": "flow_packets_per_sec",
    "flow iat mean": "flow_iat_mean",
    "flow iat std": "flow_iat_std",
    "fwd iat mean": "fwd_iat_mean",
    "bwd iat mean": "bwd_iat_mean",
    "packet length mean": "packet_length_mean",
    "packet length std": "packet_length_std",
    "syn flag count": "syn_flag_count",
    "rst flag count": "rst_flag_count",
    "psh flag count": "psh_flag_count",
    "ack flag count": "ack_flag_count",
    "fin flag count": "fin_flag_count",
    "down/up ratio": "down_up_ratio",
    "label": "original_label"
}

# Ground truth label mapping to model's 3 classes
LABEL_MAPPING = {
    "benign": "Normal",
    "normal": "Normal",
    "portscan": "Suspicious",
    "ftp-patator": "Suspicious",
    "ssh-patator": "Suspicious",
    "bot": "Suspicious",
    "dos hulk": "Malicious",
    "dos goldeneye": "Malicious",
    "dos slowloris": "Malicious",
    "dos slowhttptest": "Malicious",
    "ddos": "Malicious",
    "heartbleed": "Malicious",
    "infiltration": "Malicious",
    "web attack – brute force": "Malicious",
    "web attack – xss": "Malicious",
    "web attack – sql injection": "Malicious"
}


def map_cic_ground_truth(raw_label: str) -> str:
    """Map arbitrary CIC-IDS2017 attack string to canonical target class."""
    clean = str(raw_label).strip().lower()
    for pattern, target in LABEL_MAPPING.items():
        if pattern in clean:
            return target
    # Default non-benign to Malicious
    if "benign" in clean or "normal" in clean:
        return "Normal"
    return "Malicious"


class CICDatasetValidator:
    """Inspects and aligns uploaded public dataset with SOC Sentinel requirements."""

    def __init__(self, df: pd.DataFrame):
        self.raw_df = df.copy()
        # Clean column names (strip whitespace and lowercase)
        self.raw_df.columns = [str(c).strip().lower() for c in self.raw_df.columns]
        self.mapped_df = pd.DataFrame()
        self.matched_features: List[str] = []
        self.missing_features: List[str] = []
        self.has_ground_truth = False
        self._analyze_columns()

    def _analyze_columns(self) -> None:
        """Analyze headers and verify which canonical features are present."""
        df_renamed = self.raw_df.copy()
        rename_dict = {}

        for col in self.raw_df.columns:
            if col in CIC_COLUMN_MAP:
                rename_dict[col] = CIC_COLUMN_MAP[col]

        df_renamed = df_renamed.rename(columns=rename_dict)

        self.matched_features = [f for f in FEATURE_COLUMNS if f in df_renamed.columns]
        self.missing_features = [f for f in FEATURE_COLUMNS if f not in df_renamed.columns]
        self.has_ground_truth = "original_label" in df_renamed.columns or "label" in df_renamed.columns

        # Populate mapped dataframe
        self.mapped_df = df_renamed

    def get_summary(self) -> Dict[str, Any]:
        """Return dataset diagnostic summary."""
        return {
            "total_rows": len(self.raw_df),
            "total_columns": len(self.raw_df.columns),
            "matched_features_count": len(self.matched_features),
            "total_expected_features": len(FEATURE_COLUMNS),
            "matched_features": self.matched_features,
            "missing_features": self.missing_features,
            "has_ground_truth": self.has_ground_truth,
            "feature_coverage_pct": round(len(self.matched_features) / len(FEATURE_COLUMNS) * 100.0, 1)
        }

    def prepare_for_inference(self) -> pd.DataFrame:
        """
        Prepare features for threat prediction without modifying original labels.
        Fills missing canonical columns with 0.0.
        """
        out_df = self.mapped_df.copy()

        # Handle label column
        label_col = "original_label" if "original_label" in out_df.columns else ("label" if "label" in out_df.columns else None)
        if label_col:
            out_df["ground_truth_label"] = out_df[label_col].astype(str)
            out_df["normalized_ground_truth"] = out_df["ground_truth_label"].apply(map_cic_ground_truth)

        # Ensure all 21 features exist
        for feat in FEATURE_COLUMNS:
            if feat not in out_df.columns:
                out_df[feat] = 0.0

        # Replace infs and NaNs
        for feat in FEATURE_COLUMNS:
            out_df[feat] = pd.to_numeric(out_df[feat], errors="coerce").fillna(0.0)
            out_df[feat] = out_df[feat].replace([np.inf, -np.inf], 0.0)

        # UNB CIC-IDS2017 records Flow Duration in microseconds; normalize to seconds if needed
        if "flow_duration" in out_df.columns and out_df["flow_duration"].mean() > 1000.0:
            out_df["flow_duration"] = out_df["flow_duration"] / 1000000.0

        out_df["data_source"] = "PUBLIC_DATASET"
        return out_df

    def evaluate_against_ground_truth(self, predictor: Optional[ThreatPredictor] = None) -> Dict[str, Any]:
        """
        Run inference on the dataset and compare model predictions directly against known labels.
        Returns accuracy, precision, recall, F1, and confusion matrix.
        """
        if not self.has_ground_truth:
            raise ValueError("Dataset does not contain a ground-truth 'Label' column.")

        pred_engine = predictor or get_predictor()
        prep_df = self.prepare_for_inference()

        # Predict
        classified = pred_engine.predict_batch(prep_df[FEATURE_COLUMNS])

        y_true_str = prep_df["normalized_ground_truth"].values
        y_pred_str = classified["prediction"].values

        # Encode strings to integers [0: Normal, 1: Suspicious, 2: Malicious]
        y_true_int = Preprocessor.encode_labels(y_true_str)
        y_pred_int = Preprocessor.encode_labels(y_pred_str)

        metrics = evaluate_model(y_true_int, y_pred_int)

        # Combine results into single dataframe
        result_df = prep_df.copy()
        result_df["prediction"] = y_pred_str
        result_df["confidence"] = classified["confidence"]
        result_df["match"] = result_df["normalized_ground_truth"] == result_df["prediction"]

        return {
            "metrics": metrics,
            "results_dataframe": result_df,
            "total_evaluated": len(result_df),
            "matches": int(result_df["match"].sum()),
            "mismatches": int((~result_df["match"]).sum())
        }
