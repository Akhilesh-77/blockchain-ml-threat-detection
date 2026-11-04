"""
Predictor module for running threat classification inference on encrypted network metadata.
"""

import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from config import (
    CLASS_MAPPING,
    CLASS_NAMES,
    FEATURE_COLUMNS,
    METADATA_PATH,
    MODEL_PATH,
    SCALER_PATH,
)
from ml.preprocessing import Preprocessor


class ThreatPredictor:
    """Loads trained artifacts and performs low-latency inference on session metadata."""

    def __init__(
        self,
        model_path: Path = MODEL_PATH,
        scaler_path: Path = SCALER_PATH,
        metadata_path: Path = METADATA_PATH
    ):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.metadata_path = metadata_path

        self.model = None
        self.scaler = None
        self.metadata = {}
        self.preprocessor = None
        self.load_artifacts()

    def is_ready(self) -> bool:
        """Check if model and preprocessing pipeline are ready for inference."""
        return self.model is not None and self.preprocessor is not None

    def load_artifacts(self) -> bool:
        """Load model, scaler, and training metadata from disk."""
        if not (self.model_path.exists() and self.scaler_path.exists()):
            return False

        try:
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            self.preprocessor = Preprocessor(scaler=self.scaler)

            if self.metadata_path.exists():
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            return True
        except Exception as e:
            print(f"Error loading model artifacts: {e}")
            return False

    def predict_single(self, session_features: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a single network session metadata dictionary."""
        if not self.is_ready():
            raise RuntimeError("ThreatPredictor is not initialized. Train or load a model first.")

        df = pd.DataFrame([session_features])
        X_scaled = self.preprocessor.transform(df)

        pred_id = int(self.model.predict(X_scaled)[0])
        probabilities = self.model.predict_proba(X_scaled)[0]

        pred_label = CLASS_MAPPING.get(pred_id, "Normal")
        confidence = float(probabilities[pred_id])

        prob_dict = {
            CLASS_NAMES[i]: round(float(prob), 4)
            for i, prob in enumerate(probabilities)
        }

        return {
            "prediction": pred_label,
            "prediction_id": pred_id,
            "confidence": round(confidence, 4),
            "probabilities": prob_dict
        }

    def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """Classify a batch DataFrame of network session metadata."""
        if not self.is_ready():
            raise RuntimeError("ThreatPredictor is not initialized. Train or load a model first.")

        # Standardize columns and scale
        df_standard = Preprocessor.standardize_column_names(df)
        X_scaled = self.preprocessor.transform(df_standard)

        preds = self.model.predict(X_scaled)
        probas = self.model.predict_proba(X_scaled)

        out_df = df_standard.copy()
        out_df["prediction_id"] = preds
        out_df["prediction"] = [CLASS_MAPPING.get(p, "Normal") for p in preds]
        out_df["confidence"] = [round(float(probas[i][p]), 4) for i, p in enumerate(preds)]

        for i, name in enumerate(CLASS_NAMES):
            out_df[f"prob_{name.lower()}"] = [round(float(probas[j][i]), 4) for j in range(len(preds))]

        return out_df

    def get_metadata(self) -> Dict[str, Any]:
        """Return training evaluation metadata and model parameters."""
        return self.metadata


# Singleton instance
_predictor_instance: Optional[ThreatPredictor] = None


def get_predictor() -> ThreatPredictor:
    """Retrieve or initialize singleton ThreatPredictor."""
    global _predictor_instance
    if _predictor_instance is None or not _predictor_instance.is_ready():
        _predictor_instance = ThreatPredictor()
    return _predictor_instance
