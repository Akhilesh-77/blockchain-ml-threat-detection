"""
Evaluation module for Machine Learning model assessment and performance metrics.
"""

from pathlib import Path
import sys
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from config import CLASS_NAMES, FEATURE_COLUMNS


def evaluate_model(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    """
    Calculate thorough classification metrics on test data.
    Never invents or hardcodes statistics; every metric is calculated directly from ground truth and predictions.
    """
    acc = float(accuracy_score(y_true, y_pred))
    prec_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    prec_weighted = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
    rec_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    rec_weighted = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
    f1_macro = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2])
    report_dict = classification_report(
        y_true,
        y_pred,
        target_names=CLASS_NAMES,
        output_dict=True,
        zero_division=0
    )

    return {
        "accuracy": round(acc, 4),
        "precision_macro": round(prec_macro, 4),
        "precision_weighted": round(prec_weighted, 4),
        "recall_macro": round(rec_macro, 4),
        "recall_weighted": round(rec_weighted, 4),
        "f1_macro": round(f1_macro, 4),
        "f1_weighted": round(f1_weighted, 4),
        "confusion_matrix": cm.tolist(),
        "classification_report": report_dict,
        "classes": CLASS_NAMES,
        "total_test_samples": int(len(y_true))
    }


def extract_feature_importances(model: Any, feature_names: List[str] = FEATURE_COLUMNS) -> pd.DataFrame:
    """Extract and sort feature importance scores from a tree-based model."""
    if not hasattr(model, "feature_importances_"):
        return pd.DataFrame()

    importances = model.feature_importances_
    df = pd.DataFrame({
        "feature": feature_names,
        "importance": importances
    })
    df.sort_values(by="importance", ascending=False, inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df
