"""
Feature Extraction and Sanitization module for Encrypted Network Metadata.
Strictly adheres to metadata-only inspection without decrypting TLS payloads.
"""

import hashlib
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import FEATURE_COLUMNS


def anonymize_ip(ip_address: str) -> str:
    """
    Hash IP addresses to preserve privacy in compliance with ethical SOC standards.
    Returns truncated SHA-256 digest (e.g. 'IP-7a9b3c4d').
    """
    if not ip_address or ip_address in ["-", "0.0.0.0", "unknown"]:
        return "IP-UNKNOWN"
    digest = hashlib.sha256(ip_address.encode("utf-8")).hexdigest()[:8].upper()
    return f"IP-{digest}"


def extract_features_from_dict(raw: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract canonical numerical feature dictionary from heterogeneous input.
    """
    features: Dict[str, float] = {}
    for col in FEATURE_COLUMNS:
        val = raw.get(col, 0.0)
        try:
            val_float = float(val)
            if np.isnan(val_float) or np.isinf(val_float):
                val_float = 0.0
            features[col] = round(val_float, 4)
        except (ValueError, TypeError):
            features[col] = 0.0
    return features


def build_session_record(
    session_id: str,
    timestamp: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    features: Dict[str, float],
    prediction: str,
    confidence: float
) -> Dict[str, Any]:
    """
    Assemble a standardized session record for display, ML classification, and ledger auditing.
    """
    return {
        "session_id": session_id,
        "timestamp": timestamp,
        "src_ip_hash": anonymize_ip(src_ip),
        "dst_ip_hash": anonymize_ip(dst_ip),
        "dst_port": int(dst_port),
        "protocol": protocol,
        "features": features,
        "prediction": prediction,
        "confidence": round(float(confidence), 4),
        "audited": 0,
        "block_index": None
    }
