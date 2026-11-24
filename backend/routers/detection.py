"""
Machine Learning Threat Detection API Router for CyberNex.
Provides model metrics, feature extraction endpoints, model evaluation data,
and scenario ground-truth vs ML prediction comparisons.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.database import get_db
from backend.ml_service import ml_service
from backend.models import SecurityIncident
from backend.schemas import MLModelMetricsResponse, MLPredictionResponse

router = APIRouter(prefix="/api/detection", tags=["Machine Learning Detection"])


class PredictRequest(BaseModel):
    app_permissions_count: int = 4
    critical_permissions_count: int = 0
    is_sideloaded: bool = False
    connection_duration: float = 1.0
    packet_count: int = 20
    bytes_sent: int = 1500
    bytes_received: int = 3500
    scenario_ground_truth: Optional[str] = None


@router.get("/metrics", response_model=MLModelMetricsResponse)
def get_ml_metrics():
    """Retrieve genuine Random Forest evaluation metrics, confusion matrix, and feature importances."""
    return ml_service.get_metrics()


@router.post("/predict", response_model=MLPredictionResponse)
def predict_threat(payload: PredictRequest):
    """
    Run Machine Learning inference on custom or simulated features vector.
    Returns predicted class, confidence, risk score, contributing features, and explanation.
    """
    features = ml_service.extract_features(
        app_permissions_count=payload.app_permissions_count,
        critical_permissions_count=payload.critical_permissions_count,
        is_sideloaded=payload.is_sideloaded,
        connection_duration=payload.connection_duration,
        packet_count=payload.packet_count,
        bytes_sent=payload.bytes_sent,
        bytes_received=payload.bytes_received
    )
    return ml_service.predict(features, scenario_ground_truth=payload.scenario_ground_truth)


@router.get("/comparison")
def get_detection_comparisons(db: Session = Depends(get_db)):
    """
    Retrieve historical comparison between simulation scenario ground-truth labels
    and actual independent Machine Learning predictions.
    """
    incidents = db.query(SecurityIncident).order_by(SecurityIncident.created_at.desc()).limit(30).all()
    comparisons = []
    for inc in incidents:
        is_match = (
            (inc.threat_category in ["Trojan Horse", "Spyware", "Ransomware", "Botnet Activity", "Banking Trojan"] and inc.ml_prediction in ["Suspicious", "Malicious"]) or
            (inc.threat_category == "Normal Activity" and inc.ml_prediction == "Normal")
        )
        comparisons.append({
            "incident_id": inc.id,
            "device_id": inc.device_id,
            "scenario_ground_truth": inc.threat_category,
            "ml_prediction": inc.ml_prediction,
            "confidence": inc.confidence,
            "risk_score": inc.risk_score,
            "is_matched": is_match,
            "timestamp": inc.created_at
        })
    return comparisons


@router.get("/scenarios")
def get_threat_scenarios():
    """Retrieve catalog of 8 standard simulated threat scenarios (A through H)."""
    from backend.simulation_engine import SCENARIO_CATALOG
    return [
        {"id": k, **v} for k, v in SCENARIO_CATALOG.items()
    ]
