"""
Pydantic validation schemas for CyberNex REST API.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ============================================================================
# Device Schemas
# ============================================================================

class DeviceCreate(BaseModel):
    name: str = Field(..., example="Pixel 8 Pro - SecLab")
    manufacturer: str = Field(..., example="Google")
    model: str = Field(..., example="Pixel 8 Pro")
    android_version: str = Field(..., example="14")
    color: Optional[str] = Field(default="#06B6D4", example="#06B6D4")
    appearance: Optional[str] = Field(default="titanium-dark", example="titanium-dark")
    initial_security_profile: Optional[str] = Field(default="STANDARD", example="STANDARD")


class DeviceQuickCreate(BaseModel):
    count: int = Field(default=1, ge=1, le=5)
    preset_type: Optional[str] = Field(default="BALANCED", example="BALANCED")


class AppItem(BaseModel):
    id: str
    package_name: str
    app_name: str
    category: str
    version: str
    install_source: str
    is_system: bool
    is_sideloaded: bool
    is_quarantined: bool
    risk_score: int
    security_classification: str
    permissions: List[str]
    background_activity: str
    network_activity: str

    class Config:
        from_attributes = True


class DeviceResponse(BaseModel):
    id: str
    name: str
    manufacturer: str
    model: str
    android_version: str
    color: str
    appearance: str
    security_status: str
    risk_score: int
    active_threats_count: int
    battery_level: int
    wifi_status: str
    is_isolated: bool
    last_activity: str
    created_at: datetime
    updated_at: datetime
    installed_apps_count: Optional[int] = 0

    class Config:
        from_attributes = True


class DeviceDetailResponse(DeviceResponse):
    applications: List[AppItem] = []


# ============================================================================
# Threat Simulation Schemas
# ============================================================================

class ThreatScenarioRequest(BaseModel):
    device_id: str
    scenario_type: str  # SCENARIO_A_TROJAN, SCENARIO_B_SPYWARE, SCENARIO_C_RANSOMWARE, SCENARIO_D_ADWARE, SCENARIO_E_UNKNOWN_APK, SCENARIO_F_BOTNET, SCENARIO_G_BANKING_TROJAN, SCENARIO_H_CUSTOM
    custom_params: Optional[Dict[str, Any]] = None


class SimulationEventResponse(BaseModel):
    id: str
    session_id: Optional[str]
    device_id: str
    app_id: Optional[str]
    event_type: str
    step_number: int
    title: str
    description: str
    severity: str
    timestamp: datetime
    payload: Dict[str, Any] = {}

    class Config:
        from_attributes = True


class SimulationStatusResponse(BaseModel):
    session_id: str
    status: str
    speed: str
    active_scenario: Optional[str]
    total_events: int
    started_at: datetime
    updated_at: datetime


# ============================================================================
# Network Schemas
# ============================================================================

class NetworkEventResponse(BaseModel):
    id: str
    device_id: str
    app_id: Optional[str]
    app_name: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float
    bytes_sent: int
    bytes_received: int
    packet_count: int
    connection_freq: float
    classification: str
    timestamp: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Incident Schemas
# ============================================================================

class IncidentResponse(BaseModel):
    id: str
    device_id: str
    device_name: Optional[str] = None
    app_id: Optional[str]
    title: str
    threat_category: str
    severity: str
    status: str
    ml_prediction: str
    confidence: float
    risk_score: int
    description: str
    recommended_response: str
    resolution_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class IncidentUpdateRequest(BaseModel):
    status: str
    resolution_notes: Optional[str] = None


# ============================================================================
# Blockchain Schemas
# ============================================================================

class AuditBlockResponse(BaseModel):
    block_index: int
    record_id: str
    timestamp: datetime
    event_type: str
    description: str
    device_id: Optional[str]
    incident_id: Optional[str]
    prev_hash: str
    current_hash: str
    nonce: int
    status: str
    data_source: str
    payload: Dict[str, Any] = {}

    class Config:
        from_attributes = True


class BlockchainIntegrityResponse(BaseModel):
    is_valid: bool
    total_blocks: int
    verified_blocks: int
    tampered_block_index: Optional[int] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    last_verification_time: datetime
    latest_hash: Optional[str] = None


class TamperDemoResponse(BaseModel):
    success: bool
    tampered_block_index: int
    original_prediction: str
    altered_prediction: str
    message: str
    is_isolated_test_copy: bool


# ============================================================================
# Machine Learning Schemas
# ============================================================================

class MLPredictionResponse(BaseModel):
    prediction: str  # Normal, Suspicious, Malicious
    confidence: float
    risk_score: int
    scenario_ground_truth: Optional[str] = None
    matched_scenario: bool
    contributing_features: List[Dict[str, Any]] = []
    explanation: str
    model_version: str
    timestamp: datetime


class MLModelMetricsResponse(BaseModel):
    model_name: str
    algorithm: str
    training_dataset: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: List[List[int]]
    classes: List[str]
    feature_importances: List[Dict[str, Any]]
    trained_at: str


# ============================================================================
# Overview Dashboard & Notification Schemas
# ============================================================================

class NotificationResponse(BaseModel):
    id: str
    title: str
    message: str
    severity: str
    device_id: Optional[str]
    incident_id: Optional[str]
    is_read: bool
    timestamp: datetime

    class Config:
        from_attributes = True


class OverviewStats(BaseModel):
    total_devices: int
    protected_devices: int
    infected_devices: int
    at_risk_devices: int
    total_incidents: int
    critical_threats: int
    network_events_count: int
    blockchain_blocks_count: int
    simulation_status: str
    ml_status: str
    blockchain_status: str
    database_status: str

