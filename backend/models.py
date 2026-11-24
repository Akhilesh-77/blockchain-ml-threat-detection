"""
SQLAlchemy ORM models for CyberNex.
Comprehensive data models for Virtual Devices, Applications, Events,
Network Flows, Incidents, Blockchain Blocks, Scans, and Reports.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from backend.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class VirtualDevice(Base):
    __tablename__ = "virtual_devices"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    manufacturer = Column(String(64), nullable=False)
    model = Column(String(64), nullable=False)
    android_version = Column(String(16), nullable=False)
    color = Column(String(32), default="#06B6D4")
    appearance = Column(String(32), default="titanium-dark")
    security_status = Column(String(32), default="SECURE")  # SECURE, MONITORING, SUSPICIOUS, AT_RISK, INFECTED, ISOLATED, OFFLINE
    risk_score = Column(Integer, default=5)  # 0 to 100
    active_threats_count = Column(Integer, default=0)
    battery_level = Column(Integer, default=88)
    wifi_status = Column(String(32), default="CONNECTED")
    is_isolated = Column(Boolean, default=False)
    last_activity = Column(String(255), default="System idle, monitoring active")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    applications = relationship("InstalledApp", back_populates="device", cascade="all, delete-orphan")
    network_events = relationship("NetworkEvent", back_populates="device", cascade="all, delete-orphan")
    incidents = relationship("SecurityIncident", back_populates="device", cascade="all, delete-orphan")
    scans = relationship("DeviceScan", back_populates="device", cascade="all, delete-orphan")


class InstalledApp(Base):
    __tablename__ = "installed_applications"

    id = Column(String(64), primary_key=True, index=True)
    device_id = Column(String(64), ForeignKey("virtual_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    package_name = Column(String(255), nullable=False)
    app_name = Column(String(128), nullable=False)
    category = Column(String(64), default="Utilities")
    version = Column(String(32), default="1.0.0")
    install_source = Column(String(64), default="Google Play Store")
    is_system = Column(Boolean, default=False)
    is_sideloaded = Column(Boolean, default=False)
    is_quarantined = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    security_classification = Column(String(32), default="SAFE")  # SAFE, LOW RISK, SUSPICIOUS, HIGH RISK
    permissions_json = Column(Text, default="[]")
    background_activity = Column(String(255), default="Normal background sync")
    network_activity = Column(String(255), default="Periodic HTTPS keep-alive")
    created_at = Column(DateTime, default=utcnow)

    # Relationships
    device = relationship("VirtualDevice", back_populates="applications")

    @property
    def permissions(self) -> list:
        try:
            return json.loads(self.permissions_json) if self.permissions_json else []
        except Exception:
            return []


class SimulationSession(Base):
    __tablename__ = "simulation_sessions"

    id = Column(String(64), primary_key=True, index=True)
    status = Column(String(32), default="RUNNING")  # RUNNING, PAUSED, STOPPED
    speed = Column(String(16), default="NORMAL")    # SLOW, NORMAL, FAST
    active_scenario = Column(String(64), nullable=True)
    total_events = Column(Integer, default=0)
    started_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class SimulationEvent(Base):
    __tablename__ = "simulation_events"

    id = Column(String(64), primary_key=True, index=True)
    session_id = Column(String(64), nullable=True, index=True)
    device_id = Column(String(64), nullable=False, index=True)
    app_id = Column(String(64), nullable=True)
    event_type = Column(String(64), nullable=False)
    step_number = Column(Integer, default=1)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), default="INFORMATIONAL")
    payload_json = Column(Text, default="{}")
    timestamp = Column(DateTime, default=utcnow, index=True)


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(String(64), primary_key=True, index=True)
    device_id = Column(String(64), ForeignKey("virtual_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    app_id = Column(String(64), nullable=True)
    app_name = Column(String(128), default="System")
    src_ip = Column(String(64), default="192.168.1.105")
    dst_ip = Column(String(64), default="104.244.42.1")
    src_port = Column(Integer, default=49152)
    dst_port = Column(Integer, default=443)
    protocol = Column(String(16), default="TLS 1.3 / TCP")
    duration = Column(Float, default=1.2)
    bytes_sent = Column(Integer, default=1240)
    bytes_received = Column(Integer, default=4890)
    packet_count = Column(Integer, default=16)
    connection_freq = Column(Float, default=1.0)
    classification = Column(String(32), default="NORMAL")  # NORMAL, SUSPICIOUS, MALICIOUS
    timestamp = Column(DateTime, default=utcnow, index=True)

    # Relationships
    device = relationship("VirtualDevice", back_populates="network_events")


class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(String(64), primary_key=True, index=True)
    device_id = Column(String(64), ForeignKey("virtual_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    app_id = Column(String(64), nullable=True)
    title = Column(String(255), nullable=False)
    threat_category = Column(String(64), nullable=False)  # Trojan, Spyware, Ransomware, Adware, APK Dropper, Botnet, Banking Trojan
    severity = Column(String(32), default="MEDIUM")       # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(32), default="OPEN")           # OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    ml_prediction = Column(String(32), default="Malicious")
    confidence = Column(Float, default=0.95)
    risk_score = Column(Integer, default=85)
    description = Column(Text, nullable=False)
    recommended_response = Column(Text, nullable=False)
    resolution_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    device = relationship("VirtualDevice", back_populates="incidents")


class AuditBlock(Base):
    __tablename__ = "audit_blocks"

    block_index = Column(Integer, primary_key=True, index=True)
    record_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    description = Column(Text, nullable=False)
    device_id = Column(String(64), nullable=True, index=True)
    incident_id = Column(String(64), nullable=True)
    prev_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False)
    nonce = Column(Integer, default=0)
    payload_json = Column(Text, nullable=False)
    status = Column(String(32), default="VALID")
    data_source = Column(String(32), default="SIMULATION_ENGINE")

    @property
    def payload(self) -> dict:
        try:
            return json.loads(self.payload_json) if self.payload_json else {}
        except Exception:
            return {}


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(32), default="INFO")  # INFO, WARNING, CRITICAL, SUCCESS
    device_id = Column(String(64), nullable=True)
    incident_id = Column(String(64), nullable=True)
    is_read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=utcnow, index=True)


class DeviceScan(Base):
    __tablename__ = "device_scans"

    id = Column(String(64), primary_key=True, index=True)
    device_id = Column(String(64), ForeignKey("virtual_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    apps_scanned = Column(Integer, default=0)
    suspicious_apps = Column(Integer, default=0)
    high_risk_perms = Column(Integer, default=0)
    network_anomalies = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    verdict = Column(String(32), default="SAFE")
    recommendations_json = Column(Text, default="[]")
    block_index = Column(Integer, nullable=True)

    # Relationships
    device = relationship("VirtualDevice", back_populates="scans")


class SecurityReport(Base):
    __tablename__ = "security_reports"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    report_type = Column(String(64), default="DEVICE_SECURITY")  # DEVICE_SECURITY, INCIDENT_FORENSIC, BLOCKCHAIN_AUDIT, FULL_SIMULATION
    device_id = Column(String(64), nullable=True)
    incident_id = Column(String(64), nullable=True)
    summary_json = Column(Text, default="{}")
    format = Column(String(16), default="JSON")
    generated_at = Column(DateTime, default=utcnow, index=True)
