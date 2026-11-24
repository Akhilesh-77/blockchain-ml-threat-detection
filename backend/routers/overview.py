"""
CyberNex Overview Dashboard and Notifications Router.
Calculates authentic KPI metrics and returns system status.
"""

from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import (
    AuditBlock,
    NetworkEvent,
    Notification,
    SecurityIncident,
    VirtualDevice,
)
from backend.schemas import NotificationResponse, OverviewStats
from backend.ml_service import ml_service
from backend.blockchain_service import blockchain_service

router = APIRouter(prefix="/api/overview", tags=["Overview Dashboard"])


@router.get("/stats", response_model=OverviewStats)
def get_overview_stats(db: Session = Depends(get_db)):
    """Retrieve real-time consolidated SOC statistics computed from persisted records."""
    total_devices = db.query(VirtualDevice).count()
    protected_devices = db.query(VirtualDevice).filter(VirtualDevice.security_status == "SECURE").count()
    infected_devices = db.query(VirtualDevice).filter(VirtualDevice.security_status == "INFECTED").count()
    at_risk_devices = db.query(VirtualDevice).filter(VirtualDevice.security_status.in_(["SUSPICIOUS", "AT_RISK"])).count()

    total_incidents = db.query(SecurityIncident).count()
    critical_threats = db.query(SecurityIncident).filter(SecurityIncident.severity == "CRITICAL").count()
    net_events = db.query(NetworkEvent).count()
    blockchain_blocks = db.query(AuditBlock).count()

    # Blockchain health
    ver = blockchain_service.verify_chain(db)
    blockchain_status = "HEALTHY" if ver["is_valid"] else "INTEGRITY_WARNING"

    return OverviewStats(
        total_devices=total_devices,
        protected_devices=protected_devices,
        infected_devices=infected_devices,
        at_risk_devices=at_risk_devices,
        total_incidents=total_incidents,
        critical_threats=critical_threats,
        network_events_count=net_events,
        blockchain_blocks_count=blockchain_blocks,
        simulation_status="RUNNING",
        ml_status="READY" if ml_service.is_ready else "UNAVAILABLE",
        blockchain_status=blockchain_status,
        database_status="CONNECTED"
    )


@router.get("/notifications", response_model=List[NotificationResponse])
def get_notifications(limit: int = 20, db: Session = Depends(get_db)):
    """Retrieve system security alerts and notifications."""
    notifs = db.query(Notification).order_by(Notification.timestamp.desc()).limit(limit).all()
    return notifs


@router.post("/notifications/read-all")
def mark_all_notifications_read(db: Session = Depends(get_db)):
    """Mark all unread notifications as read."""
    db.query(Notification).update({Notification.is_read: True})
    db.commit()
    return {"success": True}

