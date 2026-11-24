"""
Network Traffic Analysis API Router for CyberNex.
Provides simulated network flows, protocol statistics, endpoint filtering,
and metadata analytics.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db
from backend.models import NetworkEvent, VirtualDevice
from backend.schemas import NetworkEventResponse

router = APIRouter(prefix="/api/network", tags=["Network Analysis"])


@router.get("/events", response_model=List[NetworkEventResponse])
def get_network_events(
    device_id: Optional[str] = None,
    classification: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Retrieve simulated network traffic events with optional device and classification filters."""
    query = db.query(NetworkEvent)
    if device_id:
        query = query.filter(NetworkEvent.device_id == device_id)
    if classification:
        query = query.filter(NetworkEvent.classification == classification)

    events = query.order_by(NetworkEvent.timestamp.desc()).limit(limit).all()
    return events


@router.get("/stats")
def get_network_stats(db: Session = Depends(get_db)):
    """Aggregate simulated traffic statistics, byte distributions, and protocol counts."""
    total_events = db.query(NetworkEvent).count()
    normal_count = db.query(NetworkEvent).filter(NetworkEvent.classification == "NORMAL").count()
    suspicious_count = db.query(NetworkEvent).filter(NetworkEvent.classification == "SUSPICIOUS").count()
    malicious_count = db.query(NetworkEvent).filter(NetworkEvent.classification == "MALICIOUS").count()

    total_bytes_sent = db.query(func.sum(NetworkEvent.bytes_sent)).scalar() or 0
    total_bytes_recv = db.query(func.sum(NetworkEvent.bytes_received)).scalar() or 0

    return {
        "total_flows": total_events,
        "normal_flows": normal_count,
        "suspicious_flows": suspicious_count,
        "malicious_flows": malicious_count,
        "total_bytes_sent": int(total_bytes_sent),
        "total_bytes_received": int(total_bytes_recv),
        "total_bytes": int(total_bytes_sent + total_bytes_recv),
        "protocol_distribution": {
            "TLS 1.3 / TCP": max(1, int(total_events * 0.85)),
            "DNS / UDP (Port 53)": int(total_events * 0.10),
            "DoH / HTTPS (Port 443)": int(total_events * 0.05)
        }
    }

