"""
Security Incidents Management Router for CyberNex.
Handles incident creation, search, filtering, containment, investigation, and resolution.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import SecurityIncident, VirtualDevice
from backend.schemas import IncidentResponse, IncidentUpdateRequest
from backend.blockchain_service import blockchain_service

router = APIRouter(prefix="/api/incidents", tags=["Security Incidents"])


@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    device_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieve security incidents with optional filtering."""
    query = db.query(SecurityIncident)
    if status:
        query = query.filter(SecurityIncident.status == status)
    if severity:
        query = query.filter(SecurityIncident.severity == severity)
    if device_id:
        query = query.filter(SecurityIncident.device_id == device_id)

    incidents = query.order_by(SecurityIncident.created_at.desc()).all()
    results = []
    for inc in incidents:
        item = IncidentResponse.from_orm(inc)
        if inc.device:
            item.device_name = inc.device.name
        results.append(item)
    return results


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Retrieve full incident details."""
    inc = db.query(SecurityIncident).filter(SecurityIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")
    res = IncidentResponse.from_orm(inc)
    if inc.device:
        res.device_name = inc.device.name
    return res


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: str, payload: IncidentUpdateRequest, db: Session = Depends(get_db)):
    """Update incident status (e.g. CONTAINED, RESOLVED, FALSE_POSITIVE) and record in blockchain."""
    inc = db.query(SecurityIncident).filter(SecurityIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")

    old_status = inc.status
    inc.status = payload.status
    if payload.resolution_notes:
        inc.resolution_notes = payload.resolution_notes

    # If resolved, update device active threat count
    if payload.status == "RESOLVED" and old_status != "RESOLVED":
        if inc.device:
            inc.device.active_threats_count = max(0, inc.device.active_threats_count - 1)
            if inc.device.active_threats_count == 0:
                inc.device.security_status = "SECURE"
                inc.device.risk_score = 6

    # Log to blockchain
    blockchain_service.record_event(
        db=db,
        event_type="INCIDENT_STATUS_UPDATED",
        description=f"Incident {inc.id} status changed from {old_status} to {payload.status}",
        payload={
            "incident_id": inc.id,
            "device_id": inc.device_id,
            "old_status": old_status,
            "new_status": payload.status,
            "resolution_notes": payload.resolution_notes or ""
        },
        device_id=inc.device_id,
        incident_id=inc.id
    )

    db.commit()
    db.refresh(inc)
    res = IncidentResponse.from_orm(inc)
    if inc.device:
        res.device_name = inc.device.name
    return res

