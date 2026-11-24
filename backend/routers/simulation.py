"""
Simulation Router for CyberNex.
Controls attack scenarios A through H, activity generation, and app quarantine.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import InstalledApp, SimulationEvent, VirtualDevice
from backend.schemas import (
    SimulationEventResponse,
    ThreatScenarioRequest,
)
from backend.simulation_engine import simulation_engine

router = APIRouter(prefix="/api/simulation", tags=["Simulation Engine"])


@router.post("/attack")
def trigger_threat_attack(payload: ThreatScenarioRequest, db: Session = Depends(get_db)):
    """
    Trigger an interactive controlled threat scenario (A through H) on a virtual device.
    Executes the complete 14-step workflow:
    Device -> Event Sequence -> ML Detection -> Security Incident -> Blockchain Block.
    """
    try:
        res = simulation_engine.run_threat_scenario(
            db=db,
            device_id=payload.device_id,
            scenario_type=payload.scenario_type,
            custom_params=payload.custom_params
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/generate-activity/{device_id}")
def generate_normal_activity(device_id: str, db: Session = Depends(get_db)):
    """Generate normal simulated application and browsing telemetry on a device."""
    events = simulation_engine.generate_normal_activity(db, device_id)
    return {
        "success": True,
        "device_id": device_id,
        "generated_events_count": len(events),
        "message": f"Generated {len(events)} normal simulated network flows."
    }


@router.post("/quarantine-app/{app_id}")
def quarantine_application(app_id: str, db: Session = Depends(get_db)):
    """Quarantine a simulated application, halt its background processes, and reduce device risk."""
    try:
        return simulation_engine.quarantine_app(db, app_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/events/{device_id}")
def get_simulation_events(device_id: str, limit: int = 50, db: Session = Depends(get_db)):
    """Retrieve live simulation event timeline for a device."""
    events = (
        db.query(SimulationEvent)
        .filter(SimulationEvent.device_id == device_id)
        .order_by(SimulationEvent.timestamp.desc())
        .limit(limit)
        .all()
    )
    return events

