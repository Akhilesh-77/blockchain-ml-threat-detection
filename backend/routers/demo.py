"""
Guided Demonstration Router for CyberNex.
Implements the 10-step academic verification demo workflow.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import (
    InstalledApp,
    NetworkEvent,
    Notification,
    SecurityIncident,
    SimulationEvent,
    VirtualDevice,
)
from backend.simulation_engine import simulation_engine

router = APIRouter(prefix="/api/demo", tags=["Guided Demo Mode"])


@router.post("/start")
def start_demo(db: Session = Depends(get_db)):
    """
    Execute the complete 10-step guided demonstration:
    1. Ensure two separate virtual devices exist.
    2. Generate normal simulated activity on Device 01.
    3. Trigger simulated Trojan attack scenario on Device 02.
    4. Run ML inference on both devices.
    5. Generate incident and notifications.
    6. Mine blockchain audit blocks.
    7. Return complete side-by-side comparison report!
    """
    devices = db.query(VirtualDevice).all()
    if len(devices) < 2:
        dev1, dev2 = simulation_engine.create_two_devices(db)
    else:
        dev1, dev2 = devices[0], devices[1]

    # Step A: Normal activity on Device 1
    normal_events = simulation_engine.generate_normal_activity(db, dev1.id)

    # Step B: Attack simulation on Device 2
    attack_res = simulation_engine.run_threat_scenario(
        db=db,
        device_id=dev2.id,
        scenario_type="SCENARIO_A_TROJAN"
    )

    db.refresh(dev1)
    db.refresh(dev2)

    return {
        "success": True,
        "message": "CyberNex Guided Demonstration successfully executed across two devices!",
        "device_1": {
            "id": dev1.id,
            "name": dev1.name,
            "status": dev1.security_status,
            "risk_score": dev1.risk_score,
            "activity": dev1.last_activity,
            "normal_flows_generated": len(normal_events)
        },
        "device_2": {
            "id": dev2.id,
            "name": dev2.name,
            "status": dev2.security_status,
            "risk_score": dev2.risk_score,
            "attack_scenario": attack_res["scenario"],
            "ml_prediction": attack_res["ml_prediction"],
            "ml_confidence": attack_res["ml_confidence"],
            "incident_id": attack_res["incident_id"],
            "blockchain_block": attack_res["blockchain_block_index"],
            "blockchain_hash": attack_res["blockchain_hash"]
        }
    }


@router.post("/reset")
def reset_demo(db: Session = Depends(get_db)):
    """Reset both devices to baseline state while preserving audit ledger."""
    devices = db.query(VirtualDevice).all()
    for d in devices:
        simulation_engine.reset_device_simulation(db, d.id)
    return {"success": True, "message": "Demo devices reset to clean baseline."}

