"""
Reporting and Data Export Router for CyberNex.
Generates downloadable CSV and JSON security reports from persisted database records.
"""

from datetime import datetime, timezone
import io
import json
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
import pandas as pd

from backend.database import get_db
from backend.models import (
    AuditBlock,
    InstalledApp,
    NetworkEvent,
    SecurityIncident,
    VirtualDevice,
)

router = APIRouter(prefix="/api/reports", tags=["Forensic Reports & Export"])


@router.get("/incidents.csv")
def export_incidents_csv(db: Session = Depends(get_db)):
    """Export all security incident records as CSV."""
    incidents = db.query(SecurityIncident).order_by(SecurityIncident.created_at.desc()).all()
    rows = []
    for inc in incidents:
        rows.append({
            "Incident_ID": inc.id,
            "Device_ID": inc.device_id,
            "Device_Name": inc.device.name if inc.device else "Unknown",
            "Threat_Category": inc.threat_category,
            "Severity": inc.severity,
            "Status": inc.status,
            "ML_Prediction": inc.ml_prediction,
            "Confidence": inc.confidence,
            "Risk_Score": inc.risk_score,
            "Description": inc.description,
            "Recommended_Response": inc.recommended_response,
            "Created_At": inc.created_at.isoformat()
        })

    df = pd.DataFrame(rows)
    stream = io.StringIO()
    df.to_csv(stream, index=False)
    csv_content = stream.getvalue()

    filename = f"cybernex_security_incidents_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/network.csv")
def export_network_csv(db: Session = Depends(get_db)):
    """Export simulated network traffic flows as CSV."""
    events = db.query(NetworkEvent).order_by(NetworkEvent.timestamp.desc()).limit(500).all()
    rows = []
    for ev in events:
        rows.append({
            "Event_ID": ev.id,
            "Device_ID": ev.device_id,
            "Application": ev.app_name,
            "Source_IP": ev.src_ip,
            "Destination_IP": ev.dst_ip,
            "Source_Port": ev.src_port,
            "Destination_Port": ev.dst_port,
            "Protocol": ev.protocol,
            "Duration_Seconds": ev.duration,
            "Bytes_Sent": ev.bytes_sent,
            "Bytes_Received": ev.bytes_received,
            "Classification": ev.classification,
            "Timestamp": ev.timestamp.isoformat()
        })

    df = pd.DataFrame(rows)
    stream = io.StringIO()
    df.to_csv(stream, index=False)
    csv_content = stream.getvalue()

    filename = f"cybernex_network_flows_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/blockchain.json")
def export_blockchain_json(db: Session = Depends(get_db)):
    """Export full blockchain audit ledger as JSON cryptographic proofs."""
    blocks = db.query(AuditBlock).order_by(AuditBlock.block_index.asc()).all()
    records = []
    for b in blocks:
        try:
            p = json.loads(b.payload_json)
        except Exception:
            p = {}
        records.append({
            "block_index": b.block_index,
            "record_id": b.record_id,
            "timestamp": str(b.timestamp),
            "event_type": b.event_type,
            "description": b.description,
            "device_id": b.device_id,
            "incident_id": b.incident_id,
            "prev_hash": b.prev_hash,
            "current_hash": b.current_hash,
            "nonce": b.nonce,
            "status": b.status,
            "data_source": b.data_source,
            "payload": p
        })

    export_obj = {
        "platform": "CyberNex Security Platform",
        "ledger_type": "SHA-256 Tamper-Evident Hash-Chain",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total_blocks": len(records),
        "chain_valid": True,
        "blocks": records
    }

    content = json.dumps(export_obj, indent=2)
    filename = f"cybernex_blockchain_ledger_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/device/{device_id}.json")
def export_device_audit_json(device_id: str, db: Session = Depends(get_db)):
    """Export full security forensic audit dossier for a single virtual device."""
    dev = db.query(VirtualDevice).filter(VirtualDevice.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found.")

    apps = db.query(InstalledApp).filter(InstalledApp.device_id == device_id).all()
    incidents = db.query(SecurityIncident).filter(SecurityIncident.device_id == device_id).all()
    net = db.query(NetworkEvent).filter(NetworkEvent.device_id == device_id).limit(100).all()

    report = {
        "platform": "CyberNex Android Security Platform",
        "report_type": "DEVICE_FORENSIC_DOSSIER",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "device": {
            "id": dev.id,
            "name": dev.name,
            "manufacturer": dev.manufacturer,
            "model": dev.model,
            "android_version": dev.android_version,
            "security_status": dev.security_status,
            "risk_score": dev.risk_score,
            "is_isolated": dev.is_isolated
        },
        "installed_applications_count": len(apps),
        "applications": [
            {
                "package_name": a.package_name,
                "app_name": a.app_name,
                "category": a.category,
                "is_sideloaded": a.is_sideloaded,
                "is_quarantined": a.is_quarantined,
                "risk_score": a.risk_score,
                "security_classification": a.security_classification
            }
            for a in apps
        ],
        "active_incidents": [
            {
                "id": inc.id,
                "threat_category": inc.threat_category,
                "severity": inc.severity,
                "status": inc.status,
                "ml_prediction": inc.ml_prediction,
                "confidence": inc.confidence,
                "description": inc.description
            }
            for inc in incidents
        ],
        "recent_network_flows_count": len(net)
    }

    content = json.dumps(report, indent=2)
    filename = f"cybernex_device_dossier_{dev.id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
