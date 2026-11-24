"""
Virtual Devices API Router for CyberNex.
Handles device creation (Single, Add 2 Devices, Presets), listing, inspection,
application queries, isolation, scanning, and removal.
"""

import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import InstalledApp, VirtualDevice
from backend.schemas import (
    AppItem,
    DeviceCreate,
    DeviceDetailResponse,
    DeviceQuickCreate,
    DeviceResponse,
)
from backend.simulation_engine import simulation_engine

router = APIRouter(prefix="/api/devices", tags=["Virtual Devices"])


@router.get("", response_model=List[DeviceResponse])
def list_devices(db: Session = Depends(get_db)):
    """List all active virtual Android devices with telemetry stats."""
    simulation_engine.seed_initial_state(db)
    devices = db.query(VirtualDevice).order_by(VirtualDevice.created_at.desc()).all()
    results = []
    for d in devices:
        item = DeviceResponse.from_orm(d)
        item.installed_apps_count = len(d.applications)
        results.append(item)
    return results


@router.post("", response_model=DeviceResponse)
def create_device(payload: DeviceCreate, db: Session = Depends(get_db)):
    """Create a single virtual Android device with custom profile."""
    dev = simulation_engine.create_device(
        db=db,
        name=payload.name,
        manufacturer=payload.manufacturer,
        model=payload.model,
        android_version=payload.android_version,
        color=payload.color or "#06B6D4",
        appearance=payload.appearance or "titanium-dark",
        initial_security_profile=payload.initial_security_profile or "STANDARD"
    )
    res = DeviceResponse.from_orm(dev)
    res.installed_apps_count = len(dev.applications)
    return res


@router.post("/quick-add", response_model=List[DeviceResponse])
def quick_add_devices(payload: DeviceQuickCreate, db: Session = Depends(get_db)):
    """
    Quick action to add 1, 2, or multiple separate virtual Android devices.
    When count=2, creates exactly two distinct devices with independent state.
    """
    presets = [
        ("Samsung Galaxy S24 Ultra", "Samsung", "Galaxy S24 Ultra", "14", "#06B6D4", "titanium-dark"),
        ("Google Pixel 9 Pro", "Google", "Pixel 9 Pro", "15", "#8B5CF6", "obsidian-slate"),
        ("OnePlus 12 5G", "OnePlus", "OnePlus 12", "14", "#10B981", "emerald-glass"),
        ("Xiaomi 14 Pro", "Xiaomi", "Xiaomi 14 Pro", "14", "#F59E0B", "carbon-black"),
        ("Nothing Phone (2)", "Nothing", "Phone (2)", "14", "#F43F5E", "glyph-white")
    ]

    created = []
    for i in range(payload.count):
        preset = presets[i % len(presets)]
        dev_name = f"{preset[0]} — Lab #{len(db.query(VirtualDevice).all()) + 1}"
        d = simulation_engine.create_device(
            db=db,
            name=dev_name,
            manufacturer=preset[1],
            model=preset[2],
            android_version=preset[3],
            color=preset[4],
            appearance=preset[5]
        )
        res = DeviceResponse.from_orm(d)
        res.installed_apps_count = len(d.applications)
        created.append(res)

    return created


@router.get("/{device_id}", response_model=DeviceDetailResponse)
def get_device_details(device_id: str, db: Session = Depends(get_db)):
    """Retrieve an individual virtual device's detailed security workspace."""
    dev = db.query(VirtualDevice).filter(VirtualDevice.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found.")

    res = DeviceDetailResponse.from_orm(dev)
    res.installed_apps_count = len(dev.applications)
    app_items = []
    for a in dev.applications:
        perms = []
        try:
            perms = json.loads(a.permissions_json) if a.permissions_json else []
        except Exception:
            perms = []
        app_items.append(AppItem(
            id=a.id,
            package_name=a.package_name,
            app_name=a.app_name,
            category=a.category,
            version=a.version,
            install_source=a.install_source,
            is_system=a.is_system,
            is_sideloaded=a.is_sideloaded,
            is_quarantined=a.is_quarantined,
            risk_score=a.risk_score,
            security_classification=a.security_classification,
            permissions=perms,
            background_activity=a.background_activity,
            network_activity=a.network_activity
        ))
    res.applications = app_items
    return res


@router.post("/{device_id}/isolate")
def isolate_device(device_id: str, db: Session = Depends(get_db)):
    """Isolate virtual device from simulated network."""
    return simulation_engine.isolate_device(db, device_id)


@router.post("/{device_id}/reset")
def reset_device(device_id: str, db: Session = Depends(get_db)):
    """Reset virtual device to clean baseline profile while preserving audit history."""
    return simulation_engine.reset_device_simulation(db, device_id)


@router.post("/{device_id}/scan")
def scan_device(device_id: str, db: Session = Depends(get_db)):
    """Execute full diagnostic security scan on virtual device."""
    return simulation_engine.run_device_scan(db, device_id)


@router.delete("/{device_id}")
def delete_device(device_id: str, db: Session = Depends(get_db)):
    """Remove a virtual Android device and log deletion to the blockchain ledger."""
    dev = db.query(VirtualDevice).filter(VirtualDevice.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found.")

    dev_name = dev.name
    db.delete(dev)
    db.commit()
    return {"success": True, "message": f"Virtual device '{dev_name}' removed."}

