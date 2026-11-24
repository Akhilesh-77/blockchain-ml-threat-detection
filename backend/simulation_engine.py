"""
CyberNex Interactive Android Security Simulation Engine.
Implements multi-device management, realistic application inventories,
controlled threat scenarios (A through H), multi-step event sequences,
ML integration, and blockchain audit commits.
"""

from datetime import datetime, timezone
import json
import random
import uuid
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.models import (
    AuditBlock,
    DeviceScan,
    InstalledApp,
    NetworkEvent,
    Notification,
    SecurityIncident,
    SimulationEvent,
    SimulationSession,
    VirtualDevice,
)
from backend.ml_service import ml_service
from backend.blockchain_service import blockchain_service


DEFAULT_APPS_BENIGN = [
    {
        "package_name": "com.android.dialer",
        "app_name": "Phone",
        "category": "Communication",
        "version": "12.4.0",
        "install_source": "System Pre-installed",
        "is_system": True,
        "is_sideloaded": False,
        "permissions": ["android.permission.CALL_PHONE", "android.permission.READ_CONTACTS"],
        "background_activity": "Idle telephony listener",
        "network_activity": "Zero background outbound data"
    },
    {
        "package_name": "com.google.android.apps.messaging",
        "app_name": "Messages",
        "category": "Communication",
        "version": "2024.1.2",
        "install_source": "System Pre-installed",
        "is_system": True,
        "is_sideloaded": False,
        "permissions": ["android.permission.RECEIVE_SMS", "android.permission.READ_SMS"],
        "background_activity": "RCS background sync",
        "network_activity": "Encrypted HTTPS keep-alives"
    },
    {
        "package_name": "com.android.chrome",
        "app_name": "Chrome Browser",
        "category": "Browsing",
        "version": "122.0.6261",
        "install_source": "Google Play Store",
        "is_system": False,
        "is_sideloaded": False,
        "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"],
        "background_activity": "Tab cache standby",
        "network_activity": "TLS 1.3 web sessions"
    },
    {
        "package_name": "com.google.android.apps.maps",
        "app_name": "Google Maps",
        "category": "Navigation",
        "version": "11.118.0",
        "install_source": "Google Play Store",
        "is_system": False,
        "is_sideloaded": False,
        "permissions": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"],
        "background_activity": "Location cache sync",
        "network_activity": "Map tile retrieval"
    },
    {
        "package_name": "com.google.android.gm",
        "app_name": "Gmail",
        "category": "Productivity",
        "version": "2024.02.18",
        "install_source": "Google Play Store",
        "is_system": False,
        "is_sideloaded": False,
        "permissions": ["android.permission.GET_ACCOUNTS", "android.permission.READ_CONTACTS"],
        "background_activity": "IMAP push listener",
        "network_activity": "Encrypted email synchronization"
    },
    {
        "package_name": "com.securebank.mobile",
        "app_name": "CyberBank Mobile",
        "category": "Finance",
        "version": "4.12.0",
        "install_source": "Google Play Store",
        "is_system": False,
        "is_sideloaded": False,
        "permissions": ["android.permission.INTERNET", "android.permission.USE_BIOMETRIC"],
        "background_activity": "Secure enclave session",
        "network_activity": "Mutual TLS API connection"
    },
    {
        "package_name": "com.socialhub.app",
        "app_name": "SocialNet",
        "category": "Social",
        "version": "310.0.1",
        "install_source": "Google Play Store",
        "is_system": False,
        "is_sideloaded": False,
        "permissions": ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.READ_MEDIA_IMAGES"],
        "background_activity": "Push notification receiver",
        "network_activity": "Media feed streaming"
    },
    {
        "package_name": "com.android.camera",
        "app_name": "Camera",
        "category": "Media",
        "version": "5.2.0",
        "install_source": "System Pre-installed",
        "is_system": True,
        "is_sideloaded": False,
        "permissions": ["android.permission.CAMERA", "android.permission.RECORD_AUDIO"],
        "background_activity": "Suspended",
        "network_activity": "Zero network calls"
    },
    {
        "package_name": "com.android.settings",
        "app_name": "Settings",
        "category": "System",
        "version": "14.0",
        "install_source": "System Pre-installed",
        "is_system": True,
        "is_sideloaded": False,
        "permissions": [],
        "background_activity": "OS configuration controller",
        "network_activity": "Zero network calls"
    }
]


SCENARIO_CATALOG = {
    "SCENARIO_A_TROJAN": {
        "name": "Trojan Simulation",
        "app_name": "FastBoost RAM Cleaner",
        "package_name": "org.cleaner.fastbooster",
        "category": "Trojan Horse",
        "severity": "HIGH",
        "dst_ip": "198.51.100.199",
        "dst_port": 8443,
        "description": "Deceptive utility application establishing covert Command & Control (C2) channel and requesting accessibility privileges.",
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET"
        ],
        "recommended": "Quarantine application immediately and review granted accessibility permissions."
    },
    "SCENARIO_B_SPYWARE": {
        "name": "Spyware Simulation",
        "app_name": "Device Battery Saver X",
        "package_name": "com.battery.saverpro",
        "category": "Spyware",
        "severity": "HIGH",
        "dst_ip": "203.0.113.88",
        "dst_port": 9001,
        "description": "Unauthorized background surveillance accessing microphone recordings and persistent GPS geolocation.",
        "permissions": [
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_CALL_LOG"
        ],
        "recommended": "Revoke microphone and background location access. Isolate device if exfiltration persists."
    },
    "SCENARIO_C_RANSOMWARE": {
        "name": "Ransomware Simulation",
        "app_name": "System Security Patch",
        "package_name": "com.android.syslock.patch",
        "category": "Ransomware",
        "severity": "CRITICAL",
        "dst_ip": "198.51.100.66",
        "dst_port": 4444,
        "description": "Simulated ransomware locker abusing Device Administrator rights and triggering mass file modification events.",
        "permissions": [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.WRITE_EXTERNAL_STORAGE"
        ],
        "recommended": "Revoke Device Admin privileges immediately, isolate virtual device from network, and terminate payload."
    },
    "SCENARIO_D_ADWARE": {
        "name": "Adware Simulation",
        "app_name": "BrightFlash Torch HD",
        "package_name": "com.flashlight.brightads",
        "category": "Adware",
        "severity": "MEDIUM",
        "dst_ip": "192.0.2.77",
        "dst_port": 8080,
        "description": "Aggressive ad-fraud payload triggering excessive full-screen popups and high-frequency background ad telemetry.",
        "permissions": [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.INTERNET"
        ],
        "recommended": "Uninstall unverified application and revoke overlay display permission."
    },
    "SCENARIO_E_UNKNOWN_APK": {
        "name": "Suspicious APK Installation",
        "app_name": "FreeGame Modded VIP",
        "package_name": "com.modded.vipgame",
        "category": "APK Dropper",
        "severity": "HIGH",
        "dst_ip": "198.51.100.12",
        "dst_port": 80,
        "description": "Unverified sideloaded APK from third-party browser containing secondary payload dropper capabilities.",
        "permissions": [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.READ_PHONE_STATE"
        ],
        "recommended": "Block unknown sources installations in Android security settings and remove installer package."
    },
    "SCENARIO_F_BOTNET": {
        "name": "Botnet-like Activity",
        "app_name": "Background Cloud Syncer",
        "package_name": "net.cloudsync.agent",
        "category": "Botnet Activity",
        "severity": "HIGH",
        "dst_ip": "198.51.100.250",
        "dst_port": 6667,
        "description": "High-frequency automated beaconing to remote synchronization endpoints matching DDoS botnet staging patterns.",
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.RECEIVE_BOOT_COMPLETED"
        ],
        "recommended": "Isolate virtual device to halt outbound beaconing and inspect associated application processes."
    },
    "SCENARIO_G_BANKING_TROJAN": {
        "name": "Banking Trojan Simulation",
        "app_name": "Bank Token Authenticator",
        "package_name": "com.auth.banktoken",
        "category": "Banking Trojan",
        "severity": "CRITICAL",
        "dst_ip": "203.0.113.150",
        "dst_port": 8443,
        "description": "Credential theft trojan attempting tapjacking overlay over legitimate banking apps and intercepting 2FA SMS tokens.",
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS"
        ],
        "recommended": "Revoke Accessibility Service and SMS permissions immediately. Quarantine application."
    },
    "SCENARIO_H_CUSTOM": {
        "name": "Custom Threat Scenario",
        "app_name": "Custom Payload App",
        "package_name": "org.custom.threatsim",
        "category": "Custom Anomaly",
        "severity": "HIGH",
        "dst_ip": "198.51.100.99",
        "dst_port": 443,
        "description": "User-configured threat scenario testing custom permission combinations and behavioral anomalies.",
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.INTERNET"
        ],
        "recommended": "Review custom scenario logs and evaluate detection rules."
    }
}


class SimulationEngine:
    """Orchestrates virtual Android device state, scenarios, ML inference, and blockchain audits."""

    @staticmethod
    def seed_initial_state(db: Session):
        """Seed default 2 devices and blockchain genesis if database is empty."""
        blockchain_service.ensure_genesis_block(db)
        count = db.query(VirtualDevice).count()
        if count == 0:
            SimulationEngine.create_two_devices(db)

    @staticmethod
    def create_device(
        db: Session,
        name: str,
        manufacturer: str,
        model: str,
        android_version: str,
        color: str = "#06B6D4",
        appearance: str = "titanium-dark",
        initial_security_profile: str = "STANDARD"
    ) -> VirtualDevice:
        """Create a single virtual Android device with its independent application inventory."""
        dev_id = f"VDEV-{uuid.uuid4().hex[:8].upper()}"
        dev = VirtualDevice(
            id=dev_id,
            name=name,
            manufacturer=manufacturer,
            model=model,
            android_version=android_version,
            color=color,
            appearance=appearance,
            security_status="SECURE",
            risk_score=6,
            active_threats_count=0,
            battery_level=random.randint(75, 98),
            wifi_status="CONNECTED",
            is_isolated=False,
            last_activity="Virtual device initialized with baseline OS image"
        )
        db.add(dev)
        db.flush()

        # Seed benign applications for this device
        for app_spec in DEFAULT_APPS_BENIGN:
            app = InstalledApp(
                id=f"APP-{uuid.uuid4().hex[:8].upper()}",
                device_id=dev.id,
                package_name=app_spec["package_name"],
                app_name=app_spec["app_name"],
                category=app_spec["category"],
                version=app_spec["version"],
                install_source=app_spec["install_source"],
                is_system=app_spec["is_system"],
                is_sideloaded=app_spec["is_sideloaded"],
                is_quarantined=False,
                risk_score=0,
                security_classification="SAFE",
                permissions_json=json.dumps(app_spec["permissions"]),
                background_activity=app_spec["background_activity"],
                network_activity=app_spec["network_activity"]
            )
            db.add(app)

        # Audit Block
        blockchain_service.record_event(
            db=db,
            event_type="VIRTUAL_DEVICE_CREATED",
            description=f"Created virtual Android device '{name}' ({manufacturer} {model}, Android {android_version})",
            payload={
                "device_id": dev.id,
                "name": name,
                "manufacturer": manufacturer,
                "model": model,
                "android_version": android_version,
                "initial_security_profile": initial_security_profile,
                "installed_apps_count": len(DEFAULT_APPS_BENIGN)
            },
            device_id=dev.id
        )

        db.commit()
        db.refresh(dev)
        return dev

    @staticmethod
    def create_two_devices(db: Session) -> Tuple[VirtualDevice, VirtualDevice]:
        """Create exactly two separate, independent virtual Android devices."""
        dev1 = SimulationEngine.create_device(
            db=db,
            name="Samsung Galaxy S24 Ultra — Alpha Lab",
            manufacturer="Samsung",
            model="Galaxy S24 Ultra",
            android_version="14",
            color="#06B6D4",
            appearance="titanium-dark"
        )

        dev2 = SimulationEngine.create_device(
            db=db,
            name="Google Pixel 8 Pro — Beta Lab",
            manufacturer="Google",
            model="Pixel 8 Pro",
            android_version="15",
            color="#8B5CF6",
            appearance="obsidian-slate"
        )

        return dev1, dev2

    @staticmethod
    def generate_normal_activity(db: Session, device_id: str) -> List[NetworkEvent]:
        """Generate benign simulated browsing and application telemetry."""
        dev = db.query(VirtualDevice).filter(VirtualDevice.id == device_id).first()
        if not dev or dev.is_isolated:
            return []

        endpoints = [
            ("142.250.190.46", "www.google.com", 443, "Chrome Browser"),
            ("172.217.16.206", "maps.googleapis.com", 443, "Google Maps"),
            ("104.244.42.1", "api.socialnet.com", 443, "SocialNet"),
            ("198.51.100.22", "api.cyberbank.internal", 443, "CyberBank Mobile")
        ]

        events = []
        for dst_ip, host, port, app_name in endpoints:
            dur = round(random.uniform(0.4, 2.5), 2)
            b_sent = random.randint(800, 4500)
            b_recv = random.randint(3000, 45000)
            pkts = random.randint(12, 60)

            evt = NetworkEvent(
                id=f"NET-{uuid.uuid4().hex[:8].upper()}",
                device_id=dev.id,
                app_name=app_name,
                src_ip="192.168.1.105",
                dst_ip=dst_ip,
                src_port=random.randint(49152, 65530),
                dst_port=port,
                protocol="TLS 1.3 / TCP",
                duration=dur,
                bytes_sent=b_sent,
                bytes_received=b_recv,
                packet_count=pkts,
                connection_freq=1.0,
                classification="NORMAL"
            )
            db.add(evt)
            events.append(evt)

        dev.last_activity = f"Generated legitimate browsing & API traffic across {len(events)} endpoints"
        dev.updated_at = datetime.now(timezone.utc)
        db.commit()
        return events

    @staticmethod
    def run_threat_scenario(
        db: Session,
        device_id: str,
        scenario_type: str,
        custom_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute the full 14-step threat attack simulation.
        Injects malicious apps/behavior, generates network flows, triggers ML detection,
        creates security incidents, and commits to the blockchain ledger.
        """
        dev = db.query(VirtualDevice).filter(VirtualDevice.id == device_id).first()
        if not dev:
            raise ValueError(f"Device {device_id} not found.")

        scenario_meta = dict(SCENARIO_CATALOG)
        if scenario_type == "SCENARIO_H_CUSTOM" and custom_params:
            scenario_meta["SCENARIO_H_CUSTOM"] = {
                "name": custom_params.get("name", "Custom Threat Scenario"),
                "app_name": custom_params.get("app_name", "Custom Payload App"),
                "package_name": "org.custom.threatsim",
                "category": custom_params.get("category", "Custom Anomaly"),
                "severity": custom_params.get("severity", "HIGH"),
                "dst_ip": "198.51.100.99",
                "dst_port": 443,
                "description": "User-configured threat scenario testing custom permission combinations and behavioral anomalies.",
                "permissions": [
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.INTERNET"
                ],
                "recommended": "Review custom scenario logs and evaluate detection rules."
            }

        spec = scenario_meta.get(scenario_type, scenario_meta["SCENARIO_A_TROJAN"])
        now = datetime.now(timezone.utc)

        # Step 1-3: Generate Simulation Events sequence
        steps = [
            ("APP_INSTALL", f"Sideloaded unverified APK: '{spec['app_name']}' from untrusted source"),
            ("PERMISSION_REQUEST", f"Application requested sensitive privileges: {', '.join(spec['permissions'])}"),
            ("BACKGROUND_EXECUTION", f"Process launched persistent daemon thread without foreground notification"),
            ("NETWORK_ANOMALY", f"Outbound socket opened to suspicious endpoint {spec['dst_ip']}:{spec['dst_port']}"),
            ("SUSPICIOUS_BEHAVIOR", spec["description"])
        ]

        sim_events = []
        for i, (ev_type, ev_desc) in enumerate(steps, 1):
            sev = spec["severity"] if i >= 4 else "INFORMATIONAL"
            sim_ev = SimulationEvent(
                id=f"EVT-{uuid.uuid4().hex[:8].upper()}",
                device_id=dev.id,
                event_type=ev_type,
                step_number=i,
                title=f"Step {i}: {ev_type.replace('_', ' ').title()}",
                description=ev_desc,
                severity=sev,
                payload_json=json.dumps({"scenario": spec["name"], "step": i}),
                timestamp=now
            )
            db.add(sim_ev)
            sim_events.append(sim_ev)

        # Step 4-5: Add or update suspicious application
        app_id = f"APP-{uuid.uuid4().hex[:8].upper()}"
        mal_app = InstalledApp(
            id=app_id,
            device_id=dev.id,
            package_name=spec["package_name"],
            app_name=spec["app_name"],
            category=spec["category"],
            version="1.0.0",
            install_source="Sideloaded / Unknown Source",
            is_system=False,
            is_sideloaded=True,
            is_quarantined=False,
            risk_score=92 if spec["severity"] == "CRITICAL" else 78,
            security_classification="HIGH RISK" if spec["severity"] in ["CRITICAL", "HIGH"] else "SUSPICIOUS",
            permissions_json=json.dumps(spec["permissions"]),
            background_activity="Abnormal continuous loop / Service Hook",
            network_activity=f"Encrypted tunnel to {spec['dst_ip']}:{spec['dst_port']}"
        )
        db.add(mal_app)

        # Step 6: Generate associated Network Events
        net_ev = NetworkEvent(
            id=f"NET-{uuid.uuid4().hex[:8].upper()}",
            device_id=dev.id,
            app_id=app_id,
            app_name=spec["app_name"],
            src_ip="192.168.1.105",
            dst_ip=spec["dst_ip"],
            src_port=random.randint(50000, 64000),
            dst_port=spec["dst_port"],
            protocol="TLS 1.3 / TCP",
            duration=0.35,
            bytes_sent=18500,
            bytes_received=3200,
            packet_count=45,
            connection_freq=18.5,
            classification="MALICIOUS" if spec["severity"] == "CRITICAL" else "SUSPICIOUS",
            timestamp=now
        )
        db.add(net_ev)

        # Step 7-9: Extract Features and Run ML Prediction
        features = ml_service.extract_features(
            app_permissions_count=len(spec["permissions"]),
            critical_permissions_count=len([p for p in spec["permissions"] if "ACCESSIBILITY" in p or "ADMIN" in p or "ALERT" in p]),
            is_sideloaded=True,
            connection_duration=0.35,
            packet_count=45,
            bytes_sent=18500,
            bytes_received=3200,
            is_anomaly=True
        )
        ml_result = ml_service.predict(features, scenario_ground_truth=spec["name"])

        # Step 10: Create Security Incident
        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        incident = SecurityIncident(
            id=inc_id,
            device_id=dev.id,
            app_id=app_id,
            title=f"Simulated {spec['name']} Detected on {dev.name}",
            threat_category=spec["category"],
            severity=spec["severity"],
            status="OPEN",
            ml_prediction=ml_result["prediction"],
            confidence=ml_result["confidence"],
            risk_score=ml_result["risk_score"],
            description=spec["description"],
            recommended_response=spec["recommended"],
            created_at=now
        )
        db.add(incident)

        # Step 11: Create Notification
        notif = Notification(
            id=f"NOTIF-{uuid.uuid4().hex[:8].upper()}",
            title=f"🚨 Threat Alert: {spec['name']}",
            message=f"{spec['app_name']} on {dev.name} classified as {ml_result['prediction']} ({ml_result['confidence']*100:.1f}% confidence)",
            severity="CRITICAL" if spec["severity"] == "CRITICAL" else "WARNING",
            device_id=dev.id,
            incident_id=inc_id,
            is_read=False,
            timestamp=now
        )
        db.add(notif)

        # Step 12: Commit to Blockchain Ledger
        block = blockchain_service.record_event(
            db=db,
            event_type="THREAT_ATTACK_SIMULATION",
            description=f"Simulated attack '{spec['name']}' analyzed on {dev.name}. Result: {ml_result['prediction']}",
            payload={
                "device_id": dev.id,
                "incident_id": inc_id,
                "scenario_type": scenario_type,
                "scenario_ground_truth": spec["name"],
                "app_name": spec["app_name"],
                "package_name": spec["package_name"],
                "ml_prediction": ml_result["prediction"],
                "ml_confidence": ml_result["confidence"],
                "risk_score": ml_result["risk_score"],
                "mitre_technique": "T1452" if "ACCESSIBILITY" in str(spec["permissions"]) else "T1453"
            },
            device_id=dev.id,
            incident_id=inc_id
        )

        # Step 13: Update Device State
        dev.security_status = "INFECTED" if spec["severity"] == "CRITICAL" else "AT_RISK"
        dev.risk_score = ml_result["risk_score"]
        dev.active_threats_count += 1
        dev.last_activity = f"Threat incident active: {spec['name']} detected"
        dev.updated_at = now

        db.commit()

        return {
            "success": True,
            "device_id": dev.id,
            "device_name": dev.name,
            "scenario": spec["name"],
            "application": spec["app_name"],
            "incident_id": inc_id,
            "blockchain_block_index": block.block_index,
            "blockchain_hash": block.current_hash,
            "ml_prediction": ml_result["prediction"],
            "ml_confidence": ml_result["confidence"],
            "risk_score": ml_result["risk_score"],
            "explanation": ml_result["explanation"],
            "sim_events_count": len(sim_events),
            "new_device_status": dev.security_status
        }

    @staticmethod
    def quarantine_app(db: Session, app_id: str) -> Dict[str, Any]:
        """Quarantine a simulated application and mitigate device risk."""
        app = db.query(InstalledApp).filter(InstalledApp.id == app_id).first()
        if not app:
            raise ValueError(f"Application {app_id} not found.")

        app.is_quarantined = True
        app.background_activity = "HALTED (Process Terminated by CyberNex SOC)"
        app.network_activity = "BLOCKED by Firewall Rule"

        dev = db.query(VirtualDevice).filter(VirtualDevice.id == app.device_id).first()
        if dev:
            dev.active_threats_count = max(0, dev.active_threats_count - 1)
            dev.risk_score = max(5, dev.risk_score - 40)
            if dev.active_threats_count == 0:
                dev.security_status = "MONITORING"
            dev.last_activity = f"Application '{app.app_name}' quarantined"

        # Record in blockchain
        block = blockchain_service.record_event(
            db=db,
            event_type="APPLICATION_QUARANTINED",
            description=f"Simulated app '{app.app_name}' quarantined on device {dev.name if dev else app.device_id}",
            payload={
                "app_id": app.id,
                "package_name": app.package_name,
                "device_id": app.device_id,
                "remediation": "Process suspended, permissions revoked, network socket blocked"
            },
            device_id=app.device_id
        )

        db.commit()
        return {
            "success": True,
            "app_id": app.id,
            "app_name": app.app_name,
            "is_quarantined": True,
            "device_status": dev.security_status if dev else "UNKNOWN",
            "block_index": block.block_index
        }

    @staticmethod
    def isolate_device(db: Session, device_id: str) -> Dict[str, Any]:
        """Isolate a virtual device from the simulated network to stop lateral spread."""
        dev = db.query(VirtualDevice).filter(VirtualDevice.id == device_id).first()
        if not dev:
            raise ValueError(f"Device {device_id} not found.")

        dev.is_isolated = True
        dev.wifi_status = "ISOLATED"
        dev.security_status = "ISOLATED"
        dev.last_activity = "Device isolated from simulated network environment"

        block = blockchain_service.record_event(
            db=db,
            event_type="DEVICE_ISOLATED",
            description=f"Virtual device '{dev.name}' isolated from network",
            payload={"device_id": dev.id, "action": "Network Isolation Enforced"},
            device_id=dev.id
        )

        db.commit()
        return {"success": True, "device_id": dev.id, "is_isolated": True, "block_index": block.block_index}

    @staticmethod
    def reset_device_simulation(db: Session, device_id: str) -> Dict[str, Any]:
        """Reset virtual device to clean baseline profile while preserving audit history."""
        dev = db.query(VirtualDevice).filter(VirtualDevice.id == device_id).first()
        if not dev:
            raise ValueError(f"Device {device_id} not found.")

        # Remove sideloaded / infected apps
        db.query(InstalledApp).filter(
            InstalledApp.device_id == device_id,
            InstalledApp.is_sideloaded == True
        ).delete()

        # Reset state
        dev.security_status = "SECURE"
        dev.risk_score = 6
        dev.active_threats_count = 0
        dev.is_isolated = False
        dev.wifi_status = "CONNECTED"
        dev.last_activity = "Simulation reset to baseline clean state"

        block = blockchain_service.record_event(
            db=db,
            event_type="SIMULATION_RESET",
            description=f"Virtual device '{dev.name}' simulation reset to clean baseline",
            payload={"device_id": dev.id, "action": "Baseline Profile Restored"},
            device_id=dev.id
        )

        db.commit()
        return {"success": True, "device_id": dev.id, "security_status": "SECURE", "block_index": block.block_index}

    @staticmethod
    def run_device_scan(db: Session, device_id: str) -> Dict[str, Any]:
        """Run full-device diagnostic scan across apps, permissions, and traffic."""
        dev = db.query(VirtualDevice).filter(VirtualDevice.id == device_id).first()
        if not dev:
            raise ValueError(f"Device {device_id} not found.")

        apps = db.query(InstalledApp).filter(InstalledApp.device_id == device_id).all()
        sideloaded = [a for a in apps if a.is_sideloaded and not a.is_quarantined]
        high_risk = [a for a in apps if a.security_classification == "HIGH RISK" and not a.is_quarantined]

        now = datetime.now(timezone.utc)
        if high_risk:
            verdict = "INFECTED" if dev.active_threats_count > 0 else "AT_RISK"
            score = max(75, dev.risk_score)
            recs = ["Quarantine flagged malicious applications", "Revoke Accessibility privileges", "Enforce network isolation"]
        elif sideloaded:
            verdict = "SUSPICIOUS"
            score = 45
            recs = ["Verify installer certificates for sideloaded APKs"]
        else:
            verdict = "SAFE"
            score = 5
            recs = ["Maintain regular automated scans", "Keep system applications updated"]

        scan = DeviceScan(
            id=f"SCAN-{uuid.uuid4().hex[:8].upper()}",
            device_id=dev.id,
            timestamp=now,
            apps_scanned=len(apps),
            suspicious_apps=len(sideloaded),
            high_risk_perms=len(high_risk),
            network_anomalies=1 if high_risk else 0,
            risk_score=score,
            verdict=verdict,
            recommendations_json=json.dumps(recs)
        )
        db.add(scan)

        block = blockchain_service.record_event(
            db=db,
            event_type="DEVICE_SCAN_COMPLETED",
            description=f"Device scan completed for '{dev.name}'. Verdict: {verdict} (Score: {score}/100)",
            payload={
                "device_id": dev.id,
                "scan_id": scan.id,
                "apps_scanned": len(apps),
                "verdict": verdict,
                "risk_score": score
            },
            device_id=dev.id
        )
        scan.block_index = block.block_index

        db.commit()
        return {
            "scan_id": scan.id,
            "device_id": dev.id,
            "apps_scanned": len(apps),
            "suspicious_apps": len(sideloaded),
            "high_risk_perms": len(high_risk),
            "risk_score": score,
            "verdict": verdict,
            "recommendations": recs,
            "block_index": block.block_index,
            "timestamp": now.isoformat()
        }


simulation_engine = SimulationEngine()
