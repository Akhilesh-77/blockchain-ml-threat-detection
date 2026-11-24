"""
Automated unit tests for CyberNex Mobile Device Security Subsystem.
Validates ADB device detection, serial anonymization, package permission scanning,
threat classification into risk levels, blockchain audit record creation,
and application rebranding integrity.
"""

import os
from pathlib import Path
import re
import pytest

from mobile.adb_manager import ADBManager, ConnectedDevice, get_adb_manager
from mobile.security_scanner import (
    CRITICAL_ANDROID_PERMISSIONS,
    DeviceSecurityPosture,
    InstalledApp,
    MobileSecurityScanner,
)
from mobile.threat_classifier import (
    DeviceSecurityAssessment,
    MobileThreatClassifier,
    ThreatFinding,
)
from mobile.ios_investigation import get_ios_feasibility_analysis
from blockchain.ledger import BlockchainLedger, get_ledger
from blockchain.verification import verify_chain_integrity
from database.db import DatabaseManager, get_db


@pytest.fixture
def temp_db(tmp_path):
    """Provides an isolated SQLite database manager for testing."""
    test_db_path = tmp_path / "test_mobile.db"
    return DatabaseManager(db_path=test_db_path)


@pytest.fixture
def temp_ledger(temp_db):
    """Provides an isolated blockchain ledger for testing."""
    return BlockchainLedger(db=temp_db)


def test_adb_serial_anonymization():
    """Verify that device serial numbers are hashed into privacy-preserving IDs."""
    raw_serial_1 = "R58M321XYZ9"
    raw_serial_2 = "98877665544"

    anon_1 = ADBManager.anonymize_device_serial(raw_serial_1)
    anon_2 = ADBManager.anonymize_device_serial(raw_serial_2)

    # Must start with DEVICE- prefix
    assert anon_1.startswith("DEVICE-")
    assert anon_2.startswith("DEVICE-")

    # Raw serials must NOT be contained in the hash
    assert raw_serial_1 not in anon_1
    assert raw_serial_2 not in anon_2

    # Deterministic and unique per serial
    assert anon_1 == ADBManager.anonymize_device_serial(raw_serial_1)
    assert anon_1 != anon_2


def test_simulated_devices_enumeration():
    """Verify detection of benchmark simulated Android devices when physical phone is absent."""
    adb = get_adb_manager()
    devices = adb.detect_devices(include_simulated=True)

    assert len(devices) >= 3
    manufacturers = [d.manufacturer for d in devices]
    assert "Google" in manufacturers
    assert "Samsung" in manufacturers

    # Check device fields
    for dev in devices:
        assert dev.device_hash.startswith("DEVICE-")
        assert dev.android_version != "Unknown"
        assert dev.sdk_level > 0
        assert dev.status == "device"


def test_mobile_security_scanner():
    """Verify MobileSecurityScanner collects package inventory and security posture."""
    adb = get_adb_manager()
    scanner = MobileSecurityScanner(adb)
    devices = adb.detect_devices(include_simulated=True)

    samsung_dev = next(d for d in devices if "SAMSUNG" in d.serial)
    posture = scanner.scan_device(samsung_dev)

    assert isinstance(posture, DeviceSecurityPosture)
    assert posture.manufacturer == "Samsung"
    assert posture.model == "Galaxy S23 Ultra"
    assert posture.total_packages > 0
    assert posture.sideloaded_count == 2
    assert len(posture.apps) > 0

    # Verify banking trojan package detection in simulation profile
    trojan_app = next((a for a in posture.apps if "fakebank" in a.package_name), None)
    assert trojan_app is not None
    assert trojan_app.is_sideloaded is True
    assert "android.permission.BIND_ACCESSIBILITY_SERVICE" in trojan_app.permissions
    assert "android.permission.SYSTEM_ALERT_WINDOW" in trojan_app.permissions


def test_threat_classification_compromised_device():
    """Verify classification of banking trojan and unknown sources into HIGH RISK."""
    adb = get_adb_manager()
    scanner = MobileSecurityScanner(adb)
    classifier = MobileThreatClassifier()
    devices = adb.detect_devices(include_simulated=True)

    samsung_dev = next(d for d in devices if "SAMSUNG" in d.serial)
    posture = scanner.scan_device(samsung_dev)
    assessment = classifier.assess_device(posture)

    assert isinstance(assessment, DeviceSecurityAssessment)
    assert assessment.overall_verdict == "HIGH RISK"
    assert assessment.high_risk_count >= 1
    assert assessment.security_score < 60  # Severely penalized
    assert len(assessment.findings_digest) == 64  # Valid SHA-256

    # Verify MITRE ATT&CK Mobile mapping
    high_findings = [f for f in assessment.findings if f.risk_level == "HIGH RISK"]
    assert any(f.mitre_attack_id == "T1452" for f in high_findings)  # Accessibility abuse


def test_threat_classification_clean_baseline_device():
    """Verify clean device with only Play Store apps achieves SAFE verdict."""
    adb = get_adb_manager()
    scanner = MobileSecurityScanner(adb)
    classifier = MobileThreatClassifier()
    devices = adb.detect_devices(include_simulated=True)

    pixel_dev = next(d for d in devices if "PIXEL" in d.serial)
    posture = scanner.scan_device(pixel_dev)
    assessment = classifier.assess_device(posture)

    assert assessment.high_risk_count == 0
    assert assessment.suspicious_count == 0
    assert assessment.security_score >= 90
    assert assessment.overall_verdict in ["SAFE", "LOW RISK"]


def test_blockchain_mobile_scan_audit_block(temp_ledger, temp_db):
    """Verify that a mobile security audit is mined and committed to the blockchain ledger."""
    adb = get_adb_manager()
    scanner = MobileSecurityScanner(adb)
    classifier = MobileThreatClassifier()
    devices = adb.detect_devices(include_simulated=True)

    posture = scanner.scan_device(devices[0])
    assessment = classifier.assess_device(posture)

    # Insert into database
    scan_id = "SCAN-UNITTEST-001"
    temp_db.insert_mobile_scan({
        "scan_id": scan_id,
        "timestamp": assessment.timestamp,
        "device_hash": posture.device_hash,
        "manufacturer": posture.manufacturer,
        "model": posture.model,
        "android_version": posture.android_version,
        "total_apps_scanned": posture.total_packages,
        "safe_count": assessment.safe_count,
        "low_risk_count": assessment.low_risk_count,
        "suspicious_count": assessment.suspicious_count,
        "high_risk_count": assessment.high_risk_count,
        "security_score": assessment.security_score,
        "overall_verdict": assessment.overall_verdict,
        "findings": [f.to_dict() for f in assessment.findings]
    })

    # Commit to blockchain
    block = temp_ledger.create_mobile_scan_record(assessment, posture, scan_id=scan_id)

    assert block.index_num == 1
    assert block.data_source == "MOBILE_SECURITY"
    assert block.prediction == assessment.overall_verdict
    assert block.current_hash.startswith("00")  # Proof-of-work difficulty 2
    assert block.metadata_json["device_hash"] == posture.device_hash
    assert "findings_digest" in block.metadata_json

    # Verify blockchain chain integrity
    chain = temp_ledger.get_chain()
    report = verify_chain_integrity(chain, difficulty=2)
    assert report.is_valid is True
    assert report.total_blocks == 2


def test_database_mobile_scans_operations(temp_db):
    """Verify database insertion and query of mobile device scan records."""
    scan_data = {
        "scan_id": "SCAN-HIST-99",
        "timestamp": "2026-11-05T01:00:00Z",
        "device_hash": "DEVICE-TEST9999",
        "manufacturer": "Google",
        "model": "Pixel 8",
        "android_version": "14",
        "total_apps_scanned": 150,
        "safe_count": 140,
        "low_risk_count": 10,
        "suspicious_count": 0,
        "high_risk_count": 0,
        "security_score": 97,
        "overall_verdict": "SAFE",
        "findings": [{"name": "Test Finding", "risk_level": "SAFE"}]
    }

    temp_db.insert_mobile_scan(scan_data)
    scans = temp_db.get_all_mobile_scans()
    assert len(scans) == 1
    assert scans[0]["scan_id"] == "SCAN-HIST-99"

    # Query by device hash
    device_history = temp_db.get_mobile_device_history("DEVICE-TEST9999")
    assert len(device_history) == 1
    assert device_history[0]["security_score"] == 97

    # Update block index link
    temp_db.update_mobile_scan_block_index("SCAN-HIST-99", block_index=5)
    updated = temp_db.get_mobile_device_history("DEVICE-TEST9999")[0]
    assert updated["block_index"] == 5


def test_ios_feasibility_analysis_content():
    """Verify the iOS investigation module returns complete technical assessment."""
    analysis = get_ios_feasibility_analysis()
    assert "title" in analysis
    assert "Apple iOS" in analysis["title"]
    assert "verdict" in analysis
    assert len(analysis["usb_protocols_available"]) >= 3
    assert len(analysis["comparison_matrix"]) >= 4
    assert len(analysis["enterprise_alternatives"]) >= 2
    assert "sandbox_architecture" in analysis


def test_rebranding_no_old_brand_occurrences():
    """Verify that old application names are completely absent from the codebase."""
    banned_patterns = [
        re.compile(r"\bsoc sentinel\b", re.IGNORECASE),
        re.compile(r"\bcybernex[t]\b", re.IGNORECASE),
        re.compile(r"\bcyber nex\b", re.IGNORECASE)
    ]

    project_root = Path(__file__).resolve().parent.parent
    checked_files = 0

    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in (".venv", ".git", "__pycache__", ".pytest_cache", "node_modules", ".next")]
        for f in files:
            if f.endswith((".py", ".md", ".json", ".txt", ".toml", ".html", ".css")):
                file_path = Path(root) / f
                checked_files += 1
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                    content = fp.read()
                    for pat in banned_patterns:
                        match = pat.search(content)
                        assert match is None, f"Found banned branding '{match.group(0)}' in {file_path}"

    assert checked_files > 15

