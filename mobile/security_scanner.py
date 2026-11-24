"""
Mobile Security Scanner for CyberNex.
Inspects installed Android packages, extracts declared/granted permissions,
identifies sideloaded APKs from unknown sources, audits OS security settings,
and enforces zero-data-exfiltration privacy boundaries.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from mobile.adb_manager import ADBManager, ConnectedDevice, get_adb_manager


# High-Risk / Critical Android Permissions recognized by MITRE ATT&CK Mobile
CRITICAL_ANDROID_PERMISSIONS = {
    # 1. Screen Reading, Keystroke Logging & Autonomous Click Exploits (Banking Trojans)
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "name": "Accessibility Service Abuse",
        "severity": "CRITICAL",
        "description": "Enables reading screen contents, intercepting credentials, and clicking UI buttons autonomously.",
        "mitre_id": "T1452"
    },
    # 2. Tapjacking & Credential Overlay
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "name": "Display Overlay / Tapjacking",
        "severity": "HIGH",
        "description": "Can draw floating overlays on top of legitimate banking or cryptocurrency applications.",
        "mitre_id": "T1453"
    },
    # 3. Silent Secondary Payload Dropper
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "name": "Unknown Package Installer",
        "severity": "HIGH",
        "description": "Permits the application to download and trigger installation of secondary malicious APK packages.",
        "mitre_id": "T1475"
    },
    # 4. Anti-Removal & Ransomware Persistence
    "android.permission.BIND_DEVICE_ADMIN": {
        "name": "Device Administrator Rights",
        "severity": "CRITICAL",
        "description": "Grants privileged device administration, preventing user uninstallation and allowing screen lock hijacking.",
        "mitre_id": "T1401"
    },
    # 5. OTP / SMS Theft & Toll Fraud
    "android.permission.RECEIVE_SMS": {
        "name": "SMS Reception Interception",
        "severity": "HIGH",
        "description": "Enables intercepting incoming SMS 2FA tokens and one-time passwords.",
        "mitre_id": "T1412"
    },
    "android.permission.READ_SMS": {
        "name": "SMS Message Database Reading",
        "severity": "HIGH",
        "description": "Allows reading historical and active SMS messages containing sensitive authentication data.",
        "mitre_id": "T1412"
    },
    "android.permission.SEND_SMS": {
        "name": "Toll Fraud / Outgoing SMS",
        "severity": "MEDIUM",
        "description": "Permits sending premium-rate SMS messages without user interaction.",
        "mitre_id": "T1448"
    },
    # 6. Audio/Visual Surveillance
    "android.permission.RECORD_AUDIO": {
        "name": "Microphone Audio Recording",
        "severity": "MEDIUM",
        "description": "Access to record background audio and environmental acoustics.",
        "mitre_id": "T1429"
    },
    "android.permission.CAMERA": {
        "name": "Camera Surveillance",
        "severity": "MEDIUM",
        "description": "Direct access to take photographs and capture video frames.",
        "mitre_id": "T1430"
    },
    # 7. Persistent Location Tracking
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "name": "Continuous Background Location",
        "severity": "MEDIUM",
        "description": "Access to GPS coordinates even when the app is minimized or backgrounded.",
        "mitre_id": "T1430"
    },
    # 8. Application Reconnaissance
    "android.permission.QUERY_ALL_PACKAGES": {
        "name": "Complete Package Inventory Query",
        "severity": "LOW",
        "description": "Allows the app to enumerate all other installed apps on the device (reconnaissance).",
        "mitre_id": "T1418"
    }
}

# Recognized Legitimate App Store Package Identifiers
VERIFIED_STORE_INSTALLERS = {
    "com.android.vending": "Google Play Store",
    "com.google.android.feedback": "Google Play Services",
    "com.sec.android.app.samsungapps": "Samsung Galaxy Store",
    "com.amazon.venezia": "Amazon Appstore",
    "com.huawei.appmarket": "Huawei AppGallery",
    "com.xiaomi.mipicks": "Xiaomi GetApps"
}


@dataclass
class InstalledApp:
    """Represents an installed Android package metadata audit record."""
    package_name: str
    app_name: str
    is_system: bool
    install_source: str                 # e.g., 'Google Play Store', 'Sideloaded / Unknown Source'
    is_sideloaded: bool
    permissions: List[str] = field(default_factory=list)
    critical_permissions: List[Dict[str, str]] = field(default_factory=list)
    target_sdk: int = 33
    version_name: str = "1.0.0"

    @property
    def has_critical_privileges(self) -> bool:
        """Return True if package requests high-risk or abusive permissions."""
        return len(self.critical_permissions) > 0


@dataclass
class DeviceSecurityPosture:
    """Full security posture of an inspected mobile device."""
    device_hash: str
    manufacturer: str
    model: str
    android_version: str
    sdk_level: int
    selinux_mode: str                   # 'Enforcing', 'Permissive', 'Disabled'
    usb_debugging_enabled: bool
    developer_options_enabled: bool
    unknown_sources_enabled: bool
    is_debuggable_build: bool
    has_test_keys: bool
    scan_timestamp: str
    total_packages: int
    system_packages_count: int
    third_party_packages_count: int
    sideloaded_count: int
    apps: List[InstalledApp] = field(default_factory=list)

    def to_summary_dict(self) -> Dict[str, Any]:
        """Convert posture into sanitized summary for database or blockchain commit."""
        return {
            "device_hash": self.device_hash,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "android_version": self.android_version,
            "sdk_level": self.sdk_level,
            "selinux_mode": self.selinux_mode,
            "usb_debugging_enabled": self.usb_debugging_enabled,
            "developer_options_enabled": self.developer_options_enabled,
            "unknown_sources_enabled": self.unknown_sources_enabled,
            "is_debuggable_build": self.is_debuggable_build,
            "has_test_keys": self.has_test_keys,
            "scan_timestamp": self.scan_timestamp,
            "total_packages": self.total_packages,
            "third_party_packages": self.third_party_packages_count,
            "sideloaded_packages": self.sideloaded_count
        }


def _make_critical_perm(perm_key: str) -> Dict[str, str]:
    meta = dict(CRITICAL_ANDROID_PERMISSIONS.get(perm_key, {}))
    meta["permission"] = perm_key
    return meta


class MobileSecurityScanner:
    """Orchestrates security audits of USB-connected Android devices."""

    def __init__(self, adb_manager: Optional[ADBManager] = None):
        self.adb = adb_manager or get_adb_manager()

    def scan_device(self, device: ConnectedDevice) -> DeviceSecurityPosture:
        """
        Perform a non-invasive diagnostic security scan of a connected device.
        Collects package metadata and Android security configuration without
        accessing personal messages, passwords, contacts, or photos.
        """
        if device.is_simulated:
            return self._scan_simulated_device(device)

        return self._scan_physical_device(device)

    def _scan_physical_device(self, device: ConnectedDevice) -> DeviceSecurityPosture:
        """Execute diagnostic ADB shell commands on a real physical Android phone."""
        timestamp = datetime.now(timezone.utc).isoformat()

        # 1. Enumerate 3rd-party vs system packages
        code_3p, stdout_3p, _ = self.adb.run_shell(device.serial, "pm list packages -3")
        pkgs_3p = set(line.replace("package:", "").strip() for line in stdout_3p.splitlines() if line.strip())

        code_sys, stdout_sys, _ = self.adb.run_shell(device.serial, "pm list packages -s")
        pkgs_sys = set(line.replace("package:", "").strip() for line in stdout_sys.splitlines() if line.strip())

        # 2. Check System Security Posture settings
        code_dev, stdout_dev, _ = self.adb.run_shell(device.serial, "settings get global development_settings_enabled")
        developer_options = (stdout_dev.strip() == "1")

        code_unk, stdout_unk, _ = self.adb.run_shell(device.serial, "settings get secure install_non_market_apps")
        unknown_sources = (stdout_unk.strip() == "1")

        apps: List[InstalledApp] = []
        sideload_count = 0

        # Scan 3rd party packages (focus of security auditing)
        for pkg in sorted(list(pkgs_3p))[:100]:  # Cap at 100 to prevent timeout
            app_meta = self._inspect_package(device.serial, pkg, is_system=False)
            if app_meta.is_sideloaded:
                sideload_count += 1
            apps.append(app_meta)

        posture = DeviceSecurityPosture(
            device_hash=device.device_hash,
            manufacturer=device.manufacturer,
            model=device.model,
            android_version=device.android_version,
            sdk_level=device.sdk_level,
            selinux_mode=device.selinux_mode,
            usb_debugging_enabled=device.usb_debugging,
            developer_options_enabled=developer_options,
            unknown_sources_enabled=unknown_sources,
            is_debuggable_build=device.is_debuggable,
            has_test_keys=(device.build_tags == "test-keys"),
            scan_timestamp=timestamp,
            total_packages=len(pkgs_3p) + len(pkgs_sys),
            system_packages_count=len(pkgs_sys),
            third_party_packages_count=len(pkgs_3p),
            sideloaded_count=sideload_count,
            apps=apps
        )

        return posture

    def _inspect_package(self, serial: str, package_name: str, is_system: bool) -> InstalledApp:
        """Inspect package install source and permissions via pm/dumpsys."""
        # Query install source
        code_src, stdout_src, _ = self.adb.run_shell(serial, f"pm get-install-source {package_name}")
        install_source_name = "Sideloaded / Unknown Source"
        is_sideloaded = True

        for k, v in VERIFIED_STORE_INSTALLERS.items():
            if k in stdout_src:
                install_source_name = v
                is_sideloaded = False
                break

        # Query granted permissions
        code_dump, stdout_dump, _ = self.adb.run_shell(serial, f"dumpsys package {package_name}")
        permissions: List[str] = []
        critical_perms: List[Dict[str, str]] = []

        for line in stdout_dump.splitlines():
            clean_line = line.strip()
            if "android.permission." in clean_line:
                perm_match = re.search(r"(android\.permission\.[A-Z0-9_]+)", clean_line)
                if perm_match:
                    perm = perm_match.group(1)
                    if perm not in permissions:
                        permissions.append(perm)
                        if perm in CRITICAL_ANDROID_PERMISSIONS:
                            meta = CRITICAL_ANDROID_PERMISSIONS[perm]
                            critical_perms.append({
                                "permission": perm,
                                "name": meta["name"],
                                "severity": meta["severity"],
                                "description": meta["description"],
                                "mitre_id": meta["mitre_id"]
                            })

        # Derive friendly name from package
        app_name = package_name.split(".")[-1].capitalize()

        return InstalledApp(
            package_name=package_name,
            app_name=app_name,
            is_system=is_system,
            install_source=install_source_name,
            is_sideloaded=is_sideloaded,
            permissions=permissions,
            critical_permissions=critical_perms
        )

    def _scan_simulated_device(self, device: ConnectedDevice) -> DeviceSecurityPosture:
        """
        Generate a comprehensive, realistic benchmark security posture for simulated devices.
        Includes well-known benign applications, high-risk malware profiles,
        and system configuration variants.
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        apps: List[InstalledApp] = []

        if "SAMSUNG" in device.serial:
            # Compromised Device Profile: Banking Trojan & Fake Cleaner
            apps = [
                InstalledApp(
                    package_name="com.fakebank.security.update",
                    app_name="Bank Security Auth Update",
                    is_system=False,
                    install_source="Sideloaded / Unknown Source",
                    is_sideloaded=True,
                    target_sdk=30,
                    version_name="3.4.1",
                    permissions=[
                        "android.permission.BIND_ACCESSIBILITY_SERVICE",
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.READ_SMS",
                        "android.permission.RECEIVE_SMS",
                        "android.permission.REQUEST_INSTALL_PACKAGES",
                        "android.permission.INTERNET"
                    ],
                    critical_permissions=[
                        _make_critical_perm("android.permission.BIND_ACCESSIBILITY_SERVICE"),
                        _make_critical_perm("android.permission.SYSTEM_ALERT_WINDOW"),
                        _make_critical_perm("android.permission.READ_SMS"),
                        _make_critical_perm("android.permission.RECEIVE_SMS"),
                        _make_critical_perm("android.permission.REQUEST_INSTALL_PACKAGES"),
                    ]
                ),
                InstalledApp(
                    package_name="org.supercleaner.rambooster",
                    app_name="Super RAM Cleaner Pro",
                    is_system=False,
                    install_source="Sideloaded / Unknown Source",
                    is_sideloaded=True,
                    target_sdk=29,
                    version_name="1.0.8",
                    permissions=[
                        "android.permission.RECORD_AUDIO",
                        "android.permission.CAMERA",
                        "android.permission.ACCESS_BACKGROUND_LOCATION",
                        "android.permission.QUERY_ALL_PACKAGES",
                        "android.permission.SYSTEM_ALERT_WINDOW"
                    ],
                    critical_permissions=[
                        _make_critical_perm("android.permission.RECORD_AUDIO"),
                        _make_critical_perm("android.permission.CAMERA"),
                        _make_critical_perm("android.permission.ACCESS_BACKGROUND_LOCATION"),
                        _make_critical_perm("android.permission.SYSTEM_ALERT_WINDOW"),
                        _make_critical_perm("android.permission.QUERY_ALL_PACKAGES"),
                    ]
                ),
                InstalledApp(
                    package_name="com.whatsapp",
                    app_name="WhatsApp Messenger",
                    is_system=False,
                    install_source="Google Play Store",
                    is_sideloaded=False,
                    target_sdk=33,
                    version_name="2.23.24.12",
                    permissions=["android.permission.CAMERA", "android.permission.RECORD_AUDIO"],
                    critical_permissions=[
                        _make_critical_perm("android.permission.CAMERA"),
                        _make_critical_perm("android.permission.RECORD_AUDIO")
                    ]
                ),
                InstalledApp(
                    package_name="com.google.android.youtube",
                    app_name="YouTube",
                    is_system=False,
                    install_source="Google Play Store",
                    is_sideloaded=False,
                    target_sdk=34,
                    version_name="18.45.38",
                    permissions=["android.permission.INTERNET"],
                    critical_permissions=[]
                ),
                InstalledApp(
                    package_name="com.spotify.music",
                    app_name="Spotify",
                    is_system=False,
                    install_source="Google Play Store",
                    is_sideloaded=False,
                    target_sdk=33,
                    version_name="8.8.84.582",
                    permissions=["android.permission.INTERNET"],
                    critical_permissions=[]
                )
            ]
            posture = DeviceSecurityPosture(
                device_hash=device.device_hash,
                manufacturer=device.manufacturer,
                model=device.model,
                android_version=device.android_version,
                sdk_level=device.sdk_level,
                selinux_mode="Enforcing",
                usb_debugging_enabled=True,
                developer_options_enabled=True,
                unknown_sources_enabled=True,   # Flagged: unknown sources enabled
                is_debuggable_build=False,
                has_test_keys=False,
                scan_timestamp=timestamp,
                total_packages=248,
                system_packages_count=243,
                third_party_packages_count=5,
                sideloaded_count=2,
                apps=apps
            )

        elif "ONEPLUS" in device.serial:
            # Compromised Configuration Profile: Permissive SELinux, Test-Keys & Ransomware Locker
            apps = [
                InstalledApp(
                    package_name="com.android.syslock.update",
                    app_name="System Decryptor Admin",
                    is_system=False,
                    install_source="Sideloaded / Unknown Source",
                    is_sideloaded=True,
                    target_sdk=28,
                    version_name="1.0.0",
                    permissions=[
                        "android.permission.BIND_DEVICE_ADMIN",
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.REQUEST_INSTALL_PACKAGES"
                    ],
                    critical_permissions=[
                        _make_critical_perm("android.permission.BIND_DEVICE_ADMIN"),
                        _make_critical_perm("android.permission.SYSTEM_ALERT_WINDOW"),
                        _make_critical_perm("android.permission.REQUEST_INSTALL_PACKAGES")
                    ]
                ),
                InstalledApp(
                    package_name="org.fdroid.fdroid",
                    app_name="F-Droid Open Source Store",
                    is_system=False,
                    install_source="Sideloaded / Unknown Source",
                    is_sideloaded=True,
                    target_sdk=33,
                    version_name="1.18.0",
                    permissions=["android.permission.REQUEST_INSTALL_PACKAGES"],
                    critical_permissions=[
                        _make_critical_perm("android.permission.REQUEST_INSTALL_PACKAGES")
                    ]
                ),
                InstalledApp(
                    package_name="org.videolan.vlc",
                    app_name="VLC Media Player",
                    is_system=False,
                    install_source="Google Play Store",
                    is_sideloaded=False,
                    target_sdk=33,
                    version_name="3.5.4",
                    permissions=["android.permission.INTERNET"],
                    critical_permissions=[]
                )
            ]
            posture = DeviceSecurityPosture(
                device_hash=device.device_hash,
                manufacturer=device.manufacturer,
                model=device.model,
                android_version=device.android_version,
                sdk_level=device.sdk_level,
                selinux_mode="Permissive",     # High Risk
                usb_debugging_enabled=True,
                developer_options_enabled=True,
                unknown_sources_enabled=True,
                is_debuggable_build=True,       # High Risk: debuggable
                has_test_keys=True,             # Suspicious: test-keys
                scan_timestamp=timestamp,
                total_packages=215,
                system_packages_count=212,
                third_party_packages_count=3,
                sideloaded_count=2,
                apps=apps
            )

        else:
            # Pixel Clean Profile: High Posture Baseline
            apps = [
                InstalledApp(
                    package_name="com.google.android.youtube",
                    app_name="YouTube",
                    is_system=False,
                    install_source="Google Play Store",
                    is_sideloaded=False,
                    target_sdk=34,
                    version_name="19.12.35",
                    permissions=["android.permission.INTERNET"],
                    critical_permissions=[]
                ),
                InstalledApp(
                    package_name="com.google.android.apps.maps",
                    app_name="Google Maps",
                    is_system=False,
                    install_source="Google Play Store",
                    is_sideloaded=False,
                    target_sdk=34,
                    version_name="11.115.0101",
                    permissions=["android.permission.ACCESS_FINE_LOCATION"],
                    critical_permissions=[]
                ),
                InstalledApp(
                    package_name="com.slack",
                    app_name="Slack",
                    is_system=False,
                    install_source="Google Play Store",
                    is_sideloaded=False,
                    target_sdk=33,
                    version_name="24.01.20",
                    permissions=["android.permission.CAMERA", "android.permission.RECORD_AUDIO"],
                    critical_permissions=[
                        CRITICAL_ANDROID_PERMISSIONS["android.permission.CAMERA"],
                        CRITICAL_ANDROID_PERMISSIONS["android.permission.RECORD_AUDIO"]
                    ]
                )
            ]
            posture = DeviceSecurityPosture(
                device_hash=device.device_hash,
                manufacturer=device.manufacturer,
                model=device.model,
                android_version=device.android_version,
                sdk_level=device.sdk_level,
                selinux_mode="Enforcing",
                usb_debugging_enabled=True,
                developer_options_enabled=False,
                unknown_sources_enabled=False,
                is_debuggable_build=False,
                has_test_keys=False,
                scan_timestamp=timestamp,
                total_packages=198,
                system_packages_count=195,
                third_party_packages_count=3,
                sideloaded_count=0,
                apps=apps
            )

        return posture
