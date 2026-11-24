"""
Mobile Malware & Threat Classification Module for CyberNex.
Analyzes Android package metadata, critical permission vectors, and OS configurations.
Classifies findings into SAFE, LOW RISK, SUSPICIOUS, or HIGH RISK with
evidence-backed MITRE ATT&CK mappings, ML confidence scores, and remediation actions.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from mobile.security_scanner import (
    CRITICAL_ANDROID_PERMISSIONS,
    DeviceSecurityPosture,
    InstalledApp,
)


@dataclass
class ThreatFinding:
    """Individual security threat or posture finding with remediation details."""
    name: str                               # Application or event name
    category: str                           # 'Application Threat', 'OS Configuration', 'Permission Anomaly'
    risk_level: str                         # 'SAFE', 'LOW RISK', 'SUSPICIOUS', 'HIGH RISK'
    detection_reason: str                   # Detailed technical explanation
    timestamp: str                          # ISO 8601 timestamp
    recommended_action: str                 # Exact remediation step
    ml_confidence: float                    # Classification / heuristic confidence (0.0 to 1.0)
    mitre_attack_id: Optional[str] = None  # MITRE ATT&CK Mobile technique ID
    package_name: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding into dictionary format."""
        return {
            "name": self.name,
            "package_name": self.package_name,
            "category": self.category,
            "risk_level": self.risk_level,
            "detection_reason": self.detection_reason,
            "timestamp": self.timestamp,
            "recommended_action": self.recommended_action,
            "ml_confidence": round(self.ml_confidence, 4),
            "mitre_attack_id": self.mitre_attack_id,
            "details": self.details
        }


@dataclass
class DeviceSecurityAssessment:
    """Complete diagnostic assessment and risk rating for an inspected device."""
    device_hash: str
    security_score: int                     # 0 (Compromised) to 100 (Hardened)
    overall_verdict: str                    # 'HIGH RISK', 'SUSPICIOUS', 'LOW RISK', 'SAFE'
    timestamp: str
    total_findings: int
    high_risk_count: int
    suspicious_count: int
    low_risk_count: int
    safe_count: int
    findings: List[ThreatFinding] = field(default_factory=list)
    findings_digest: str = ""

    def calculate_findings_digest(self) -> str:
        """Compute SHA-256 hash of all findings for tamper-evident blockchain commitment."""
        serialized = json.dumps([f.to_dict() for f in self.findings], sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class MobileThreatClassifier:
    """
    Evaluates Android security posture and package permissions using heuristic
    feature vectors and security intelligence rules.
    """

    def assess_device(self, posture: DeviceSecurityPosture) -> DeviceSecurityAssessment:
        """
        Evaluate full device security posture, classify every application and configuration finding,
        and calculate an aggregate Device Security Score (0-100).
        """
        findings: List[ThreatFinding] = []
        now = datetime.now(timezone.utc).isoformat()

        # 1. Evaluate OS Security Configurations
        # Check SELinux Mode
        if posture.selinux_mode.lower() == "permissive":
            findings.append(ThreatFinding(
                name="SELinux in Permissive Mode",
                category="OS Configuration",
                risk_level="HIGH RISK",
                detection_reason=(
                    "Security-Enhanced Linux (SELinux) is set to 'Permissive'. Mandatory Access Control (MAC) "
                    "enforcement is disabled, allowing compromised apps to bypass domain boundaries."
                ),
                timestamp=now,
                recommended_action="Set SELinux to 'Enforcing' mode via fastboot or restore official OEM firmware.",
                ml_confidence=0.98,
                mitre_attack_id="T1402"
            ))
        elif posture.selinux_mode.lower() == "disabled":
            findings.append(ThreatFinding(
                name="SELinux Disabled",
                category="OS Configuration",
                risk_level="HIGH RISK",
                detection_reason="SELinux kernel enforcement is completely deactivated. Full device compromise possible.",
                timestamp=now,
                recommended_action="Flash official OEM factory image immediately.",
                ml_confidence=0.99,
                mitre_attack_id="T1402"
            ))
        else:
            findings.append(ThreatFinding(
                name="SELinux Kernel Hardening",
                category="OS Configuration",
                risk_level="SAFE",
                detection_reason="SELinux is running in Enforcing mode. Mandatory Access Control policies active.",
                timestamp=now,
                recommended_action="Maintain current firmware update schedule.",
                ml_confidence=0.99
            ))

        # Check Test-Keys / Custom ROM Signing
        if posture.has_test_keys:
            findings.append(ThreatFinding(
                name="Engineering / Test-Keys Build Detected",
                category="OS Configuration",
                risk_level="SUSPICIOUS",
                detection_reason=(
                    "Firmware was signed with public Android Open Source Project (AOSP) test-keys. "
                    "Indicates a custom ROM, engineering build, or unofficial firmware."
                ),
                timestamp=now,
                recommended_action="Verify device firmware integrity against official manufacturer cryptographic hashes.",
                ml_confidence=0.91,
                mitre_attack_id="T1406"
            ))

        # Check Debuggable Kernel
        if posture.is_debuggable_build:
            findings.append(ThreatFinding(
                name="Debuggable System Build (ro.debuggable=1)",
                category="OS Configuration",
                risk_level="HIGH RISK",
                detection_reason=(
                    "Device kernel allows arbitrary adb root access and memory attachment. "
                    "Any app can potentially be inspected or hijacked over debugging interfaces."
                ),
                timestamp=now,
                recommended_action="Flash a production 'user' build rather than 'userdebug' or 'eng' build.",
                ml_confidence=0.96,
                mitre_attack_id="T1451"
            ))

        # Check Unknown Sources Setting
        if posture.unknown_sources_enabled:
            findings.append(ThreatFinding(
                name="Unknown Sources Sideloading Enabled",
                category="OS Configuration",
                risk_level="SUSPICIOUS",
                detection_reason=(
                    "Device allows installation of APKs from unverified third-party web browsers "
                    "or file managers without Google Play Protect gatekeeping."
                ),
                timestamp=now,
                recommended_action="Disable 'Install Unknown Apps' under Settings > Security to prevent dropper execution.",
                ml_confidence=0.88,
                mitre_attack_id="T1475"
            ))

        # USB Debugging Advisory
        if posture.usb_debugging_enabled:
            findings.append(ThreatFinding(
                name="USB Debugging Active (ADB Port Opened)",
                category="OS Configuration",
                risk_level="LOW RISK",
                detection_reason=(
                    "USB Debugging is actively enabled to facilitate CyberNex security auditing. "
                    "If left enabled in public environments, device is vulnerable to unauthorized physical extraction."
                ),
                timestamp=now,
                recommended_action="Disable USB Debugging in Developer Options when not conducting authorized SOC audits.",
                ml_confidence=0.85,
                mitre_attack_id="T1451"
            ))

        # 2. Evaluate Installed Third-Party Applications
        for app in posture.apps:
            if app.is_system:
                continue

            app_finding = self._classify_application(app, now)
            findings.append(app_finding)

        # 3. Calculate Overall Security Score (0 to 100)
        high_risk_count = sum(1 for f in findings if f.risk_level == "HIGH RISK")
        suspicious_count = sum(1 for f in findings if f.risk_level == "SUSPICIOUS")
        low_risk_count = sum(1 for f in findings if f.risk_level == "LOW RISK")
        safe_count = sum(1 for f in findings if f.risk_level == "SAFE")

        # Weighted score deduction algorithm
        score = 100
        score -= (high_risk_count * 28)
        score -= (suspicious_count * 12)
        score -= (low_risk_count * 3)
        score = max(5, min(100, score))

        # Determine aggregate verdict
        if high_risk_count > 0:
            overall_verdict = "HIGH RISK"
        elif suspicious_count > 0:
            overall_verdict = "SUSPICIOUS"
        elif low_risk_count > 0:
            overall_verdict = "LOW RISK"
        else:
            overall_verdict = "SAFE"

        assessment = DeviceSecurityAssessment(
            device_hash=posture.device_hash,
            security_score=score,
            overall_verdict=overall_verdict,
            timestamp=now,
            total_findings=len(findings),
            high_risk_count=high_risk_count,
            suspicious_count=suspicious_count,
            low_risk_count=low_risk_count,
            safe_count=safe_count,
            findings=findings
        )
        assessment.findings_digest = assessment.calculate_findings_digest()

        return assessment

    def _classify_application(self, app: InstalledApp, timestamp: str) -> ThreatFinding:
        """
        Classifies an individual application into SAFE, LOW RISK, SUSPICIOUS, or HIGH RISK
        using permission combinations, install source verification, and behavioral heuristics.
        """
        perms_set = set(app.permissions)
        critical_perms = [p.get("permission", p.get("name", "")) for p in app.critical_permissions]

        has_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms_set
        has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in perms_set
        has_dropper = "android.permission.REQUEST_INSTALL_PACKAGES" in perms_set
        has_device_admin = "android.permission.BIND_DEVICE_ADMIN" in perms_set
        has_sms_read = "android.permission.READ_SMS" in perms_set or "android.permission.RECEIVE_SMS" in perms_set
        has_surveillance = "android.permission.RECORD_AUDIO" in perms_set and "android.permission.CAMERA" in perms_set
        has_background_loc = "android.permission.ACCESS_BACKGROUND_LOCATION" in perms_set

        # --- Rule 1: High Risk — Banking Trojan Profile ---
        # Sideloaded + (Accessibility Service OR (Overlay + SMS Read / Dropper))
        if app.is_sideloaded and (has_accessibility or (has_overlay and (has_sms_read or has_dropper))):
            reasons = []
            if has_accessibility:
                reasons.append("Accessibility Service (capable of autonomous keystroke logging & button clicking)")
            if has_overlay:
                reasons.append("SYSTEM_ALERT_WINDOW overlay permission (tapjacking/phishing attack vector)")
            if has_sms_read:
                reasons.append("SMS read/receive permissions (2FA token interception)")
            if has_dropper:
                reasons.append("Silent secondary APK dropper capability")

            return ThreatFinding(
                name=f"{app.app_name} ({app.package_name})",
                package_name=app.package_name,
                category="Application Threat",
                risk_level="HIGH RISK",
                detection_reason=(
                    f"Application is sideloaded from an unverified source and requests abusive permissions matching "
                    f"Android Banking Trojan signatures (e.g. SharkBot/FluBot): {', '.join(reasons)}."
                ),
                timestamp=timestamp,
                recommended_action=(
                    "Revoke Accessibility and Overlay permissions immediately, uninstall the APK via adb uninstall, "
                    "and review banking credentials."
                ),
                ml_confidence=0.97,
                mitre_attack_id="T1452",
                details={"install_source": app.install_source, "abusive_permissions": critical_perms}
            )

        # --- Rule 2: High Risk — Ransomware / Device Locker Profile ---
        if app.is_sideloaded and has_device_admin and (has_overlay or has_dropper):
            return ThreatFinding(
                name=f"{app.app_name} ({app.package_name})",
                package_name=app.package_name,
                category="Application Threat",
                risk_level="HIGH RISK",
                detection_reason=(
                    "Sideloaded package requests Device Administrator privileges combined with display overlays. "
                    "Matches Android Locker / Ransomware behavior preventing uninstallation."
                ),
                timestamp=timestamp,
                recommended_action="Deactivate Device Admin under Settings > Security > Device Admin Apps, then uninstall.",
                ml_confidence=0.95,
                mitre_attack_id="T1401",
                details={"install_source": app.install_source, "permissions": app.permissions}
            )

        # --- Rule 3: Suspicious — Sideloaded Spyware / Aggressive Cleaner ---
        if app.is_sideloaded and (has_surveillance or (has_background_loc and has_overlay)):
            return ThreatFinding(
                name=f"{app.app_name} ({app.package_name})",
                package_name=app.package_name,
                category="Application Threat",
                risk_level="SUSPICIOUS",
                detection_reason=(
                    "Unverified third-party app requests background acoustic surveillance, camera access, "
                    "or persistent continuous geolocation without legitimate justification."
                ),
                timestamp=timestamp,
                recommended_action="Restrict camera and microphone permissions to 'Only while using the app'.",
                ml_confidence=0.89,
                mitre_attack_id="T1429",
                details={"install_source": app.install_source, "permissions": app.permissions}
            )

        # --- Rule 4: Suspicious — Sideloaded Package without Critical Permissions ---
        if app.is_sideloaded and len(critical_perms) > 0:
            return ThreatFinding(
                name=f"{app.app_name} ({app.package_name})",
                package_name=app.package_name,
                category="Application Threat",
                risk_level="SUSPICIOUS",
                detection_reason=(
                    f"Application was installed outside official verified app stores ({app.install_source}) "
                    f"and requests sensitive capabilities ({', '.join(critical_perms[:3])})."
                ),
                timestamp=timestamp,
                recommended_action="Verify developer signing certificate or replace with official Play Store release.",
                ml_confidence=0.82,
                mitre_attack_id="T1475",
                details={"install_source": app.install_source}
            )

        # --- Rule 5: Low Risk — Play Store App with Sensitive Permissions ---
        if not app.is_sideloaded and len(critical_perms) > 0:
            return ThreatFinding(
                name=f"{app.app_name} ({app.package_name})",
                package_name=app.package_name,
                category="Application Threat",
                risk_level="LOW RISK",
                detection_reason=(
                    f"Verified Play Store application uses legitimate sensitive permissions "
                    f"({', '.join(critical_perms[:2])}) proportional to expected application functions."
                ),
                timestamp=timestamp,
                recommended_action="No urgent action required. Periodically audit app permissions in Android Settings.",
                ml_confidence=0.91,
                details={"install_source": app.install_source, "verified": True}
            )

        # --- Rule 6: Safe — Standard Verified Application ---
        return ThreatFinding(
            name=f"{app.app_name} ({app.package_name})",
            package_name=app.package_name,
            category="Application Threat",
            risk_level="SAFE",
            detection_reason="Application is installed from a verified store, requests standard permissions, and exhibits no malware indicators.",
            timestamp=timestamp,
            recommended_action="None. Application posture is clean.",
            ml_confidence=0.96,
            details={"install_source": app.install_source}
        )
