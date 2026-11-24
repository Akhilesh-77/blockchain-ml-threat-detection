"""
Android Debug Bridge (ADB) Manager for CyberNex Mobile Security Monitoring.
Discovers ADB executable, detects connected USB devices, queries hardware/OS
properties via authorized diagnostic interfaces, and respects device privacy.
"""

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ConnectedDevice:
    """Represents a connected mobile device and its diagnostic telemetry."""
    serial: str
    device_hash: str
    status: str                         # 'device', 'unauthorized', 'offline', 'simulated'
    manufacturer: str = "Unknown"
    model: str = "Unknown"
    brand: str = "Unknown"
    android_version: str = "Unknown"
    sdk_level: int = 0
    build_id: str = "Unknown"
    build_tags: str = "release-keys"
    selinux_mode: str = "Enforcing"
    usb_debugging: bool = True
    is_authorized: bool = True
    is_debuggable: bool = False
    is_simulated: bool = False
    connection_type: str = "USB"
    raw_properties: Dict[str, str] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        """Formatted human-readable device name."""
        if self.manufacturer != "Unknown" and self.model != "Unknown":
            return f"{self.manufacturer} {self.model}"
        return f"Android Device ({self.device_hash})"


class ADBManager:
    """Manages ADB discovery, device enumeration, and authorized diagnostic queries."""

    # Standard Windows install locations for Android SDK platform-tools
    COMMON_WINDOWS_PATHS = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk" / "platform-tools" / "adb.exe",
        Path("C:/platform-tools/adb.exe"),
        Path("C:/Program Files/Android/platform-tools/adb.exe"),
        Path("C:/Program Files (x86)/Android/android-sdk/platform-tools/adb.exe"),
        Path("C:/tools/platform-tools/adb.exe"),
    ]

    def __init__(self, custom_adb_path: Optional[str] = None):
        self.custom_path: Optional[str] = custom_adb_path
        self._adb_path: Optional[str] = None
        self._adb_version: Optional[str] = None
        self.resolve_adb()

    def resolve_adb(self) -> Optional[str]:
        """Locate ADB executable on system PATH or standard Android SDK directories."""
        # 1. Custom configured path
        if self.custom_path and os.path.exists(self.custom_path):
            self._adb_path = self.custom_path
            return self._adb_path

        # 2. Check system PATH
        path_binary = shutil.which("adb")
        if path_binary:
            self._adb_path = path_binary
            return self._adb_path

        # 3. Check common Windows paths
        for p in self.COMMON_WINDOWS_PATHS:
            if p.exists() and p.is_file():
                self._adb_path = str(p)
                return self._adb_path

        self._adb_path = None
        return None

    @property
    def is_available(self) -> bool:
        """Return True if a valid ADB executable is resolved on the host."""
        return self._adb_path is not None and os.path.isfile(self._adb_path)

    @property
    def adb_path(self) -> str:
        """Return the active ADB executable path or an informative placeholder."""
        return self._adb_path or "Not Detected"

    def get_adb_version(self) -> str:
        """Query and return the installed ADB version string."""
        if not self.is_available:
            return "ADB Not Installed / Not Found on PATH"

        if self._adb_version:
            return self._adb_version

        try:
            res = subprocess.run(
                [self._adb_path, "version"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False
            )
            first_line = res.stdout.strip().split("\n")[0] if res.stdout else "Unknown Version"
            self._adb_version = first_line
            return self._adb_version
        except Exception as e:
            return f"Error querying ADB version: {e}"

    @staticmethod
    def anonymize_device_serial(serial: str) -> str:
        """
        Generate a deterministic, privacy-preserving device identifier.
        Raw device serial numbers, IMEIs, or MAC addresses are NEVER recorded
        or exposed on blockchain ledgers or dashboards.
        """
        if not serial:
            return "DEVICE-ANONYMOUS"
        digest = hashlib.sha256(serial.encode("utf-8")).hexdigest()[:12].upper()
        return f"DEVICE-{digest}"

    def run_adb_command(self, args: List[str], timeout: int = 8) -> Tuple[int, str, str]:
        """Execute an arbitrary ADB command safely with timeout handling."""
        if not self.is_available:
            return -1, "", "ADB executable is not available on this host."

        cmd = [self._adb_path] + args
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout} seconds: {' '.join(cmd)}"
        except Exception as e:
            return -1, "", str(e)

    def run_shell(self, serial: str, shell_command: str, timeout: int = 10) -> Tuple[int, str, str]:
        """Execute a diagnostic shell command on an authorized Android device via ADB."""
        return self.run_adb_command(["-s", serial, "shell", shell_command], timeout=timeout)

    def detect_devices(self, include_simulated: bool = False) -> List[ConnectedDevice]:
        """
        Detect and enumerate all USB-connected Android devices.
        Parses device connection status ('device', 'unauthorized', 'offline').
        For authorized devices, queries hardware and OS properties.
        """
        devices: List[ConnectedDevice] = []

        if self.is_available:
            code, stdout, stderr = self.run_adb_command(["devices", "-l"])
            if code == 0:
                devices.extend(self._parse_devices_output(stdout))

        # If no physical devices found and simulated mode requested, return simulated benchmark devices
        if len(devices) == 0 and include_simulated:
            devices = self.get_simulated_devices()

        return devices

    def _parse_devices_output(self, output: str) -> List[ConnectedDevice]:
        """Parse the output of 'adb devices -l' into ConnectedDevice objects."""
        devices: List[ConnectedDevice] = []
        lines = [line.strip() for line in output.splitlines() if line.strip()]

        for line in lines:
            if line.startswith("List of devices") or line.startswith("*"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            serial = parts[0]
            status_str = parts[1].lower()

            # Parse key:value metadata from -l format (e.g. model:Pixel_7 device:cheetah transport_id:1)
            props: Dict[str, str] = {}
            for token in parts[2:]:
                if ":" in token:
                    k, v = token.split(":", 1)
                    props[k] = v

            device_hash = self.anonymize_device_serial(serial)
            is_authorized = (status_str == "device")

            dev = ConnectedDevice(
                serial=serial,
                device_hash=device_hash,
                status=status_str,
                model=props.get("model", "Android Device"),
                brand=props.get("product", "Generic"),
                is_authorized=is_authorized,
                usb_debugging=True,
                is_simulated=False,
                connection_type="USB"
            )

            # If authorized, query full properties via adb shell getprop
            if is_authorized:
                self._enrich_device_properties(dev)

            devices.append(dev)

        return devices

    def _enrich_device_properties(self, dev: ConnectedDevice) -> None:
        """Query getprop and security posture on an authorized connected device."""
        code, stdout, _ = self.run_shell(dev.serial, "getprop")
        if code == 0:
            parsed_props: Dict[str, str] = {}
            for line in stdout.splitlines():
                m = re.match(r"^\[(.*?)\]:\s*\[(.*?)\]$", line.strip())
                if m:
                    parsed_props[m.group(1)] = m.group(2)

            dev.raw_properties = parsed_props
            dev.manufacturer = parsed_props.get("ro.product.manufacturer", dev.manufacturer).capitalize()
            dev.model = parsed_props.get("ro.product.model", dev.model)
            dev.brand = parsed_props.get("ro.product.brand", dev.brand).capitalize()
            dev.android_version = parsed_props.get("ro.build.version.release", "Unknown")
            dev.sdk_level = int(parsed_props.get("ro.build.version.sdk", 0) or 0)
            dev.build_id = parsed_props.get("ro.build.id", parsed_props.get("ro.build.display.id", "Unknown"))
            dev.build_tags = parsed_props.get("ro.build.tags", "release-keys")
            dev.is_debuggable = (parsed_props.get("ro.debuggable", "0") == "1")

        # Query SELinux mode
        code_se, stdout_se, _ = self.run_shell(dev.serial, "getenforce")
        if code_se == 0:
            dev.selinux_mode = stdout_se.strip() or "Enforcing"

    def disconnect_device(self, serial: str) -> Tuple[bool, str]:
        """
        Disconnect or release an active device monitoring session.
        If device is connected over TCP/IP, invokes 'adb disconnect'.
        For USB devices, stops active polling in CyberNex.
        """
        if ":" in serial:  # TCP/IP device (ip:port)
            code, out, err = self.run_adb_command(["disconnect", serial])
            return code == 0, out or err
        return True, f"Monitoring session paused for USB device {self.anonymize_device_serial(serial)}."

    @classmethod
    def get_simulated_devices(cls) -> List[ConnectedDevice]:
        """
        Provides realistic simulated mobile device profiles.
        Enables rigorous testing of CyberNex mobile security analysis,
        permission heuristics, and blockchain verification without requiring
        a physical hardware phone or pre-installed ADB drivers.
        """
        dev1 = ConnectedDevice(
            serial="SIMULATED-PIXEL-7A-001",
            device_hash="DEVICE-94F8B31A4C2E",
            status="device",
            manufacturer="Google",
            model="Pixel 7a",
            brand="Google",
            android_version="14",
            sdk_level=34,
            build_id="UP1A.231005.007",
            build_tags="release-keys",
            selinux_mode="Enforcing",
            usb_debugging=True,
            is_authorized=True,
            is_debuggable=False,
            is_simulated=True,
            connection_type="USB (Simulated)"
        )

        dev2 = ConnectedDevice(
            serial="SIMULATED-SAMSUNG-S23-002",
            device_hash="DEVICE-E720BC84A1D5",
            status="device",
            manufacturer="Samsung",
            model="Galaxy S23 Ultra",
            brand="Samsung",
            android_version="13",
            sdk_level=33,
            build_id="TP1A.220624.014",
            build_tags="release-keys",
            selinux_mode="Enforcing",
            usb_debugging=True,
            is_authorized=True,
            is_debuggable=False,
            is_simulated=True,
            connection_type="USB (Simulated)"
        )

        dev3 = ConnectedDevice(
            serial="SIMULATED-ONEPLUS-DEV-003",
            device_hash="DEVICE-31C4A8D9F05B",
            status="device",
            manufacturer="OnePlus",
            model="OnePlus 11 5G",
            brand="OnePlus",
            android_version="13",
            sdk_level=33,
            build_id="CPH2449_13.1.0.580",
            build_tags="test-keys",
            selinux_mode="Permissive",
            usb_debugging=True,
            is_authorized=True,
            is_debuggable=True,
            is_simulated=True,
            connection_type="USB (Simulated)"
        )

        return [dev1, dev2, dev3]


# Global singleton instance
_adb_manager_instance: Optional[ADBManager] = None


def get_adb_manager(custom_path: Optional[str] = None) -> ADBManager:
    """Return singleton ADBManager instance."""
    global _adb_manager_instance
    if _adb_manager_instance is None or (custom_path and _adb_manager_instance.custom_path != custom_path):
        _adb_manager_instance = ADBManager(custom_adb_path=custom_path)
    return _adb_manager_instance

