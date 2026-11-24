# 📱 CyberNex — USB Mobile Device Security Monitoring & Forensic Guide

Comprehensive engineering and operational guide for conducting authorized USB Android security audits, permission analysis, threat detection, and blockchain verification using **CyberNex**.

---

## 📋 Table of Contents
1. [Architecture & Diagnostic Philosophy](#1-architecture--diagnostic-philosophy)
2. [Windows Setup & ADB Platform-Tools Installation](#2-windows-setup--adb-platform-tools-installation)
3. [Android Device Configuration (Developer Mode & USB Debugging)](#3-android-device-configuration-developer-mode--usb-debugging)
4. [Security Inspection Surfaces](#4-security-inspection-surfaces)
5. [Malware Detection & Heuristic Classification Model](#5-malware-detection--heuristic-classification-model)
6. [Blockchain Audit Integration & Privacy Safeguards](#6-blockchain-audit-integration--privacy-safeguards)
7. [Apple iOS Diagnostic & Feasibility Assessment](#7-apple-ios-diagnostic--feasibility-assessment)
8. [Troubleshooting & FAQ](#8-troubleshooting--faq)

---

## 1. Architecture & Diagnostic Philosophy

Modern enterprise security boundaries extend to mobile devices connected via USB cables to corporate workstations. USB-connected devices can act as malicious drop vectors, malicious charging payloads ("Juice Jacking"), or exfiltration bridges.

**CyberNex** provides non-invasive, authorized diagnostic monitoring using the **Android Debug Bridge (ADB)** interface:
- **Zero-Payload & Privacy Preservation:** Strictly audits package metadata, installation sources, and declared/granted permissions. CyberNex **never** accesses personal text messages (SMS contents), photos, contact lists, browsing history, or private credentials.
- **Privacy-Preserving Device Identifiers:** Hardware serials, IMEIs, and phone numbers are deterministically hashed via SHA-256 (`DEVICE-<hash>`) prior to display or blockchain ledger commitment.
- **Evidence-Based Threat Classification:** Categorizes security findings into **SAFE**, **LOW RISK**, **SUSPICIOUS**, or **HIGH RISK** mapped directly to MITRE ATT&CK Mobile techniques.
- **Tamper-Evident Ledger Audit:** Mines Proof-of-Work SHA-256 audit blocks for every mobile security scan.

---

## 2. Windows Setup & ADB Platform-Tools Installation

To audit physical Android phones connected to your Windows computer, Android SDK Platform-Tools (`adb.exe`) is required.

### Step 1: Download Android Platform-Tools
1. Download the official standalone package from Google Android Developers:
   [https://developer.android.com/tools/releases/platform-tools](https://developer.android.com/tools/releases/platform-tools)
2. Extract the ZIP archive (e.g., to `C:\platform-tools` or `%LOCALAPPDATA%\Android\Sdk\platform-tools`).

### Step 2: Add ADB to Windows PATH (Optional but Recommended)
1. Open PowerShell and run:
   ```powershell
   [System.Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\platform-tools", "User")
   ```
2. Or configure a custom path directly in CyberNex.

### Step 3: Verify ADB on Windows
In PowerShell:
```powershell
adb version
```
Expected output:
```
Android Debug Bridge version 1.0.41
Version 35.0.1-...
```

---

## 3. Android Device Configuration (Developer Mode & USB Debugging)

To allow CyberNex to inspect application permissions and OS settings:

### Step 1: Enable Developer Options
1. Open **Settings** > **About phone** (or **Settings** > **System** > **About phone**).
2. Tap **Build number** exactly **7 times** consecutively.
3. When prompted, enter your device PIN/pattern. A toast will confirm: *"You are now a developer!"*.

### Step 2: Enable USB Debugging
1. Go to **Settings** > **System** > **Developer options** (on Samsung: **Settings** > **Developer options**).
2. Scroll to the **Debugging** section.
3. Toggle **USB debugging** to **ON**.

### Step 3: Connect USB Cable & Authorize
1. Connect your phone to your PC using a high-grade data USB cable.
2. Unlock your phone.
3. A popup prompt will appear:
   ```
   Allow USB debugging?
   The computer's RSA key fingerprint is:
   XX:XX:XX:XX:...
   [✓] Always allow from this computer
   [Cancel]  [Allow]
   ```
4. Check **"Always allow from this computer"** and tap **Allow**.

### Step 4: Verify Connection in CyberNex
1. Launch CyberNex:
   ```powershell
   streamlit run app.py
   ```
2. Navigate to **`📱 Mobile Device Security`** > **`🔌 A. Connected Devices`**.
3. Your device model will appear with `STATUS: DEVICE` (Authorized).

---

## 4. Security Inspection Surfaces

CyberNex executes non-invasive diagnostic package manager queries:

| Command Surface | Purpose | Privacy Boundary |
|:---|:---|:---|
| `adb devices -l` | Enumerate connected devices & transport IDs | Hardware serial hashed immediately |
| `adb shell getprop` | OS release, API level, SELinux mode, build tags | Read-only OS properties |
| `adb shell pm list packages -3` | Enumerate user-installed third-party packages | Ignores app data directories |
| `adb shell pm get-install-source <pkg>` | Verify if installed via Google Play vs Sideloaded | Metadata only |
| `adb shell dumpsys package <pkg>` | Extract declared and granted permissions | Zero credential extraction |
| `adb shell settings get ...` | Audit Unknown Sources & Developer Options posture | System flags only |

---

## 5. Malware Detection & Heuristic Classification Model

### Critical Android Permissions (MITRE ATT&CK Mobile)

1. **`android.permission.BIND_ACCESSIBILITY_SERVICE` (MITRE `T1452`):**
   - **Severity:** CRITICAL
   - **Threat Vector:** Primary vector for Android Banking Trojans (e.g., SharkBot, FluBot, Xenomorph). Enables reading text across other apps, logging keystrokes, and clicking UI buttons autonomously to transfer funds.
2. **`android.permission.SYSTEM_ALERT_WINDOW` (MITRE `T1453`):**
   - **Severity:** HIGH
   - **Threat Vector:** Tapjacking and credential phishing. Draws transparent or look-alike overlay windows atop banking/crypto apps to capture entered credentials.
3. **`android.permission.REQUEST_INSTALL_PACKAGES` (MITRE `T1475`):**
   - **Severity:** HIGH
   - **Threat Vector:** Silent dropper. Downloads and prompts background installation of secondary malicious payloads without Play Protect gatekeeping.
4. **`android.permission.BIND_DEVICE_ADMIN` (MITRE `T1401`):**
   - **Severity:** CRITICAL
   - **Threat Vector:** Ransomware / Device Locker persistence. Hijacks lock screen policies and prevents user uninstallation.
5. **`android.permission.READ_SMS` / `RECEIVE_SMS` (MITRE `T1412`):**
   - **Severity:** HIGH
   - **Threat Vector:** 2FA OTP Interception & SMS Toll Fraud.

### Heuristic Risk Scoring Rules

- **HIGH RISK (Critical Threat):**
  - Sideloaded APK + Accessibility Service.
  - Sideloaded APK + Overlay Window + SMS Read / Dropper.
  - Sideloaded APK + Device Administrator Rights.
  - SELinux Kernel in `Permissive` or `Disabled` mode.
  - Debuggable Kernel (`ro.debuggable=1`).
- **SUSPICIOUS (Action Advised):**
  - Sideloaded APK requesting Microphone, Camera, or Background Geolocation.
  - Unknown Sources sideloading toggle actively enabled.
  - Custom ROM signed with public AOSP `test-keys`.
- **LOW RISK (Advisory):**
  - USB Debugging actively enabled (expected during audit, advisory for mobile use).
  - Verified Google Play Store app using sensitive permissions proportional to its function.
- **SAFE:**
  - Verified Store app with standard, proportional permissions and no malware signatures.

### Device Security Score Calculation
$$\text{Score} = \max\Big(5, \min\big(100, 100 - (28 \times N_{\text{high}}) - (12 \times N_{\text{suspicious}}) - (3 \times N_{\text{low}})\big)\Big)$$

- **90 - 100:** Hardened / Secure Posture.
- **70 - 89:** Moderate Risk / Action Advised.
- **0 - 69:** Critical Threat Detected / Immediate Remediation Required.

---

## 6. Blockchain Audit Integration & Privacy Safeguards

Every mobile security scan generates an immutable block linking to CyberNex's SHA-256 hash-chain:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MOBILE SCAN AUDIT BLOCK                         │
├────────────────────────────────────────────────────────────────────────┤
│ Index:           #27                                                   │
│ Event ID:        MOB-E498A1B29F41                                      │
│ Data Source:     MOBILE_SECURITY                                       │
│ Prediction:      HIGH RISK                                             │
│ Security Score:  42 / 100                                              │
│ Device ID:       DEVICE-E720BC84A1D5 (Hashed Serial)                   │
│ Findings Digest: SHA-256(canonical JSON of all findings)               │
│ Previous Hash:   00a89d71f...                                          │
│ Current Hash:    0048102f6... (Mined PoW Difficulty = 2)               │
└────────────────────────────────────────────────────────────────────────┘
```

### Privacy Guarantee
- **No IMEI Numbers:** Never collected or stored.
- **No Phone Numbers or IMSI:** Never collected or stored.
- **No Message Payloads:** Text messages, chats, and photos are never read or stored.
- **No Personal Browsing History:** Zero URL or browsing history telemetry.

---

## 7. Apple iOS Diagnostic & Feasibility Assessment

### Core Architectural Disparities: Android ADB vs Apple iOS

| Architectural Dimension | Android ADB Architecture | Apple iOS Architecture |
|:---|:---|:---|
| **USB Diagnostic Daemon** | Open ADB daemon built into AOSP | Proprietary `lockdownd` & `usbmuxd` |
| **Shell Access** | Full unprivileged shell via `adb shell` | Completely blocked without jailbreak |
| **Application Isolation** | Sandboxed UID, but public metadata inspectable via `pm` | Strict XNU Kernel Container Sandbox (`Containers/Data/...`) |
| **Permission Queries** | Full dumpsys inspection (`dumpsys package`) | Governed by TCC daemon; external host blocked |
| **Installation Source** | Queryable (`pm get-install-source`) | All non-enterprise apps signed by App Store |
| **Enterprise Fleet Option** | ADB / Android Enterprise MDM | Apple Business Manager / MDM Configuration Profiles |

### Conclusion on iOS USB Monitoring
Direct, unprivileged USB inspection of installed iOS app sandboxes is **architecturally blocked by Apple's kernel-enforced sandboxing**. Enterprise organizations must deploy **Mobile Device Management (MDM)** (e.g. Microsoft Intune, Jamf Pro) with Supervised Device enrollment to maintain app inventories and compliance reporting for iOS fleets.

---

## 8. Troubleshooting & FAQ

### Q1: `adb` is not recognized as an internal or external command.
**Solution:** Ensure platform-tools is downloaded and extracted. Add `C:\platform-tools` to your system PATH, or launch CyberNex where realistic simulation devices are available for demonstration.

### Q2: Device status shows `unauthorized`.
**Solution:** Unlock your Android phone. Look for the prompt *"Allow USB debugging? The computer's RSA key fingerprint is..."*, check *"Always allow"*, and tap **Allow**. Then click **"🔄 Refresh Devices"** in CyberNex.

### Q3: No devices appear when the phone is plugged in.
**Solution:**
1. Check your USB cable (ensure it is a data cable, not charge-only).
2. On Android, change the USB connection mode from *'Charging only'* to *'File Transfer / MTP'*.
3. Ensure **USB Debugging** is toggled ON under Developer Options.
4. On Windows, verify that the Google USB Driver or OEM USB Driver (Samsung, Google, Xiaomi) is installed in Windows Device Manager.

### Q4: How do I disconnect or stop monitoring?
**Solution:** Click **"🛑 Stop / Disconnect Monitoring"** in Tab A, or simply unplug the USB cable.

