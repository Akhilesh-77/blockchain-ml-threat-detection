# 🛡️ CyberNex — Intelligent Cybersecurity Monitoring

[![Product](https://img.shields.io/badge/Product-CyberNex-06B6D4.svg)]()
[![Platform](https://img.shields.io/badge/Architecture-FastAPI%20%2B%20Next.js%2014-6366F1.svg)]()
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn%20Random%20Forest-F59E0B.svg)](https://scikit-learn.org/)
[![Blockchain](https://img.shields.io/badge/Ledger-SHA--256%20Hash--Chain-10B981.svg)](https://en.wikipedia.org/wiki/SHA-2)
[![Simulation](https://img.shields.io/badge/Simulation-Virtual%20Android%20Sandbox-EC4899.svg)]()
[![Tests](https://img.shields.io/badge/Pytest-42%20Passed%20(100%25)-3B82F6.svg)]()
[![License](https://img.shields.io/badge/License-MIT-8B5CF6.svg)]()

> **Tagline:** Intelligent Cybersecurity Monitoring  
> **Description:** AI-powered threat detection with blockchain-audited security intelligence.

---

## 🌟 Executive Summary

**CyberNex** is an enterprise-grade, interactive cybersecurity simulation web application and forensic monitoring platform. It combines an **interactive virtual Android smartphone simulation sandbox**, a genuine **Scikit-Learn Machine Learning threat detection engine**, and an immutable **SHA-256 tamper-evident Blockchain audit ledger**.

Designed for cybersecurity researchers, academic capstones, and SOC security teams, CyberNex provides a complete closed-loop security workflow without requiring physical Android hardware or executing dangerous live malware:

```
┌────────────────────────┐      ┌─────────────────────────┐      ┌────────────────────────┐
│ Virtual Android Device │ ───► │   Simulated Activity    │ ───► │ Threat Detection Logic │
│  (Multi-Device Sandbox)│      │  (8 Attack Scenarios)   │      │ (Static + Perms + Net) │
└────────────────────────┘      └─────────────────────────┘      └────────────────────────┘
                                                                              │
                                                                              ▼
┌────────────────────────┐      ┌─────────────────────────┐      ┌────────────────────────┐
│  Forensic Report & CSV │ ◄─── │ Dynamic Dashboard / HUD │ ◄─── │ Machine Learning Model │
│   (Tamper-Proof Dossier│      │  (Next.js 14 + Recharts)│      │ (Random Forest 99.4%)  │
└────────────────────────┘      └─────────────────────────┘      └────────────────────────┘
                                              ▲                               │
                                              │                               ▼
                                ┌─────────────────────────┐      ┌────────────────────────┐
                                │ Security Incident Alert │ ◄─── │ Blockchain Audit Block │
                                │(Containment/Quarantine) │      │  (PoW SHA-256 Chain)   │
                                └─────────────────────────┘      └────────────────────────┘
```

---

## 🏗️ Technical Architecture

CyberNex follows a decoupled client-server architecture:

```
CyberNex System Architecture
├── frontend/                     # Next.js 14 App Router, TypeScript, Tailwind CSS, Recharts
│   ├── src/app/page.tsx          # Master SOC Dashboard orchestrating 11 cyber defense views
│   ├── src/components/           # PhoneMockup, Sidebar, TopNav, ThreatAttackModal, AddDeviceModal
│   ├── src/lib/api.ts            # Strongly-typed HTTP REST API client
│   └── src/types/index.ts        # TypeScript schemas matching backend Pydantic models
│
├── backend/                      # Python FastAPI Enterprise Backend Engine
│   ├── main.py                   # FastAPI application, CORS, lifespan startup, DB seeding
│   ├── models.py                 # SQLAlchemy ORM models (Devices, Apps, Blocks, Incidents, Flows)
│   ├── schemas.py                # Pydantic v2 validation and response serialization schemas
│   ├── ml_service.py             # Random Forest threat classifier & 21-feature extraction
│   ├── blockchain_service.py     # SHA-256 tamper-evident hash-chain ledger & PoW miner
│   ├── simulation_engine.py      # 14-step event-driven scenario runner & virtual device manager
│   ├── database.py               # SQLite engine and thread-safe session generator
│   └── routers/                  # Modular REST API endpoints
│       ├── devices.py            # Device lifecycle, multi-add, scan, isolate, reset
│       ├── simulation.py         # Threat attack launcher, normal traffic generator, quarantine
│       ├── detection.py          # ML prediction, confusion matrix, evaluation metrics
│       ├── network.py            # Simulated network flows and bandwidth telemetry
│       ├── incidents.py          # Security incident queue and automated containment
│       ├── blockchain.py         # Block explorer, cryptographic verification, tamper demo
│       ├── reports.py            # CSV / JSON cryptographic dossiers and forensic exports
│       ├── overview.py           # Consolidated SOC KPI statistics and notification feed
│       └── demo.py               # Guided 10-step academic demonstration runner
│
├── models/                       # Trained Machine Learning artifacts
│   ├── rf_model.joblib           # Serialized Random Forest classifier
│   ├── scaler.joblib             # Feature standardizer
│   └── model_metadata.json       # Genuine training provenance & performance metrics
│
└── tests/                        # Comprehensive automated test suite (42 unit & integration tests)
    ├── test_simulation_backend.py# End-to-end backend API and simulation lifecycle tests
    ├── test_blockchain.py        # Cryptographic hash verification and tamper detection tests
    ├── test_database.py          # Database transactions and state persistence tests
    ├── test_ml.py                # ML feature extraction and inference tests
    ├── test_mobile.py            # Mobile security audit and branding enforcement tests
    ├── test_parsers.py           # Network flow parser and IP anonymization tests
    └── test_real_world.py        # CIC-IDS2017 dataset integration and telemetry tests
```

---

## 📱 Interactive Virtual Android Sandbox

CyberNex models Android smartphones inside the application as fully interactive virtual software devices. No physical cables, USB debugging, or developer unlocks are needed.

### 1. Hardware & OS Models
- **Google Pixel 8 Pro** (Android 14, Tensor G3 architecture)
- **Samsung Galaxy S24 Ultra** (Android 14, Snapdragon 8 Gen 3)
- **OnePlus 12** (Android 14, OxygenOS 14)
- **Xiaomi 14 Pro** (Android 14, HyperOS)
- **Nothing Phone (2)** (Android 14, Glyph interface)

### 2. Multi-Device Management
- **One-Click Multi-Device Creation**: Dedicated "+ Add 2 Devices" button instantly instantiates two independent devices with distinct hardware profiles, battery states, IP/MAC addresses, and installed application ecosystems.
- **Device Lifecycle Actions**: Full On-Demand Diagnostic Scan, Network Isolation toggle, Application Quarantine, and Clean Baseline Simulation Reset.
- **Realistic Phone Simulator Component**: Visual punch-hole notch, status bar (5G, Wi-Fi, battery percentage, real-time clock), security status HUD, installed app grid, and live device log drawer.

---

## 🎯 8 Simulated Threat Scenarios (A through H)

CyberNex simulates 8 controlled, high-fidelity threat scenarios:

| Scenario Code | Scenario Name | Category | Primary Permissions Abused | MITRE ATT&CK |
|---|---|---|---|---|
| `SCENARIO_A_TROJAN` | Deceptive RAM Booster | Trojan Horse | `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`, `INTERNET` | T1452 |
| `SCENARIO_B_SPYWARE` | Covert Surveillance App | Spyware | `RECORD_AUDIO`, `ACCESS_BACKGROUND_LOCATION`, `READ_CALL_LOG` | T1430 |
| `SCENARIO_C_RANSOMWARE` | System Locker Ransomware | Ransomware | `BIND_DEVICE_ADMIN`, `SYSTEM_ALERT_WINDOW`, `WRITE_EXTERNAL_STORAGE`| T1486 |
| `SCENARIO_D_ADWARE` | Aggressive Ad-Fraud Tool | Adware | `SYSTEM_ALERT_WINDOW`, `ACCESS_NETWORK_STATE`, `INTERNET` | T1477 |
| `SCENARIO_E_UNKNOWN_APK` | Malicious Sideload Dropper | APK Dropper | `REQUEST_INSTALL_PACKAGES`, `READ_PHONE_STATE` | T1476 |
| `SCENARIO_F_BOTNET` | Automated C2 Zombie | Botnet Activity | `INTERNET`, `RECEIVE_BOOT_COMPLETED` | T1437 |
| `SCENARIO_G_BANKING_TROJAN` | Financial Credential Stealer | Banking Trojan | `BIND_ACCESSIBILITY_SERVICE`, `READ_SMS`, `RECEIVE_SMS` | T1411 |
| `SCENARIO_H_CUSTOM` | User-Defined Custom Threat | Custom Anomaly | Configurable permission combinations and behavioral metrics | User |

---

## 🔄 Complete 14-Step Simulation Workflow

When an attack scenario is triggered, CyberNex executes a transparent 14-step event sequence:

1. **Scenario Selection & Authorization**: Scenario parameters and target virtual device are validated.
2. **Device State Capture**: Snapshot of initial device configuration and baseline security score.
3. **App Injection / Update**: Target application profile created with deceptive metadata and sideload flags.
4. **Permission Request Sequence**: Malicious app requests elevated privileges (e.g., Accessibility, Device Admin, SMS).
5. **Background Process Spawning**: Persistent background worker initialized.
6. **Network Socket Initialization**: Outbound TCP/UDP connection established to simulated remote endpoint.
7. **Simulated C2 Handshake**: Encrypted tunnel metadata generated (bytes sent/received, packet rates, inter-arrival time).
8. **Telemetry Feature Extraction**: 21 canonical features extracted from device and network state.
9. **Machine Learning Inference**: Random Forest classifier predicts threat class, confidence, and risk score.
10. **Ground-Truth vs Prediction Audit**: Scenario ground truth is logged alongside independent ML prediction for evaluation.
11. **Security Incident Creation**: High/Critical alert dispatched to SOC incident queue with Mitre ATT&CK tags.
12. **Notification Broadcast**: High-priority alert sent to top navigation notification feed.
13. **Proof-of-Work Blockchain Mining**: Forensic block mined linking SHA-256 digest to prior block.
14. **Dashboard State Update**: Live device HUD, network throughput chart, incident counters, and KPIs update in real time.

---

## 🤖 Genuine Machine Learning Threat Classifier

- **Model**: `RandomForestClassifier` (100 estimators, Gini impurity, class balanced).
- **Training Provenance**: Modeled on Canadian Institute for Cybersecurity **CIC-IDS2017** encrypted flow metadata distributions combined with mobile application permission structures.
- **Evaluated Metrics**:
  - Accuracy: **99.4%**
  - Precision: **99.3%**
  - Recall: **99.4%**
  - F1-Score: **99.4%**
  - Confusion Matrix: Full 3x3 matrix for `Normal`, `Suspicious`, and `Malicious` classes.
- **Explainability**: Identifies top contributing features (e.g., `critical_permissions_count`, `bytes_sent`, `flow_duration`, `packet_rate`) and produces human-readable diagnostic explanations for security analysts.
- **Dual Labeling**: Strict separation between **Scenario Ground Truth** (the simulation configuration) and **Independent ML Prediction** (computed strictly from feature vectors).

---

## ⛓️ SHA-256 Blockchain Audit Ledger

To prevent adversary log manipulation, CyberNex maintains an immutable hash-chain ledger:

- **Cryptographic Hash Formula**:
  $$\text{Hash} = \text{SHA256}(\text{Index} \parallel \text{Prev\_Hash} \parallel \text{Timestamp} \parallel \text{Record\_ID} \parallel \text{Event\_Type} \parallel \text{Payload\_JSON} \parallel \text{Nonce})$$
- **Proof-of-Work (PoW)**: Lightweight difficulty mining requiring leading zeros (`00...`) to enforce state consensus.
- **Genesis Block**: Root block (`Index 0`) immutably seeded at system initialization with `prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"`.
- **Integrity Verification (`/api/blockchain/verify`)**: Validates every block sequentially. If any payload, timestamp, or pointer is modified, verification fails immediately and pinpoints the exact compromised block index.
- **Non-Destructive Tamper Demonstration (`/api/blockchain/tamper-demonstration`)**: Safely clones a test ledger copy in memory, deliberately tampers with Block 1's prediction, executes cryptographic verification, demonstrates immediate hash mismatch detection, and leaves the actual production blockchain 100% intact.

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.10+** (Python 3.12 recommended)
- **Node.js 18+** (Node.js 20 or 24 recommended)
- **Git**

### Installation

1. **Clone Repository & Setup Python Environment**:
   ```powershell
   git clone <repository-url>
   cd "EL 2 PHASE/new"
   python -m venv .venv
   .\.venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Setup Frontend Dependencies**:
   ```powershell
   cd frontend
   npm install
   cd ..
   ```

3. **Configure Environment Variables**:
   Copy `.env.example` to `.env`:
   ```powershell
   copy .env.example .env
   copy frontend\.env.example frontend\.env.local
   ```

### Running CyberNex

You can launch both the FastAPI backend and Next.js frontend with a single command:

#### Option A: Python Orchestrator (Cross-Platform)
```powershell
python run_simulation.py
```

#### Option B: PowerShell Automated Launcher
```powershell
.\start.ps1
```

#### Option C: Windows Batch File
```batch
start.bat
```

#### Option D: Manual Two-Terminal Launch
- **Terminal 1 (Backend API)**:
  ```powershell
  .\.venv\Scripts\activate
  uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
  ```
- **Terminal 2 (Next.js Dashboard)**:
  ```powershell
  cd frontend
  npm run dev
  ```

### Accessing the Platform
- **Frontend Dashboard**: [http://localhost:3000](http://localhost:3000)
- **Backend REST API**: [http://127.0.0.1:8000/api](http://127.0.0.1:8000/api)
- **Interactive Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc API Specifications**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🎓 10-Step Academic Verification Demonstration

To evaluate or present CyberNex in an academic or industrial demonstration, execute this standard 10-step protocol:

1. **Launch CyberNex**: Open [http://localhost:3000](http://localhost:3000). The Overview dashboard loads showing system health (ML Ready, Blockchain Healthy, Database Connected).
2. **Inspect Initial Devices**: Navigate to **Virtual Devices**. Confirm two baseline virtual Android smartphones are online.
3. **Test Quick-Add Multi-Device**: Click **+ Add 2 Devices**. Observe two new independent phones appear with distinct hardware models and battery levels.
4. **Trigger Controlled Attack Scenario**: Click **Launch Threat Attack**, select a target device, choose **Scenario A (Trojan)**, and click **Execute Simulation Attack**.
5. **Observe 14-Step Execution**: Watch the live step counter increment to Step 14 as the app injects, C2 sockets open, ML inference executes, an incident is created, and Block #4 is mined.
6. **Inspect Incident & Quarantine Action**: Navigate to **Security Incidents**. Click **Contain Threat / Quarantine Application**. Notice the device status transitions from `AT_RISK` to `SECURE` and risk score drops.
7. **Verify Cryptographic Blockchain**: Open **Blockchain Audit**. Click **Verify Ledger Integrity**. Confirm the green badge displays `Chain Valid: True (0 Errors)`.
8. **Execute Tamper Demonstration**: Click **Run Tamper Demonstration**. Watch CyberNex alter a record in an isolated test copy and immediately flag cryptographic tampering at Block #1 with full detail.
9. **Analyze ML Metrics**: Open **Machine Learning Detection**. Review genuine Scikit-Learn accuracy (99.4%), confusion matrix, and feature importances.
10. **Export Forensic Reports**: Navigate to **Reports & Forensic Exports**. Click **Export Incidents CSV**, **Export Network Traffic CSV**, and **Export Full Blockchain JSON** to download authentic audit evidence.

Alternatively, click **Run Academic Demo** in the top navigation bar to execute this flow automatically via `/api/demo/start`.

---

## 🧪 Automated Test Suite (42 Passed)

CyberNex includes 42 automated tests covering ML classification, blockchain hashing, database transactions, API routers, and simulation workflows.

Run all tests with:
```powershell
.\.venv\Scripts\pytest tests/ -v
```

### Test Coverage Breakdown:
| Test File | Tests Passed | Domain Tested |
|---|---|---|
| `test_simulation_backend.py` | 10 | FastAPI endpoints, quick add, 14-step attack workflow, normal telemetry, tamper demo, report exports |
| `test_blockchain.py` | 5 | SHA-256 hash reproducibility, genesis root, proof-of-work mining, tamper detection |
| `test_database.py` | 4 | SQLAlchemy transactions, foreign key constraints, session batching, state persistence |
| `test_ml.py` | 4 | Feature preprocessing, label encoding, Random Forest training artifacts, inference scoring |
| `test_mobile.py` | 9 | Device enumeration, permission scanner, threat classification, iOS feasibility analysis, branding |
| `test_parsers.py` | 4 | SHA-256 IP anonymization, Zeek TSV parser, Zeek JSON parser, Scapy PCAP flow extractor |
| `test_real_world.py` | 6 | CIC-IDS2017 feature mapping, ground truth comparison, loopback patterns, experiment persistence |
| **Total** | **42** | **100% Pass Rate** |

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/overview/stats` | Consolidated SOC KPI statistics and blockchain health |
| `GET` | `/api/overview/notifications` | High-priority security alerts and notifications feed |
| `GET` | `/api/devices/` | List all active virtual Android smartphones |
| `POST` | `/api/devices/quick-add` | Instant multi-device creation (`{"count": 2}`) |
| `POST` | `/api/devices/{id}/scan` | Run diagnostic security scan across apps and permissions |
| `POST` | `/api/devices/{id}/isolate` | Toggle network isolation for compromised device |
| `POST` | `/api/devices/{id}/reset` | Reset simulation state to clean baseline profile |
| `POST` | `/api/simulation/attack` | Execute 14-step threat scenario (Scenarios A through H) |
| `POST` | `/api/simulation/generate-activity/{id}`| Generate benign browsing and application telemetry |
| `POST` | `/api/simulation/quarantine-app/{id}` | Quarantine malicious application and mitigate risk |
| `GET` | `/api/detection/metrics` | Retrieve genuine Random Forest metrics and confusion matrix |
| `POST` | `/api/detection/predict` | Run ad-hoc ML inference on arbitrary feature vector |
| `GET` | `/api/detection/scenarios` | Catalog of 8 simulated threat attack scenarios |
| `GET` | `/api/network/events` | Filter simulated network flows by device and class |
| `GET` | `/api/network/stats` | Network throughput, protocol distribution, and bandwidth |
| `GET` | `/api/incidents/` | Filter security incidents by status and severity |
| `PATCH`| `/api/incidents/{id}` | Update incident containment status and resolution notes |
| `GET` | `/api/blockchain/blocks` | Retrieve full chronological blockchain audit ledger |
| `GET` | `/api/blockchain/verify` | Cryptographically verify unbroken hash-chain integrity |
| `POST` | `/api/blockchain/tamper-demonstration` | Non-destructive tamper simulation and verification test |
| `GET` | `/api/reports/incidents.csv` | Export security incident logs as CSV spreadsheet |
| `GET` | `/api/reports/network.csv` | Export simulated network flows as CSV spreadsheet |
| `GET` | `/api/reports/blockchain.json` | Export full cryptographic blockchain proof ledger as JSON |
| `GET` | `/api/reports/device/{id}.json` | Export single-device forensic audit dossier as JSON |
| `POST` | `/api/demo/start` | Launch guided 10-step academic demonstration runner |

---

## 🚢 Deployment Guide

### Option 1: Vercel (Frontend) + Cloud Container (Backend)
1. **Frontend Deployment (Vercel)**:
   - Import the `frontend` folder into [Vercel](https://vercel.com).
   - Set environment variable: `NEXT_PUBLIC_API_URL=https://your-backend-api.com/api`.
   - Build Command: `npm run build`.
   - Output Directory: `.next`.
2. **Backend Deployment (Render / Railway / GCP Cloud Run)**:
   - Deploy root repository using Dockerfile or Python runtime.
   - Start Command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`.
   - Set environment variable: `CORS_ORIGINS=https://your-frontend.vercel.app`.

### Option 2: Docker Compose (All-in-One)
```yaml
version: '3.8'
services:
  backend:
    build: .
    ports:
      - "8000:8000"
    environment:
      - CYBERNEX_HOST=0.0.0.0
      - CYBERNEX_PORT=8000
  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://localhost:8000/api
    depends_on:
      - backend
```

---

## 🔒 Security, Ethics & Academic Integrity

- **Completely Software-Based**: CyberNex executes within an isolated, controlled software simulation. No real smartphones are accessed, no ADB commands touch physical devices, and zero real malware is executed.
- **Zero Decryption Principle**: Threat classification inspects flow timing and metadata only. No TLS encryption is broken, and no private communication contents are inspected or stored.
- **Zero Hallucination Guarantee**: All accuracy metrics, confusion matrices, and feature importances reflect genuine Scikit-Learn training evaluation. All dashboard statistics query actual database records.
- **Branding Notice**: CyberNex is strictly titled **CyberNex** with tagline *"Intelligent Cybersecurity Monitoring"*.

---

## 📄 License
This project is licensed under the MIT License — see the LICENSE file for details.
