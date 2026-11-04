# 🛡️ SOC Sentinel — Real-World Testing & Validation Guide

Comprehensive engineering and operational guide for conducting real-world network traffic testing, public dataset validation, and cryptographic blockchain verification using **SOC Sentinel**.

---

## 📋 Table of Contents
1. [Architecture & Testing Philosophy](#1-architecture--testing-philosophy)
2. [Data Source Classification Standard](#2-data-source-classification-standard)
3. [Windows Setup & Live Packet Capture](#3-windows-setup--live-packet-capture)
4. [Zeek Installation & conn.log Workflow](#4-zeek-installation--connlog-workflow)
5. [Public Dataset Testing: UNB CIC-IDS2017](#5-public-dataset-testing-unb-cic-ids2017)
6. [Controlled Security Testing (Laboratory Mode)](#6-controlled-security-testing-laboratory-mode)
7. [Machine Learning Provenance & Verification](#7-machine-learning-provenance--verification)
8. [Blockchain Audit Ledger & Tamper Verification](#8-blockchain-audit-ledger--tamper-verification)

---

## 1. Architecture & Testing Philosophy

SOC Sentinel is designed to eliminate artificial or fabricated cybersecurity metrics. Every dashboard statistic, chart, and alert is derived strictly from:
1. Measured socket/packet flow metadata.
2. Formally trained Random Forest classifier inference.
3. Persistent SQLite session tables.
4. Cryptographically linked SHA-256 blockchain blocks.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DATA SOURCE CLASSIFICATION                      │
│                                                                        │
│  [1. LIVE_NETWORK]     [2. PUBLIC_DATASET]    [3. CONTROLLED_LAB]      │
│   Real live TCP/TLS    UNB CIC-IDS2017 CSVs   Isolated Loopback 127.0  │
│   (Google, YouTube)    (Known Attack Labels)  (Beacon / Tor Simulation)│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Zero Payload Decryption)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      METADATA EXTRACTION PIPELINE                      │
│      21 Flow Features: Duration, IAT, Bytes, Packets, TCP Flags        │
│      Privacy Shield: SHA-256 IP Anonymization (Zero PII Retention)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       RANDOM FOREST CLASSIFIER                         │
│               Normal (0)  |  Suspicious (1)  |  Malicious (2)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  TAMPER-EVIDENT SHA-256 HASH-CHAIN                     │
│    Binds Event ID + Pred + Confidence + Source + Metadata Hash         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Source Classification Standard

Every telemetry record, block, and dashboard widget explicitly displays its origin tag:

| Tag | Badge | Description |
| :--- | :--- | :--- |
| `LIVE_NETWORK` | `LIVE NETWORK DATA` | Real live traffic captured from network interface or live socket requests (Google, YouTube, etc.). |
| `PUBLIC_DATASET` | `PUBLIC DATASET` | Authentic public benchmark datasets (e.g. UNB CIC-IDS2017) containing labelled ground truth. |
| `CONTROLLED_LAB` | `CONTROLLED_LAB` | Local isolated tests executed strictly against loopback (`127.0.0.1`). |
| `SYNTHETIC_DEMO` | `SYNTHETIC DEMO` | Statistical benchmark samples used exclusively for demonstration. |

If no live traffic has been collected, the Overview dashboard explicitly displays:
```
⚠️ NO LIVE NETWORK DATA AVAILABLE.
```

---

## 3. Windows Setup & Live Packet Capture

SOC Sentinel supports two live capture engines on Windows:

### Engine 1: Unprivileged Live Web Generator (Recommended — No Admin Required)
This engine does not require administrative privileges or third-party drivers. It establishes real TLS 1.3 socket connections to legitimate external endpoints, measures transport-layer duration, packet chunks, byte rates, and inter-arrival times:
1. Open the dashboard: `streamlit run app.py`.
2. Navigate to **`🧪 Real-World Test Lab`** ➔ **`📡 A. Live Traffic Capture`**.
3. Select any target destination:
   - `www.google.com` (Search queries, TLS 1.3 web requests)
   - `www.youtube.com` (Video CDN buffering)
   - `www.wikipedia.org` (Knowledge API)
   - `www.cloudflare.com` (Edge proxy)
4. Click **"Connect & Measure Live Session"**.
5. The measured session is classified by the ML model in real time and can be committed to the blockchain ledger.

### Engine 2: Scapy Promiscuous Sniffer (Requires Npcap)
To sniff raw frames from your wireless or Ethernet interface:
1. Download and install **Npcap** from [https://npcap.com/#download](https://npcap.com/#download).
2. During setup, check **"Install Npcap in WinPcap API-compatible Mode"**.
3. Open an administrative PowerShell prompt and launch:
   ```powershell
   streamlit run app.py
   ```
4. In **`📡 A. Live Traffic Capture`**, select your network adapter and click **"Start Live Sniffing"**.

---

## 4. Zeek Installation & conn.log Workflow

Zeek (formerly Bro) is the industry standard for network security monitoring.

### Step 1: Install Zeek on Windows (via WSL2)
```bash
# In Windows Subsystem for Linux (WSL2 Ubuntu):
sudo apt update
sudo apt install -y zeek
```

### Step 2: Generate conn.log from Live Traffic or PCAP
```bash
# Capture live interface traffic:
sudo zeek -i eth0

# Or process an existing PCAP file:
zeek -C -r capture.pcap
```
This produces `conn.log` in the current working directory.

### Step 3: Ingest into SOC Sentinel
1. Open the SOC Sentinel dashboard.
2. In **`📡 Traffic Analysis`**, select **"Upload Zeek conn.log"**.
3. Upload `conn.log`.
4. The system automatically parses session durations, bytes, packets, and connection states (`SF`, `REJ`, `S0`) and feeds them into the ML model.

---

## 5. Public Dataset Testing: UNB CIC-IDS2017

Official source: [University of New Brunswick CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)

### Supported CSV Files:
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
- `Wednesday-workingHours.pcap_ISCX.csv`

### Feature Mapping:
The loader automatically strips whitespace and maps UNB column headers to the 21 internal features:
- ` Flow Duration` ➔ `flow_duration` (microseconds automatically converted to seconds)
- ` Total Fwd Packets` ➔ `total_fwd_packets`
- ` Total Backward Packets` ➔ `total_bwd_packets`
- `Total Length of Fwd Packets` ➔ `total_fwd_bytes`
- `Total Length of Bwd Packets` ➔ `total_bwd_bytes`
- ` Fwd Packet Length Mean` ➔ `fwd_packet_length_mean`
- ` Bwd Packet Length Mean` ➔ `bwd_packet_length_mean`
- ` Flow IAT Mean` ➔ `flow_iat_mean`
- ` Flow IAT Std` ➔ `flow_iat_std`
- ` Down/Up Ratio` ➔ `down_up_ratio`
- ` Label` ➔ Preserved as ground truth for validation!

### Validation Procedure:
1. Navigate to **`🧪 Real-World Test Lab`** ➔ **`📊 B. Public Dataset Testing`**.
2. Either upload a downloaded UNB CSV or select the bundled verified subset (`data/sample/cic_ids2017_sample.csv`).
3. Click **"Run ML Model Evaluation on Public Dataset"**.
4. The system compares the model's predictions directly against known labels, displaying:
   - Confusion Matrix
   - Accuracy
   - Macro & Weighted Precision
   - Macro & Weighted Recall
   - Macro F1-Score
5. Click **"Save as Validated Experiment in Database"** to permanently record the run in the experiment registry.

---

## 6. Controlled Security Testing (Laboratory Mode)

All security pattern tests are **strictly restricted to localhost loopback (`127.0.0.1`)**:

1. **Tor / DoH Cell Tunneling Simulator:**
   - Tests fixed 512-byte chunk alignment (Tor cell structure).
   - Generates low-jitter symmetric packet timing.
2. **Periodic C2 Beaconing Simulator:**
   - Tests deterministic heartbeat intervals (e.g. 1.0s) with negligible jitter (`std < 0.005`).
3. **Rapid Volumetric Burst Simulator:**
   - Tests abrupt bursts of high-velocity TCP attempts over local loopback.
4. **Normal Local Web Service:**
   - Tests standard asymmetric client-server interaction on loopback.

---

## 7. Machine Learning Provenance & Verification

To verify that the model is legitimately trained:
1. Navigate to **`🧠 Machine Learning`**.
2. The provenance card displays:
   - **Model Name:** SOC Sentinel Random Forest Threat Classifier v2.0
   - **Algorithm:** Random Forest (100 estimators, balanced class weights, max depth 16)
   - **Training Dataset:** CIC-IDS2017 Encrypted Flow Distributions Benchmark
   - **Training Records:** 2,400 stratified flows
   - **Testing Records:** 600 held-out flows
   - **Data Leakage Safeguard:** Preprocessor (`StandardScaler`) was fit exclusively on the training split and applied identically during inference.
3. If model artifacts are missing or deleted, the dashboard immediately alerts:
   ```
   ⚠️ MODEL NOT TRAINED — No pre-trained model found.
   ```

---

## 8. Blockchain Audit Ledger & Tamper Verification

Every detection event commits a block containing:
- `index_num`: Sequential block index.
- `event_id`: Unique event UUID.
- `timestamp`: UTC timestamp.
- `prediction`: Detection category (`Normal`, `Suspicious`, `Malicious`).
- `confidence`: Prediction probability score.
- `data_source`: Origin tag (`LIVE_NETWORK`, `PUBLIC_DATASET`, `CONTROLLED_LAB`, `SYNTHETIC_DEMO`).
- `metadata_json`: Sanitized flow metrics.
- `metadata_hash`: Cryptographic SHA-256 digest of input flow features.
- `prev_hash`: SHA-256 link to prior block.
- `current_hash`: Block SHA-256 digest.
- `nonce`: Proof-of-work solution.

### Tamper-Evidence Demonstration:
1. Navigate to **`⛓️ Blockchain Audit`**.
2. Under **"Tamper Simulation & Stress Test"**, select any block and alter its classification in SQLite.
3. Click **"Verify Entire Ledger Integrity"**.
4. The verification engine immediately flags:
   ```
   🚨 TAMPER DETECTED in Block #X! The block data was modified without a valid cryptographic re-mine.
   ```
5. Click **"Restore / Repair Block Authentic State"** to restore data authenticity.
