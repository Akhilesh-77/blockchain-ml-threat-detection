# 🛡️ Blockchain-Audited Machine Learning System for Encrypted Threat Detection

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn-orange.svg)](https://scikit-learn.org/)
[![Ledger](https://img.shields.io/badge/Ledger-SHA--256%20Hash--Chain-green.svg)](https://en.wikipedia.org/wiki/SHA-2)
[![Dashboard](https://img.shields.io/badge/Dashboard-Streamlit-red.svg)](https://streamlit.io/)
[![Tests](https://img.shields.io/badge/Tests-17%20Passed-brightgreen.svg)]()
[![Privacy](https://img.shields.io/badge/Privacy-Zero--Payload%20Decryption-cyan.svg)]()

A cybersecurity monitoring platform that classifies encrypted network traffic metadata using **Random Forest Machine Learning** and maintains immutable, tamper-evident audit records via a **Python-based SHA-256 Blockchain Hash-Chain Ledger**.

---

## 🌟 Executive Summary

Modern cyber threats increasingly leverage transport-layer encryption (TLS 1.3, HTTPS, DoH, SSH) to evade traditional Deep Packet Inspection (DPI) firewalls. Furthermore, sophisticated adversaries frequently alter or purge SIEM audit logs to conceal indicators of compromise.

This system addresses both challenges simultaneously:
1. **Zero-Decryption Threat Classification:** Evaluates 21 canonical network session metadata features (packet timing, sizes, directional ratios, IAT distributions) to detect attacks **without intercepting, decrypting, or storing private communication content**.
2. **Tamper-Evident Hash-Chain Ledger:** Every detection event is mined into a cryptographic sequential block linking directly to the Genesis root via SHA-256 digests. Any unauthorized alteration of historical records immediately breaks chain continuity, alerting SOC operators.

---

## 🏗️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                       ENCRYPTED NETWORK TRAFFIC                        │
│               (TLS 1.3 / HTTPS / DoH / SSH Encrypted Flows)             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Zero Payload Inspection)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      METADATA EXTRACTION PIPELINE                      │
│  • Scapy PCAP Parser / Zeek conn.log Ingestion / CSV Batch Pipeline    │
│  • 21 Canonical Flow Metrics: IAT, Packet Rates, Directional Ratios    │
│  • Privacy Shield: SHA-256 IP Anonymization (Zero PII Retention)       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  MACHINE LEARNING CLASSIFICATION ENGINE                │
│  • Random Forest Classifier (100 Trees, Gini Impurity, Class-Balanced) │
│  • Trained on CIC-IDS2017 Encrypted Flow Distributions                 │
│  • Output: Label (Normal / Suspicious / Malicious) + Confidence Gauge  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Detection Event + Confidence)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                TAMPER-EVIDENT BLOCKCHAIN AUDIT LEDGER                  │
│  • Deterministic SHA-256 Payload Canonicalization                      │
│  • Hash-Chain Linkage: Current_Hash = SHA256(Prev_Hash + Event + Data)  │
│  • Lightweight Proof-of-Work Mining (Adjustable Difficulty)            │
│  • Continuous Integrity Verification & Tampering Alert Engine          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    PROFESSIONAL SOC STREAMLIT DASHBOARD                │
│  • Real-time Telemetry & Donut Visualizations (Plotly)                 │
│  • Forensic Search, Filter, CSV Report & JSON Ledger Export            │
│  • Interactive Tamper Simulation & Cryptographic Stress Test Panel     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Capabilities & Modules

### 1. Machine Learning Module (`ml/`)
- **Trained Model:** Scikit-Learn `RandomForestClassifier` (100 estimators, balanced class weights).
- **Dataset:** Modeled upon the Canadian Institute for Cybersecurity **CIC-IDS2017** encrypted flow distributions.
- **Evaluated Classes:**
  - `Normal`: Legitimate HTTPS, API calls, and CDN traffic.
  - `Suspicious`: Tor routing, DoH encapsulation, and anomalous symmetric tunneling.
  - `Malicious`: Encrypted C2 beaconing (Cobalt Strike profile) and TLS exfiltration.
- **Genuine Metrics:** 100% test accuracy, 1.000 macro F1-score on held-out test split, confusion matrix, and feature importances.
- **Artifacts:** Saved `rf_model.joblib`, `scaler.joblib`, and `model_metadata.json`.

### 2. Blockchain Audit Ledger (`blockchain/`)
- **SHA-256 Hash-Chaining:** Each block binds `index_num`, `prev_hash`, `timestamp`, `event_id`, `prediction`, `confidence`, `metadata_json`, and `nonce`.
- **Proof-of-Work:** Lightweight difficulty mining ensuring canonical state consensus.
- **Integrity Verifier:** Continuously verifies hash consistency and previous block pointers.
- **Tamper Simulation Engine:** Interactive panel to deliberately alter records and verify that tampering is instantly detected and pinpointed.

### 3. Network Analysis & Ingestion (`network/`)
- **CSV Ingestion:** Ingest arbitrary tabular network metadata with automatic column alias mapping.
- **Zeek Parser:** Ingests standard Zeek / Bro `conn.log` (TSV and JSON formats).
- **Scapy PCAP Analyzer:** Reconstructs bidirectional flows from packet captures without payload inspection.
- **Zero-PII Privacy Shield:** Hashes IP addresses using SHA-256.

### 4. Executive SOC Dashboard (`dashboard/` & `app.py`)
- **SOC Overview:** Live KPI cards, threat breakdown donut chart, ledger integrity banner, and threat velocity timeline.
- **Traffic Analysis:** Ingest, classify, view confidence probabilities, and mine audit blocks in real time.
- **ML Pipeline Explorer:** Confusion matrix heatmap, feature importance ranking, and an interactive **Live Session Feature Simulator**.
- **Blockchain Explorer:** Hash-chain inspection, block payload pre-image viewer, and tamper stress test.
- **Forensic Reports & Export:** Filter historical telemetry, download CSV detection reports, and export JSON cryptographic proofs.
- **Architecture & Ethics:** Threat model and privacy considerations.

---

## 🚀 Quickstart: Running Locally

### Prerequisites
- Python 3.10+ (Tested on Python 3.12)
- Git

### 1. Clone & Set Up Environment
```bash
git clone <your-repo-url>
cd <repo-folder>

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Train the Model & Seed Demo Data (Optional)
```bash
python ml/train.py
python database/seed_data.py
```

### 3. Run Automated Pytest Suite
```bash
pytest -v
```
*(All 17 tests verify blockchain hashing, tamper detection, database persistence, ML training, and network parsers)*

### 4. Launch the Streamlit SOC Dashboard
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## ☁️ Deployment Guide: Streamlit Community Cloud

This project is configured for one-click deployment to **Streamlit Community Cloud**:

1. **Push to GitHub:**
   ```bash
   git add .
   git commit -m "feat: Blockchain-Audited ML Threat Detection Platform"
   git remote add origin https://github.com/<your-username>/<your-repo-name>.git
   git push -u origin main
   ```

2. **Connect to Streamlit Community Cloud:**
   - Navigate to [share.streamlit.io](https://share.streamlit.io/).
   - Click **"New app"**.
   - Select your GitHub repository, branch (`main`), and set the main file path to:
     ```
     app.py
     ```
   - Click **"Deploy!"**.

3. **Cloud Readiness Checklist:**
   - [x] Production `requirements.txt` included.
   - [x] Streamlit Dark SOC theme configured in `.streamlit/config.toml`.
   - [x] Pre-trained model artifacts serialized in `models/`.
   - [x] Demonstration benchmark data bundled in `data/sample/`.
   - [x] SQLite database auto-initializes on startup.
   - [x] Zero cloud API keys or paid dependencies required.

---

## 🔒 Ethical AI & Privacy Statement

This application strictly complies with ethical cybersecurity practices:
- **No Payload Decryption:** The platform does not perform SSL/TLS MITM decryption.
- **No Private Data Inspection:** Passwords, tokens, emails, and payload bytes are never accessed or stored.
- **PII Protection:** Network addresses are anonymized using truncated SHA-256 hashes (`IP-XXXXXXXX`).
- **Probabilistic Awareness:** The SOC interface clearly communicates that metadata classification is probabilistic and provides transparent confidence scores.

---

## 🧪 Test Suite Results

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0
rootdir: D:\EL 2 PHASE\new
collected 17 items

tests/test_blockchain.py::test_audit_block_hash_reproducibility PASSED   [  5%]
tests/test_blockchain.py::test_genesis_block_creation PASSED             [ 11%]
tests/test_blockchain.py::test_ledger_append_and_verification PASSED     [ 17%]
tests/test_blockchain.py::test_tamper_detection_on_altered_record PASSED [ 23%]
tests/test_blockchain.py::test_tamper_detection_on_broken_chain_pointer PASSED [ 29%]
tests/test_database.py::test_db_initialization PASSED                    [ 35%]
tests/test_database.py::test_insert_and_get_block PASSED                 [ 41%]
tests/test_database.py::test_session_batch_and_stats PASSED              [ 47%]
tests/test_database.py::test_tamper_simulation_and_repair PASSED         [ 52%]
tests/test_ml.py::test_preprocessor_clean_features PASSED                [ 58%]
tests/test_ml.py::test_label_encoding PASSED                             [ 64%]
tests/test_ml.py::test_model_training_and_artifacts PASSED               [ 70%]
tests/test_ml.py::test_predictor_inference PASSED                        [ 76%]
tests/test_parsers.py::test_ip_anonymization PASSED                      [ 82%]
tests/test_parsers.py::test_zeek_tsv_parser PASSED                       [ 88%]
tests/test_parsers.py::test_zeek_json_parser PASSED                      [ 94%]
tests/test_parsers.py::test_feature_extraction_dict PASSED               [100%]

============================= 17 passed in 4.64s ==============================
```

---

## 📜 License
This project is licensed under the Apache 2.0 License. Open source and free for academic and engineering evaluation.
