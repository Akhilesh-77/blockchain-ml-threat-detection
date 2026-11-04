"""
About and System Architecture Dashboard View.
Details the cybersecurity engineering design, system architecture, ethical considerations,
technology stack, and threat model.
"""

import streamlit as st


def render_about_view() -> None:
    """Render Project Architecture, Ethical Design, and System Overview page."""
    st.markdown("""
        <div class="soc-header">
            <h1>ℹ️ System Architecture & Engineering Specifications</h1>
            <p>Comprehensive overview of the Blockchain-Audited Machine Learning System for Encrypted Threat Detection.</p>
        </div>
    """, unsafe_allow_html=True)

    # 1. Project Overview & Motivation
    st.subheader("1. Project Overview")
    st.markdown("""
    Modern cyber threats increasingly leverage transport-layer encryption (TLS 1.3, HTTPS, DoH, SSH) to evade traditional Deep Packet Inspection (DPI) firewalls. Concurrently, malicious actors and compromised insiders frequently attempt to delete or alter Security Information & Event Management (SIEM) detection logs to conceal unauthorized intrusions.

    This platform addresses both critical challenges by combining:
    1. **Machine Learning Metadata Classification:** Classifies encrypted network traffic flows into **Normal**, **Suspicious**, or **Malicious** strictly using session metadata metrics (packet lengths, inter-arrival times, burst rates, directional ratios) **without decrypting TLS payloads or intercepting private communication contents**.
    2. **Cryptographic Blockchain-Audited Ledger:** Binds every detection decision and its metadata into an immutable, tamper-evident local **SHA-256 hash-chain**. Any attempt by an adversary or rogue administrator to alter an audit record immediately invalidates subsequent cryptographic block digests, instantly triggering SOC tampering alerts.
    """)

    # 2. System Architecture Flow
    st.subheader("2. System Architecture & Pipeline")
    st.markdown("""
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
    │  • Probabilistic Threat Label (Normal / Suspicious / Malicious)        │
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
    """)

    # 3. Technology Stack Table
    st.subheader("3. Technology Stack")
    st.markdown("""
    | Component | Technology | Rationale & Implementation |
    | :--- | :--- | :--- |
    | **Language** | Python 3.12 | Core backend, cryptographic routines, and data processing. |
    | **Machine Learning** | Scikit-learn, NumPy | Random Forest Classifier with stratified cross-validation and feature importance analysis. |
    | **Network Analysis** | Zeek & Scapy | Bidirectional flow reconstruction from PCAP captures and `conn.log` parsing without payload decryption. |
    | **Blockchain Ledger** | Python hashlib (SHA-256) | Tamper-evident sequential hash-chain with deterministic JSON payload serialization. |
    | **Database** | SQLite 3 | Embedded ACID-compliant persistent storage for sessions and audit blocks. |
    | **Dashboard UI** | Streamlit | Responsive dark SOC cybersecurity user interface with live telemetry and controls. |
    | **Visualizations** | Plotly Express & Graph Objects | Dynamic confusion matrix heatmaps, donut distributions, and feature importance charts. |
    | **Automated Testing** | Pytest | Comprehensive test suite verifying ML, cryptographic hashing, and SQLite persistence. |
    """)

    # 4. Ethical AI, Privacy & Limitations
    st.subheader("4. Ethical Considerations, Privacy & Technical Limitations")
    st.markdown("""
    > [!IMPORTANT]
    > **Zero-Payload Decryption Policy:** This system operates strictly on transport and network layer metadata (timing, packet sizes, directionality). It does **not** install TLS interception certificates, perform man-in-the-middle (MITM) decryption, or capture passwords, private messages, or payload contents. All IP addresses are salted and hashed with SHA-256 prior to persistent storage.

    > [!NOTE]
    > **Probabilistic Nature of Machine Learning:** Metadata classification is probabilistic. While the model achieves high accuracy on benchmark encrypted distributions, it does not guarantee detection of every novel or adversarial threat. It is designed as an advanced anomaly detection tool to empower SOC analysts, not as a replacement for defense-in-depth security.

    > [!NOTE]
    > **Local Hash-Chain vs Public Blockchain:** This implementation uses a local, high-throughput cryptographic hash-chain ledger tailored for audit compliance and SIEM integrity. It does not incur the monetary gas fees, energy waste, or public ledger disclosure associated with decentralized public cryptocurrencies.
    """)
