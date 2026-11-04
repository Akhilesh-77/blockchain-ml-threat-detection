"""
Traffic Analysis Dashboard View.
Handles CSV upload, Zeek conn.log parsing, Scapy PCAP parsing, demonstration benchmark ingestion,
real-time batch ML inference, and automated Blockchain Ledger auditing.
"""

from datetime import datetime, timezone
from pathlib import Path
import uuid
import pandas as pd
import streamlit as st
from blockchain.ledger import get_ledger
from config import SAMPLE_DATA_DIR
from database.db import get_db
from ml.predict import get_predictor
from network.feature_extraction import anonymize_ip
from network.traffic_capture import parse_pcap_file
from network.zeek_parser import parse_zeek_conn_log


def render_traffic_analysis_view() -> None:
    """Render the Traffic Analysis and Classification page."""
    st.markdown("""
        <div class="soc-header">
            <h1>📡 Encrypted Network Traffic Analysis</h1>
            <p>Ingest network session metadata, classify threats without TLS decryption, and audit findings into the cryptographic ledger.</p>
        </div>
    """, unsafe_allow_html=True)

    db = get_db()
    ledger = get_ledger()
    predictor = get_predictor()

    if not predictor.is_ready():
        st.error("ML Model is not loaded. Please train or load a model from the Machine Learning tab.")
        return

    # Ingestion Source Selector
    st.subheader("1. Select Ingestion Source")
    input_source = st.radio(
        "Ingestion Method:",
        [
            "⚡ Demonstration Benchmark (Pre-packaged CIC-IDS2017 Encrypted Metadata)",
            "📁 Upload CSV Dataset (Flow Metadata)",
            "📋 Upload Zeek conn.log (Bro / Zeek NSM Log)",
            "📦 Upload PCAP Capture (Scapy Flow Reconstruction)"
        ],
        index=0
    )

    df_to_analyze = None

    # Option A: Demo Benchmark
    if "Demonstration Benchmark" in input_source:
        st.markdown("""
            > [!NOTE]
            > **Demonstration Benchmark Mode:** Analyzes a realistic sample of encrypted flows covering standard HTTPS, DoH/Tor tunneling, and TLS C2 beaconing.
        """)
        csv_path = SAMPLE_DATA_DIR / "encrypted_traffic_sample.csv"
        if csv_path.exists():
            sample_count = st.slider("Number of sample sessions to analyze:", min_value=5, max_value=100, value=20, step=5)
            full_sample_df = pd.read_csv(csv_path)
            # Pick a diverse sample across classes
            df_to_analyze = full_sample_df.sample(n=sample_count, random_state=42).reset_index(drop=True)
        else:
            st.warning("Sample dataset not found. Generating fresh benchmark...")
            from ml.train import train_model
            train_model()
            full_sample_df = pd.read_csv(csv_path)
            df_to_analyze = full_sample_df.head(20)

    # Option B: CSV Upload
    elif "Upload CSV" in input_source:
        uploaded_file = st.file_uploader("Upload Network Flow Metadata CSV", type=["csv"])
        if uploaded_file is not None:
            try:
                df_to_analyze = pd.read_csv(uploaded_file)
                st.success(f"Successfully loaded CSV with {len(df_to_analyze):,} rows and {len(df_to_analyze.columns)} columns.")
            except Exception as e:
                st.error(f"Error parsing CSV file: {e}")

    # Option C: Zeek conn.log
    elif "Upload Zeek" in input_source:
        st.markdown("Upload standard Zeek/Bro `conn.log` (tab-delimited `#fields` format or JSON lines).")
        uploaded_zeek = st.file_uploader("Upload conn.log", type=["log", "txt", "json", "tsv"])
        if uploaded_zeek is not None:
            try:
                content = uploaded_zeek.read()
                df_to_analyze = parse_zeek_conn_log(content)
                if not df_to_analyze.empty:
                    st.success(f"Parsed {len(df_to_analyze):,} Zeek connection flows!")
                else:
                    st.error("No valid connection records parsed from uploaded file.")
            except Exception as e:
                st.error(f"Error parsing Zeek log: {e}")

    # Option D: PCAP capture
    elif "Upload PCAP" in input_source:
        st.markdown("Upload raw `.pcap` capture file. Flows will be reconstructed and metadata extracted via Scapy without payload inspection.")
        uploaded_pcap = st.file_uploader("Upload PCAP capture", type=["pcap", "pcapng", "cap"])
        if uploaded_pcap is not None:
            try:
                with st.spinner("Reconstructing bidirectional flows with Scapy..."):
                    df_to_analyze = parse_pcap_file(uploaded_pcap.read())
                if not df_to_analyze.empty:
                    st.success(f"Reconstructed {len(df_to_analyze):,} network session flows!")
                else:
                    st.warning("No IP/TCP/UDP flows found in packet capture.")
            except Exception as e:
                st.error(f"Error parsing PCAP file: {e}")

    # Processing and Classification Phase
    if df_to_analyze is not None and not df_to_analyze.empty:
        st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
        st.subheader("2. Run Machine Learning Inference")

        # Classify with predictor
        with st.spinner("Classifying metadata with Random Forest Classifier..."):
            classified_df = predictor.predict_batch(df_to_analyze)

        # Compute summary metrics for this batch
        batch_total = len(classified_df)
        b_normal = int((classified_df["prediction"] == "Normal").sum())
        b_suspicious = int((classified_df["prediction"] == "Suspicious").sum())
        b_malicious = int((classified_df["prediction"] == "Malicious").sum())
        b_threats = b_suspicious + b_malicious

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Batch Ingested", f"{batch_total:,} flows")
        col2.metric("Normal", f"{b_normal:,}", delta=f"{b_normal/batch_total*100:.0f}%")
        col3.metric("Suspicious", f"{b_suspicious:,}", delta=f"{b_suspicious/batch_total*100:.0f}%", delta_color="off")
        col4.metric("Malicious", f"{b_malicious:,}", delta=f"{b_malicious/batch_total*100:.0f}%", delta_color="inverse")

        # Action: Commit to SQLite & Blockchain Ledger
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        audit_col1, audit_col2 = st.columns([2, 1])

        with audit_col1:
            st.markdown("""
                > [!IMPORTANT]
                > **Tamper-Evident Ledger Commitment:** Committing will record these classified sessions into SQLite and mine individual cryptographic SHA-256 blocks linking to the immutable audit ledger.
            """)

        with audit_col2:
            commit_button = st.button("🔒 Commit & Mine Audit Blocks", type="primary", use_container_width=True)

        if commit_button:
            with st.spinner(f"Mining {batch_total} cryptographic audit blocks into ledger..."):
                mined_count = 0
                for _, row in classified_df.iterrows():
                    session_id = row.get("session_id", f"SES-{uuid.uuid4().hex[:8].upper()}")
                    ts = row.get("timestamp", datetime.now(timezone.utc).isoformat())
                    src_ip = row.get("src_ip", "192.168.1.100")
                    dst_ip = row.get("dst_ip", "10.0.0.1")
                    dst_port = int(row.get("dst_port", 443))
                    proto = str(row.get("protocol", "TCP/TLS 1.3"))

                    features = {col: float(row[col]) for col in df_to_analyze.columns if col in predictor.get_metadata().get("features", [])}

                    # Store session record
                    db.insert_session({
                        "session_id": session_id,
                        "timestamp": ts,
                        "src_ip_hash": anonymize_ip(str(src_ip)),
                        "dst_ip_hash": anonymize_ip(str(dst_ip)),
                        "dst_port": dst_port,
                        "protocol": proto,
                        "features": features,
                        "prediction": row["prediction"],
                        "confidence": float(row["confidence"]),
                        "audited": 1,
                        "block_index": None
                    })

                    # Mine audit block
                    block = ledger.create_detection_record(
                        prediction=row["prediction"],
                        confidence=float(row["confidence"]),
                        metadata_summary={
                            "flow_duration": features.get("flow_duration", 0),
                            "total_fwd_packets": features.get("total_fwd_packets", 0),
                            "total_bwd_packets": features.get("total_bwd_packets", 0),
                            "total_fwd_bytes": features.get("total_fwd_bytes", 0),
                            "total_bwd_bytes": features.get("total_bwd_bytes", 0),
                            "dst_port": dst_port,
                            "protocol": proto,
                            "flow_bytes_per_sec": features.get("flow_bytes_per_sec", 0),
                            "flow_packets_per_sec": features.get("flow_packets_per_sec", 0),
                        },
                        event_id=f"EVT-{session_id}"
                    )

                    db.mark_session_audited(session_id, block.index_num)
                    mined_count += 1

                st.success(f"Successfully mined and cryptographically audited {mined_count} sessions into the Blockchain ledger!")
                st.rerun()

        # Display Classification Table
        st.subheader("3. Classified Session Telemetry")
        display_data = []
        for i, row in classified_df.iterrows():
            badge_class = f"badge-{row['prediction'].lower()}"
            conf_val = float(row["confidence"]) * 100
            display_data.append({
                "Index": i + 1,
                "Prediction": f"<span class='{badge_class}'>{row['prediction']}</span>",
                "Confidence": f"{conf_val:.1f}%",
                "Prob (Normal)": f"{float(row.get('prob_normal', 0))*100:.1f}%",
                "Prob (Suspicious)": f"{float(row.get('prob_suspicious', 0))*100:.1f}%",
                "Prob (Malicious)": f"{float(row.get('prob_malicious', 0))*100:.1f}%",
                "Duration (s)": f"{float(row.get('flow_duration', 0)):.3f}",
                "Fwd Pkts": int(row.get("total_fwd_packets", 0)),
                "Bwd Pkts": int(row.get("total_bwd_packets", 0)),
                "Fwd Mean Len": f"{float(row.get('fwd_packet_length_mean', 0)):.1f}",
                "Bwd Mean Len": f"{float(row.get('bwd_packet_length_mean', 0)):.1f}",
                "Down/Up Ratio": f"{float(row.get('down_up_ratio', 0)):.2f}"
            })

        st.write(pd.DataFrame(display_data).to_html(escape=False, index=False), unsafe_allow_html=True)

