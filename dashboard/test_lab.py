"""
Real-World Test Lab Dashboard View.
Provides:
1. Live Network Traffic Collection (Scapy interface sniffer & unprivileged live HTTPS activity collector).
2. Public Dataset Testing (CIC-IDS2017 feature mapping & ground truth comparison).
3. Controlled Security Laboratory (isolated localhost 127.0.0.1 tests).
4. Experiment History & Ground-Truth Validation (Confusion Matrix, Precision, Recall, F1).
5. Blockchain Audit Verification (genuine record counts, chain integrity & tamper verification).
"""

from datetime import datetime, timezone
from pathlib import Path
import uuid
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from blockchain.ledger import get_ledger
from blockchain.verification import verify_chain_integrity
from config import CLASS_NAMES, FEATURE_COLUMNS, PALETTE, SAMPLE_DATA_DIR
from database.db import get_db
from ml.evaluation import evaluate_model
from ml.predict import get_predictor
from ml.validation import get_model_validation_status
from network.cic_ids_loader import CICDatasetValidator
from network.feature_extraction import anonymize_ip
from network.live_collector import (
    LiveTrafficCollector,
    capture_live_http_session,
    get_live_collector,
    run_controlled_loopback_test,
    run_normal_browsing_simulation,
)


def render_test_lab_view() -> None:
    """Render the executive Real-World Test Lab."""
    st.markdown("""
        <div class="soc-header">
            <h1>🧪 SOC Sentinel — Real-World Test Lab</h1>
            <p>Empirical cybersecurity laboratory: capture live network traffic, validate against public CIC-IDS2017 benchmarks, execute controlled isolated tests, and audit results in the Blockchain ledger.</p>
        </div>
    """, unsafe_allow_html=True)

    db = get_db()
    ledger = get_ledger()
    predictor = get_predictor()
    collector = get_live_collector()
    model_status = get_model_validation_status()

    # 1. Model Validation Status Bar
    if not model_status["is_trained"]:
        st.error("⚠️ MODEL NOT TRAINED — No valid machine learning model found on disk. Please train a model in the Machine Learning tab.")
        return

    # Tabs for the 5 Sub-Sections
    tab_live, tab_dataset, tab_lab, tab_history, tab_blockchain = st.tabs([
        "📡 A. Live Traffic Capture",
        "📊 B. Public Dataset Testing (CIC-IDS2017)",
        "🔬 C. Controlled Security Lab",
        "📈 D. Experiment History & Validation",
        "⛓️ E. Blockchain Verification"
    ])

    # =========================================================================
    # TAB A: LIVE TRAFFIC CAPTURE
    # =========================================================================
    with tab_live:
        st.subheader("Live Network Traffic Collection")
        st.markdown("""
            Capture authorized network traffic from your local machine. Two collection engines are supported:
            1. **Real-World Live Web Session Generator (No Admin / No Npcap Required):** Connects to real public websites (Google, YouTube, Cloudflare, Wikipedia) and measures genuine socket metadata.
            2. **Scapy Promiscuous Sniffer:** Captures raw network interface frames (requires Npcap driver on Windows).
        """)

        col_left, col_right = st.columns([1, 1])

        with col_left:
            st.markdown("### Method 1: Everyday Real-World Traffic Generator")
            st.markdown("Generates real live encrypted HTTPS sessions by performing common everyday internet activities.")

            target_options = [
                "www.google.com (Search / HTTPS Web)",
                "www.youtube.com (Streaming / Video CDN)",
                "www.wikipedia.org (Knowledge Base / REST API)",
                "www.cloudflare.com (Cloud CDN / Proxy)",
                "www.github.com (Developer Platform / Git HTTPS)"
            ]
            selected_site = st.selectbox("Select Target Live Destination:", target_options, index=0)
            host_clean = selected_site.split(" ")[0].strip()

            c1, c2 = st.columns(2)
            with c1:
                run_single = st.button("🌐 Connect & Measure Live Session", type="primary", use_container_width=True)
            with c2:
                run_multi = st.button("🚀 Run Multi-Site Browsing Mix (5 Sites)", use_container_width=True)

            if run_single:
                with st.spinner(f"Opening live TLS connection to {host_clean}..."):
                    live_res = capture_live_http_session(target_host=host_clean, port=443, use_tls=True)
                    st.session_state["last_live_session"] = live_res

                    # Run ML classification immediately
                    feat_df = pd.DataFrame([live_res])
                    pred_res = predictor.predict_batch(feat_df)
                    st.session_state["last_live_pred"] = pred_res.iloc[0].to_dict()

            if run_multi:
                with st.spinner("Executing live browsing across 5 legitimate websites..."):
                    multi_df = run_normal_browsing_simulation()
                    pred_multi = predictor.predict_batch(multi_df)
                    st.session_state["multi_live_preds"] = pred_multi
                    st.success(f"Successfully captured {len(pred_multi)} real-world web sessions!")

        with col_right:
            st.markdown("### Method 2: Scapy Interface Sniffer (Promiscuous)")
            npcap_installed = collector.is_npcap_installed()

            if npcap_installed:
                st.markdown("<span class='badge-normal'>● NPCAP DRIVER ACTIVE</span>", unsafe_allow_html=True)
                ifaces = collector.get_available_interfaces()
                selected_iface = st.selectbox("Network Interface:", ifaces if ifaces else ["Default"])

                sc1, sc2 = st.columns(2)
                with sc1:
                    if not collector.is_capturing:
                        if st.button("▶️ Start Live Sniffing", type="primary", use_container_width=True):
                            collector.start_capture(interface=selected_iface, bpf_filter="tcp port 443 or port 80")
                            st.rerun()
                    else:
                        st.info("Sniffing in progress...")
                with sc2:
                    if collector.is_capturing:
                        if st.button("⏹️ Stop Capture", type="secondary", use_container_width=True):
                            captured = collector.stop_capture()
                            st.success(f"Captured {len(captured)} network flows!")
                            st.rerun()
            else:
                st.markdown("<span class='badge-suspicious'>● NPCAP NOT INSTALLED</span>", unsafe_allow_html=True)
                st.info("""
                    **Windows Notice:** Promiscuous packet sniffing on Windows requires **Npcap** (WinPcap successor).
                    * You can download Npcap from: [npcap.com](https://npcap.com/#download) (Select "Install Npcap in WinPcap API-compatible Mode").
                    * In the meantime, **Method 1 (Everyday Live Web Generator)** above connects to real networks and extracts genuine flow metadata without needing Npcap or Administrator privileges!
                """)

        # Display Live Captured Results
        st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
        if "last_live_pred" in st.session_state:
            p = st.session_state["last_live_pred"]
            badge_class = f"badge-{p['prediction'].lower()}"

            st.markdown(f"""
                <div style="background: #111827; border: 1px solid #1F2937; border-left: 4px solid #06B6D4; border-radius: 8px; padding: 18px; margin-bottom: 15px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span class="badge-cyan">DATA SOURCE: LIVE NETWORK DATA</span>
                            <h3 style="margin: 8px 0 4px 0; color: #F9FAFB;">Live Session: {p.get('dst_ip', 'Unknown')}</h3>
                            <div style="color: #9CA3AF; font-size: 0.85rem;">
                                Duration: <strong>{p.get('flow_duration', 0):.3f}s</strong> |
                                Inbound Bytes: <strong>{p.get('total_bwd_bytes', 0):,}</strong> |
                                Outbound Bytes: <strong>{p.get('total_fwd_bytes', 0):,}</strong> |
                                Down/Up Ratio: <strong>{p.get('down_up_ratio', 0):.2f}</strong>
                            </div>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 0.8rem; color: #9CA3AF; text-transform: uppercase;">Model Classification</div>
                            <span class="{badge_class}" style="font-size: 1.15rem; padding: 6px 14px;">{p['prediction']}</span>
                            <div style="font-size: 0.9rem; color: #F9FAFB; margin-top: 4px;">Confidence: <strong>{p['confidence']*100:.1f}%</strong></div>
                        </div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            if st.button("🔒 Commit Live Session to Blockchain Ledger & SQLite", type="primary"):
                # Insert session
                db.insert_session({
                    "session_id": p["session_id"],
                    "timestamp": p["timestamp"],
                    "src_ip_hash": anonymize_ip(p["src_ip"]),
                    "dst_ip_hash": anonymize_ip(p["dst_ip"]),
                    "dst_port": int(p.get("dst_port", 443)),
                    "protocol": p.get("protocol", "TCP/TLS 1.3"),
                    "features": {col: float(p[col]) for col in FEATURE_COLUMNS if col in p},
                    "prediction": p["prediction"],
                    "confidence": float(p["confidence"]),
                    "audited": 1,
                    "block_index": None,
                    "data_source": "LIVE_NETWORK"
                })

                # Mine blockchain block
                block = ledger.create_detection_record(
                    prediction=p["prediction"],
                    confidence=float(p["confidence"]),
                    metadata_summary=p,
                    event_id=f"EVT-{p['session_id']}",
                    data_source="LIVE_NETWORK"
                )
                db.mark_session_audited(p["session_id"], block.index_num)
                st.success(f"Committed live session to Blockchain Ledger at Block #{block.index_num}!")
                st.rerun()

        if "multi_live_preds" in st.session_state:
            multi_p = st.session_state["multi_live_preds"]
            st.markdown("#### Multi-Site Live Captured Telemetry")
            st.dataframe(multi_p[["session_id", "dst_ip", "flow_duration", "total_fwd_bytes", "total_bwd_bytes", "prediction", "confidence"]], use_container_width=True)

            if st.button("🔒 Commit All Live Sessions to Blockchain Ledger"):
                for _, r in multi_p.iterrows():
                    db.insert_session({
                        "session_id": r["session_id"],
                        "timestamp": r["timestamp"],
                        "src_ip_hash": anonymize_ip(r["src_ip"]),
                        "dst_ip_hash": anonymize_ip(r["dst_ip"]),
                        "dst_port": int(r.get("dst_port", 443)),
                        "protocol": r.get("protocol", "TCP/TLS 1.3"),
                        "features": {col: float(r[col]) for col in FEATURE_COLUMNS if col in r},
                        "prediction": r["prediction"],
                        "confidence": float(r["confidence"]),
                        "audited": 1,
                        "block_index": None,
                        "data_source": "LIVE_NETWORK"
                    })
                    blk = ledger.create_detection_record(
                        prediction=r["prediction"],
                        confidence=float(r["confidence"]),
                        metadata_summary=r.to_dict(),
                        event_id=f"EVT-{r['session_id']}",
                        data_source="LIVE_NETWORK"
                    )
                    db.mark_session_audited(r["session_id"], blk.index_num)
                st.success(f"Mined {len(multi_p)} live blocks into the Blockchain ledger!")
                st.rerun()

    # =========================================================================
    # TAB B: PUBLIC DATASET TESTING (CIC-IDS2017)
    # =========================================================================
    with tab_dataset:
        st.subheader("Public Cybersecurity Dataset Testing (CIC-IDS2017)")
        st.markdown("""
            Test the model against authentic public datasets from the **Canadian Institute for Cybersecurity (UNB CIC-IDS2017)**.
            The pipeline automatically parses UNB headers, extracts the 21 canonical flow metrics, preserves original attack labels, and evaluates genuine accuracy.
        """)

        dataset_mode = st.radio(
            "Select CIC-IDS2017 Input Mode:",
            [
                "📁 Use Pre-Packaged CIC-IDS2017 Verified Subset (Sample Benchmark)",
                "📤 Upload Custom Official CIC-IDS2017 CSV File"
            ],
            index=0
        )

        cic_df = None
        if "Pre-Packaged" in dataset_mode:
            sample_cic_path = SAMPLE_DATA_DIR / "cic_ids2017_sample.csv"
            if sample_cic_path.exists():
                cic_df = pd.read_csv(sample_cic_path)
                st.info(f"Loaded verified CIC-IDS2017 sample subset containing **{len(cic_df)}** flows with labelled attacks.")
            else:
                st.warning("Sample file not found.")
        else:
            up_cic = st.file_uploader("Upload CIC-IDS2017 CSV file", type=["csv"])
            if up_cic is not None:
                cic_df = pd.read_csv(up_cic)

        if cic_df is not None and not cic_df.empty:
            validator = CICDatasetValidator(cic_df)
            summary = validator.get_summary()

            # Diagnostic Cards
            dcol1, dcol2, dcol3, dcol4 = st.columns(4)
            dcol1.metric("Total Records", f"{summary['total_rows']:,}")
            dcol2.metric("Matched Features", f"{summary['matched_features_count']}/{summary['total_expected_features']}")
            dcol3.metric("Feature Coverage", f"{summary['feature_coverage_pct']}%")
            dcol4.metric("Ground Truth Labels", "Detected" if summary["has_ground_truth"] else "Not Found")

            if summary["missing_features"]:
                st.warning(f"Missing features (defaulted to 0.0): {', '.join(summary['missing_features'])}")

            st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
            if st.button("🚀 Run ML Model Evaluation on Public Dataset", type="primary"):
                with st.spinner("Running inference and comparing against ground truth labels..."):
                    eval_results = validator.evaluate_against_ground_truth(predictor=predictor)
                    st.session_state["cic_eval_results"] = eval_results

            if "cic_eval_results" in st.session_state:
                res = st.session_state["cic_eval_results"]
                m = res["metrics"]
                rdf = res["results_dataframe"]

                st.markdown("### Ground Truth Evaluation Results")
                rcol1, rcol2, rcol3, rcol4, rcol5 = st.columns(5)
                rcol1.metric("Validation Accuracy", f"{m['accuracy']*100:.2f}%")
                rcol2.metric("Macro Precision", f"{m['precision_macro']*100:.2f}%")
                rcol3.metric("Macro Recall", f"{m['recall_macro']*100:.2f}%")
                rcol4.metric("Macro F1-Score", f"{m['f1_macro']:.4f}")
                rcol5.metric("Correct Classifications", f"{res['matches']}/{res['total_evaluated']}")

                # Confusion Matrix Heatmap
                cm_df = pd.DataFrame(m["confusion_matrix"], index=CLASS_NAMES, columns=CLASS_NAMES)
                fig_cm = px.imshow(
                    cm_df,
                    text_auto=True,
                    color_continuous_scale="Purples",
                    labels=dict(x="Model Prediction", y="Known Ground Truth", color="Count"),
                    title="Confusion Matrix: Ground Truth vs Model Prediction"
                )
                fig_cm.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#9CA3AF"), height=300)
                st.plotly_chart(fig_cm, use_container_width=True)

                st.markdown("### Classified Session Comparison Table")
                display_cols = ["ground_truth_label", "normalized_ground_truth", "prediction", "confidence", "match", "flow_duration", "total_fwd_packets", "total_bwd_packets"]
                st.dataframe(rdf[display_cols], use_container_width=True)

                ecol1, ecol2 = st.columns(2)
                with ecol1:
                    if st.button("💾 Save as Validated Experiment in Database"):
                        exp_id = f"EXP-{uuid.uuid4().hex[:8].upper()}"
                        db.insert_experiment({
                            "experiment_id": exp_id,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "experiment_name": "CIC-IDS2017 Dataset Benchmark",
                            "data_source": "PUBLIC_DATASET",
                            "total_sessions": len(rdf),
                            "normal_count": int((rdf["prediction"] == "Normal").sum()),
                            "suspicious_count": int((rdf["prediction"] == "Suspicious").sum()),
                            "malicious_count": int((rdf["prediction"] == "Malicious").sum()),
                            "ground_truth_available": 1,
                            "metrics": m,
                            "notes": f"Validation run against {summary['total_rows']} CIC-IDS2017 flows. Accuracy: {m['accuracy']*100:.2f}%"
                        })
                        st.success(f"Experiment {exp_id} saved successfully!")

                with ecol2:
                    if st.button("🔒 Commit Evaluated Sessions to Blockchain Ledger"):
                        mined = 0
                        for _, row in rdf.iterrows():
                            sess_id = f"CIC-{uuid.uuid4().hex[:8].upper()}"
                            db.insert_session({
                                "session_id": sess_id,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "src_ip_hash": "IP-CIC-SRC",
                                "dst_ip_hash": "IP-CIC-DST",
                                "dst_port": 443,
                                "protocol": "TCP/TLS",
                                "features": {col: float(row[col]) for col in FEATURE_COLUMNS if col in row},
                                "prediction": row["prediction"],
                                "confidence": float(row["confidence"]),
                                "audited": 1,
                                "block_index": None,
                                "data_source": "PUBLIC_DATASET"
                            })
                            blk = ledger.create_detection_record(
                                prediction=row["prediction"],
                                confidence=float(row["confidence"]),
                                metadata_summary=row.to_dict(),
                                event_id=f"EVT-{sess_id}",
                                data_source="PUBLIC_DATASET"
                            )
                            db.mark_session_audited(sess_id, blk.index_num)
                            mined += 1
                        st.success(f"Mined {mined} blocks with PUBLIC_DATASET tag into the Blockchain ledger!")
                        st.rerun()

    # =========================================================================
    # TAB C: CONTROLLED SECURITY LAB (ISOLATED 127.0.0.1)
    # =========================================================================
    with tab_lab:
        st.subheader("Controlled Security Testing Laboratory")
        st.markdown("""
            > [!IMPORTANT]
            > **Safety & Ethics Boundary:** All controlled pattern tests in this section operate **strictly on localhost loopback (`127.0.0.1`)** or simulated in-memory packet exchanges. They do not attack, scan, or probe third-party networks.
        """)

        st.markdown("### Select Laboratory Testing Scenario:")
        lab_scenario = st.selectbox(
            "Test Scenario:",
            [
                "1. Tor / DoH Uniform Cell Tunneling Pattern (Fixed 512B Chunks, Symmetric Ratios)",
                "2. Periodic C2 Beaconing Pattern (Rigid Heartbeat, Low Jitter)",
                "3. Rapid Volumetric Burst Connection (High SYN Rate, Brief Duration)",
                "4. Normal Local Web Service (Bursty Asymmetric HTTP)"
            ],
            index=0
        )

        pattern_key = "tor_cell_tunnel"
        if "Tor" in lab_scenario:
            pattern_key = "tor_cell_tunnel"
        elif "C2" in lab_scenario:
            pattern_key = "c2_beacon"
        elif "Volumetric" in lab_scenario:
            pattern_key = "rapid_burst"
        else:
            pattern_key = "normal_local"

        if st.button("🧪 Execute Controlled Laboratory Test", type="primary"):
            sim_result = run_controlled_loopback_test(pattern_key)
            sim_df = pd.DataFrame([sim_result])
            sim_pred = predictor.predict_batch(sim_df).iloc[0].to_dict()
            st.session_state["last_lab_pred"] = sim_pred

        if "last_lab_pred" in st.session_state:
            lp = st.session_state["last_lab_pred"]
            badge_class = f"badge-{lp['prediction'].lower()}"

            st.markdown(f"""
                <div style="background: #111827; border: 1px solid #1F2937; border-left: 4px solid #8B5CF6; border-radius: 8px; padding: 18px; margin: 15px 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span class="badge-purple">DATA SOURCE: CONTROLLED_LAB (127.0.0.1)</span>
                            <h3 style="margin: 8px 0 4px 0; color: #F9FAFB;">Scenario: {lp['session_id']}</h3>
                            <div style="color: #9CA3AF; font-size: 0.85rem;">
                                Duration: <strong>{lp.get('flow_duration', 0):.3f}s</strong> |
                                Forward Pkts: <strong>{lp.get('total_fwd_packets', 0)}</strong> |
                                Backward Pkts: <strong>{lp.get('total_bwd_packets', 0)}</strong> |
                                IAT Jitter: <strong>{lp.get('flow_iat_std', 0):.4f}</strong>
                            </div>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 0.8rem; color: #9CA3AF; text-transform: uppercase;">Classifier Result</div>
                            <span class="{badge_class}" style="font-size: 1.15rem; padding: 6px 14px;">{lp['prediction']}</span>
                            <div style="font-size: 0.9rem; color: #F9FAFB; margin-top: 4px;">Confidence: <strong>{lp['confidence']*100:.1f}%</strong></div>
                        </div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            if st.button("🔒 Commit Lab Result to Blockchain Ledger"):
                db.insert_session({
                    "session_id": lp["session_id"],
                    "timestamp": lp["timestamp"],
                    "src_ip_hash": anonymize_ip(lp["src_ip"]),
                    "dst_ip_hash": anonymize_ip(lp["dst_ip"]),
                    "dst_port": int(lp.get("dst_port", 443)),
                    "protocol": lp.get("protocol", "TCP/TLS"),
                    "features": {col: float(lp[col]) for col in FEATURE_COLUMNS if col in lp},
                    "prediction": lp["prediction"],
                    "confidence": float(lp["confidence"]),
                    "audited": 1,
                    "block_index": None,
                    "data_source": "CONTROLLED_LAB"
                })
                blk = ledger.create_detection_record(
                    prediction=lp["prediction"],
                    confidence=float(lp["confidence"]),
                    metadata_summary=lp,
                    event_id=f"EVT-{lp['session_id']}",
                    data_source="CONTROLLED_LAB"
                )
                db.mark_session_audited(lp["session_id"], blk.index_num)
                st.success(f"Lab detection committed at Block #{blk.index_num}!")
                st.rerun()

    # =========================================================================
    # TAB D: EXPERIMENT HISTORY & VALIDATION
    # =========================================================================
    with tab_history:
        st.subheader("Experiment Registry & Validation Records")
        exps = db.get_all_experiments(limit=50)

        if exps:
            st.markdown(f"Registered **{len(exps)}** completed real-world experiment runs:")
            exp_display = []
            for e in exps:
                exp_display.append({
                    "Experiment ID": e["experiment_id"],
                    "Timestamp (UTC)": e["timestamp"][:19].replace("T", " "),
                    "Name": e["experiment_name"],
                    "Data Source": e["data_source"],
                    "Total Flows": e["total_sessions"],
                    "Normal": e["normal_count"],
                    "Suspicious": e["suspicious_count"],
                    "Malicious": e["malicious_count"],
                    "Ground Truth": "Yes" if e["ground_truth_available"] else "No",
                    "Notes": e["notes"]
                })
            st.dataframe(pd.DataFrame(exp_display), use_container_width=True)

            st.markdown("### Selected Experiment Metric Inspector")
            exp_ids = [e["experiment_id"] for e in exps]
            sel_exp_id = st.selectbox("Inspect Experiment:", exp_ids, index=0)
            sel_exp = next((e for e in exps if e["experiment_id"] == sel_exp_id), None)

            if sel_exp and sel_exp.get("metrics"):
                sm = sel_exp["metrics"]
                if "accuracy" in sm:
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Accuracy", f"{sm['accuracy']*100:.2f}%")
                    c2.metric("Precision", f"{sm['precision_macro']*100:.2f}%")
                    c3.metric("Recall", f"{sm['recall_macro']*100:.2f}%")
                    c4.metric("F1-Score", f"{sm['f1_macro']:.4f}")
        else:
            st.info("No experiment runs registered yet. Run an evaluation in the 'Public Dataset Testing' tab and save the experiment.")

    # =========================================================================
    # TAB E: BLOCKCHAIN VERIFICATION
    # =========================================================================
    with tab_blockchain:
        st.subheader("Cryptographic Blockchain Ledger Verification")
        chain = ledger.get_chain()
        ds_counts = db.get_data_source_counts()

        # Breakdown of genuine audit blocks by data source
        bcol1, bcol2, bcol3, bcol4 = st.columns(4)
        bcol1.metric("Total Ledger Blocks", f"{len(chain):,}")
        bcol2.metric("Live Network Sessions", f"{ds_counts.get('LIVE_NETWORK', 0):,}")
        bcol3.metric("Public Dataset Sessions", f"{ds_counts.get('PUBLIC_DATASET', 0):,}")
        bcol4.metric("Controlled Lab Sessions", f"{ds_counts.get('CONTROLLED_LAB', 0):,}")

        st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
        v_report = verify_chain_integrity(chain, difficulty=2)

        if v_report.is_valid:
            st.markdown(f"""
                <div class="valid-alert">
                    <h3 style="margin: 0 0 6px 0; color: #34D399;">🔒 ALL {len(chain)} BLOCKCHAIN RECORDS CRYPTOGRAPHICALLY VALID</h3>
                    <p style="margin: 0; color: #A7F3D0; font-size: 0.9rem;">
                        Every audit record's SHA-256 digest strictly matches its canonical payload and metadata hash.
                        Previous block links maintain unbroken continuity back to the Genesis block.
                    </p>
                </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
                <div class="tamper-alert">
                    <h3 style="margin: 0 0 6px 0; color: #F87171;">🚨 CRYPTOGRAPHIC INTEGRITY VIOLATION</h3>
                    <p style="margin: 0; color: #FECACA; font-size: 0.9rem;">
                        {v_report.error_message} (Tampered Block: #{v_report.tampered_block_index})
                    </p>
                </div>
            """, unsafe_allow_html=True)

        st.markdown("### Ledger Blocks by Source Tag")
        chain_display = []
        for b in reversed(chain[-15:]):
            chain_display.append({
                "Block #": b.index_num,
                "Event UUID": b.event_id,
                "Data Source": b.data_source,
                "Classification": b.prediction,
                "Confidence": f"{b.confidence*100:.1f}%",
                "Hash": b.current_hash[:16] + "...",
                "Prev Hash": b.prev_hash[:16] + "...",
                "Timestamp (UTC)": b.timestamp[:19].replace("T", " ")
            })
        st.dataframe(pd.DataFrame(chain_display), use_container_width=True)
