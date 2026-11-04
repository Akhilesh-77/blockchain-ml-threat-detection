"""
Machine Learning Pipeline Dashboard View.
Renders genuine evaluation metrics, confusion matrix heatmap, feature importances,
an interactive live metadata session simulator, and retraining capabilities.
"""

import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from config import CLASS_NAMES, FEATURE_COLUMNS, METADATA_PATH, PALETTE
from ml.predict import get_predictor
from ml.train import train_model


def render_ml_view() -> None:
    """Render Machine Learning pipeline evaluation and interactive simulator."""
    st.markdown("""
        <div class="soc-header">
            <h1>🧠 Machine Learning Classification Engine</h1>
            <p>Random Forest model trained on encrypted network session metadata distributions. Evaluates flow timing, volume, and flag metrics without TLS payload inspection.</p>
        </div>
    """, unsafe_allow_html=True)

    predictor = get_predictor()
    meta = predictor.get_metadata()

    if not meta or "metrics" not in meta:
        st.warning("No trained model metadata found. Initiating model training...")
        with st.spinner("Training Random Forest Classifier..."):
            meta = train_model()
            predictor.load_artifacts()
            st.rerun()

    metrics = meta["metrics"]

    # 1. Genuine Metric Cards
    mcol1, mcol2, mcol3, mcol4, mcol5 = st.columns(5)
    with mcol1:
        st.metric("Test Accuracy", f"{metrics['accuracy']*100:.2f}%", help="Calculated directly on 20% stratified test split")
    with mcol2:
        st.metric("Macro Precision", f"{metrics['precision_macro']*100:.2f}%", help="Unweighted average precision across all classes")
    with mcol3:
        st.metric("Macro Recall", f"{metrics['recall_macro']*100:.2f}%", help="Unweighted average recall across all classes")
    with mcol4:
        st.metric("Macro F1-Score", f"{metrics['f1_macro']:.4f}", help="Harmonic mean of precision and recall")
    with mcol5:
        st.metric("Test Samples", f"{metrics['total_test_samples']:,}", help="Number of evaluated held-out sessions")

    st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)

    # 2. Confusion Matrix & Feature Importances
    col_cm, col_fi = st.columns([1, 1])

    with col_cm:
        st.subheader("Confusion Matrix (Test Split)")
        cm = metrics["confusion_matrix"]
        cm_df = pd.DataFrame(cm, index=CLASS_NAMES, columns=CLASS_NAMES)

        fig_cm = px.imshow(
            cm_df,
            text_auto=True,
            color_continuous_scale="Viridis",
            labels=dict(x="Predicted Class", y="Actual Class", color="Count"),
            x=CLASS_NAMES,
            y=CLASS_NAMES
        )
        fig_cm.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#9CA3AF"),
            margin=dict(t=20, b=20, l=20, r=20),
            height=320
        )
        st.plotly_chart(fig_cm, use_container_width=True)

    with col_fi:
        st.subheader("Top Feature Importances (Gini Impurity)")
        fi_list = meta.get("feature_importances", [])
        if fi_list:
            fi_df = pd.DataFrame(fi_list[:10])
            fi_df = fi_df.sort_values(by="importance", ascending=True)

            fig_fi = px.bar(
                fi_df,
                x="importance",
                y="feature",
                orientation="h",
                color="importance",
                color_continuous_scale="Blues",
                labels={"importance": "Relative Importance", "feature": "Metadata Feature"}
            )
            fig_fi.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#9CA3AF"),
                margin=dict(t=20, b=20, l=20, r=20),
                height=320,
                coloraxis_showscale=False
            )
            st.plotly_chart(fig_fi, use_container_width=True)

    # 3. Interactive Live Feature Simulator
    st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
    st.subheader("🔬 Interactive Encrypted Session Simulator")
    st.markdown("Adjust encrypted session flow metadata parameters below to observe real-time model inference and confidence probabilities.")

    sim_col1, sim_col2, sim_col3 = st.columns(3)

    with sim_col1:
        sim_duration = st.slider("Flow Duration (seconds)", 0.01, 60.0, 3.5, step=0.1)
        sim_fwd_pkts = st.number_input("Total Forward Packets", 1, 500, 15)
        sim_bwd_pkts = st.number_input("Total Backward Packets", 1, 500, 25)
        sim_fwd_bytes = st.number_input("Total Forward Bytes", 50, 500000, 3200)

    with sim_col2:
        sim_bwd_bytes = st.number_input("Total Backward Bytes", 50, 1000000, 28000)
        sim_fwd_len_mean = st.slider("Fwd Packet Mean Length (bytes)", 40.0, 1500.0, 213.0, step=5.0)
        sim_bwd_len_mean = st.slider("Bwd Packet Mean Length (bytes)", 40.0, 1500.0, 1120.0, step=5.0)
        sim_iat_std = st.slider("Flow IAT Std Dev (Jitter)", 0.001, 2.0, 0.25, step=0.01)

    with sim_col3:
        sim_psh_flags = st.slider("PSH Flag Count", 0, 50, 4)
        sim_rst_flags = st.selectbox("RST Flag Count", [0, 1, 2], index=0)
        sim_syn_flags = st.selectbox("SYN Flag Count", [1, 2, 3], index=0)
        sim_ratio = sim_bwd_pkts / max(sim_fwd_pkts, 1)
        st.markdown(f"**Down/Up Ratio:** `{sim_ratio:.2f}`")

    # Run Simulation Inference
    sim_features = {
        "flow_duration": sim_duration,
        "total_fwd_packets": sim_fwd_pkts,
        "total_bwd_packets": sim_bwd_pkts,
        "total_fwd_bytes": sim_fwd_bytes,
        "total_bwd_bytes": sim_bwd_bytes,
        "fwd_packet_length_mean": sim_fwd_len_mean,
        "bwd_packet_length_mean": sim_bwd_len_mean,
        "flow_bytes_per_sec": (sim_fwd_bytes + sim_bwd_bytes) / max(sim_duration, 0.001),
        "flow_packets_per_sec": (sim_fwd_pkts + sim_bwd_pkts) / max(sim_duration, 0.001),
        "flow_iat_mean": sim_duration / max(sim_fwd_pkts + sim_bwd_pkts, 1),
        "flow_iat_std": sim_iat_std,
        "fwd_iat_mean": sim_duration / max(sim_fwd_pkts, 1),
        "bwd_iat_mean": sim_duration / max(sim_bwd_pkts, 1),
        "packet_length_mean": (sim_fwd_bytes + sim_bwd_bytes) / max(sim_fwd_pkts + sim_bwd_pkts, 1),
        "packet_length_std": abs(sim_bwd_len_mean - sim_fwd_len_mean) * 0.4,
        "syn_flag_count": sim_syn_flags,
        "rst_flag_count": sim_rst_flags,
        "psh_flag_count": sim_psh_flags,
        "ack_flag_count": sim_fwd_pkts + sim_bwd_pkts - 1,
        "fin_flag_count": 1,
        "down_up_ratio": sim_ratio
    }

    sim_res = predictor.predict_single(sim_features)
    pred_label = sim_res["prediction"]
    conf = sim_res["confidence"]
    probs = sim_res["probabilities"]

    badge_style = f"badge-{pred_label.lower()}"

    st.markdown(f"""
        <div style="background: #111827; border: 1px solid #1F2937; border-radius: 8px; padding: 20px; margin-top: 15px;">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <span style="color: #9CA3AF; font-size: 0.85rem; text-transform: uppercase; font-weight: 600;">Simulation Classification</span>
                    <div style="margin-top: 4px;">
                        <span class="{badge_style}" style="font-size: 1.1rem; padding: 6px 16px;">{pred_label.upper()}</span>
                    </div>
                </div>
                <div style="text-align: right;">
                    <span style="color: #9CA3AF; font-size: 0.85rem; text-transform: uppercase; font-weight: 600;">Model Confidence</span>
                    <div style="font-size: 1.8rem; font-weight: 700; color: #F9FAFB;">{conf*100:.1f}%</div>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Probability Distribution Bar
    prob_cols = st.columns(3)
    prob_cols[0].progress(probs.get("Normal", 0.0), text=f"Normal: {probs.get('Normal', 0.0)*100:.1f}%")
    prob_cols[1].progress(probs.get("Suspicious", 0.0), text=f"Suspicious: {probs.get('Suspicious', 0.0)*100:.1f}%")
    prob_cols[2].progress(probs.get("Malicious", 0.0), text=f"Malicious: {probs.get('Malicious', 0.0)*100:.1f}%")

    # 4. Model Training Control
    st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
    st.subheader("⚙️ Retrain Classifier")
    st.write("Retrain the Random Forest model on the benchmark dataset or an uploaded custom dataset.")

    if st.button("🔄 Retrain Model on CIC-IDS2017 Benchmark"):
        with st.spinner("Retraining Random Forest Classifier..."):
            new_meta = train_model(random_state=42)
            predictor.load_artifacts()
            st.success(f"Model successfully retrained! New Accuracy: {new_meta['metrics']['accuracy']*100:.2f}%")
            st.rerun()
