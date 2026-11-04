"""
SOC Overview Dashboard View.
Renders real-time telemetry, threat breakdown, blockchain ledger health, and detection velocity.
"""

from typing import Any, Dict, List
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from blockchain.ledger import get_ledger
from blockchain.verification import verify_chain_integrity
from config import PALETTE
from dashboard.styles import render_metric_card
from database.db import get_db


def render_overview_view() -> None:
    """Render the executive SOC Overview page with explicit data source classification."""
    db = get_db()
    ledger = get_ledger()

    st.markdown("""
        <div class="soc-header">
            <h1>🛡️ SOC Command Center & Telemetry</h1>
            <p>Live monitoring of encrypted network session metadata classified by Random Forest & audited via SHA-256 Hash-Chain.</p>
        </div>
    """, unsafe_allow_html=True)

    # 1. Data Source Scope Selector
    ds_counts = db.get_data_source_counts()
    scope_options = [
        f"🌐 All Data Sources (Total: {sum(ds_counts.values()):,})",
        f"📡 Live Network Data (Captured: {ds_counts.get('LIVE_NETWORK', 0):,})",
        f"📊 Public Dataset (CIC-IDS2017: {ds_counts.get('PUBLIC_DATASET', 0):,})",
        f"⚡ Synthetic Demonstration Benchmark ({ds_counts.get('SYNTHETIC_DEMO', 0):,})"
    ]

    selected_scope_str = st.radio(
        "Telemetry Data Source Scope:",
        scope_options,
        index=0,
        horizontal=True
    )

    data_source_filter = None
    badge_html = "<span class='badge-cyan'>DATA SOURCE: CONSOLIDATED SOC TELEMETRY</span>"

    if "Live Network Data" in selected_scope_str:
        data_source_filter = "LIVE_NETWORK"
        badge_html = "<span class='badge-source-live'>DATA SOURCE: LIVE NETWORK DATA</span>"
    elif "Public Dataset" in selected_scope_str:
        data_source_filter = "PUBLIC_DATASET"
        badge_html = "<span class='badge-source-public'>DATA SOURCE: PUBLIC DATASET (CIC-IDS2017)</span>"
    elif "Synthetic Demonstration" in selected_scope_str:
        data_source_filter = "SYNTHETIC_DEMO"
        badge_html = "<span class='badge-source-demo'>DATA SOURCE: SYNTHETIC DEMONSTRATION BENCHMARK</span>"

    st.markdown(f"<div style='margin-bottom: 12px;'>{badge_html}</div>", unsafe_allow_html=True)

    # 2. Fetch real-time statistics filtered by data source
    stats = db.get_session_stats(data_source=data_source_filter)
    chain = ledger.get_chain(data_source=data_source_filter)
    verification = verify_chain_integrity(ledger.get_chain(), difficulty=2)

    total_sessions = stats["total_sessions"]
    normal_count = stats["normal_sessions"]
    suspicious_count = stats["suspicious_sessions"]
    malicious_count = stats["malicious_sessions"]
    threat_pct = stats["threat_pct"]
    total_blocks = len(chain)

    # Empty State Alert for Live Network
    if data_source_filter == "LIVE_NETWORK" and total_sessions == 0:
        st.markdown("""
            <div class="tamper-alert" style="background: rgba(6, 182, 212, 0.1); border-color: #0284c7; color: #bae6fd;">
                <h3 style="margin: 0 0 6px 0; color: #38bdf8;">⚠️ NO LIVE NETWORK DATA AVAILABLE</h3>
                <p style="margin: 0; font-size: 0.92rem;">
                    No live network traffic has been captured from this device yet.
                    To capture real HTTPS flows or start interface sniffing, navigate to the <strong>🧪 Real-World Test Lab</strong> in the sidebar.
                </p>
            </div>
        """, unsafe_allow_html=True)

    # 3. Key Telemetry Metric Cards
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(
            render_metric_card(
                "Total Sessions",
                f"{total_sessions:,}",
                "Network flows ingested",
                border_color=PALETTE["cyan"]
            ),
            unsafe_allow_html=True
        )

    with col2:
        st.markdown(
            render_metric_card(
                "Normal Traffic",
                f"{normal_count:,}",
                "Legitimate TLS sessions",
                border_color=PALETTE["normal"]
            ),
            unsafe_allow_html=True
        )

    with col3:
        st.markdown(
            render_metric_card(
                "Suspicious Flows",
                f"{suspicious_count:,}",
                "Tunneling / Anomaly",
                border_color=PALETTE["suspicious"]
            ),
            unsafe_allow_html=True
        )

    with col4:
        st.markdown(
            render_metric_card(
                "Malicious Threats",
                f"{malicious_count:,}",
                "C2 Beacon / Exfiltration",
                border_color=PALETTE["malicious"]
            ),
            unsafe_allow_html=True
        )

    with col5:
        st.markdown(
            render_metric_card(
                "Threat Ratio",
                f"{threat_pct:.1f}%",
                f"{stats['threat_sessions']} threat events",
                border_color=PALETTE["purple"]
            ),
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # 3. Blockchain Ledger Status Banner
    if verification.is_valid:
        st.markdown(f"""
            <div class="valid-alert" style="display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <strong>🔒 BLOCKCHAIN AUDIT LEDGER INTACT</strong> — All <strong>{total_blocks}</strong> cryptographic blocks verified with SHA-256 hash-chaining. Zero tampering detected.
                </div>
                <span class="badge-normal">STATUS: HEALTHY</span>
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
            <div class="tamper-alert" style="display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <strong>⚠️ TAMPER ALERT IN BLOCKCHAIN LEDGER</strong> — Integrity violation flagged at <strong>Block #{verification.tampered_block_index}</strong>: {verification.error_message}
                </div>
                <span class="badge-malicious">INTEGRITY COMPROMISED</span>
            </div>
        """, unsafe_allow_html=True)

    # 4. Interactive Visualizations
    chart_col1, chart_col2 = st.columns([1, 2])

    with chart_col1:
        st.subheader("Threat Classification Distribution")
        if total_sessions > 0:
            labels = ["Normal", "Suspicious", "Malicious"]
            values = [normal_count, suspicious_count, malicious_count]
            colors = [PALETTE["normal"], PALETTE["suspicious"], PALETTE["malicious"]]

            fig_donut = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                hole=0.6,
                marker=dict(colors=colors, line=dict(color="#0B0F19", width=2)),
                textinfo="percent+label",
                hoverinfo="label+value+percent",
                showlegend=False
            )])
            fig_donut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=10, b=10, l=10, r=10),
                height=280,
                font=dict(color="#9CA3AF")
            )
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("No session data available yet. Ingest network traffic to populate charts.")

    with chart_col2:
        st.subheader("Session Threat Velocity Timeline")
        sessions = db.get_all_sessions(limit=50, data_source=data_source_filter)
        if sessions:
            df_sess = pd.DataFrame(sessions)
            df_sess["timestamp"] = pd.to_datetime(df_sess["timestamp"])
            df_sess = df_sess.sort_values(by="timestamp")

            color_map = {
                "Normal": PALETTE["normal"],
                "Suspicious": PALETTE["suspicious"],
                "Malicious": PALETTE["malicious"]
            }

            fig_timeline = px.scatter(
                df_sess,
                x="timestamp",
                y="confidence",
                color="prediction",
                color_discrete_map=color_map,
                size=[12] * len(df_sess),
                hover_data=["session_id", "protocol", "dst_port", "src_ip_hash", "dst_ip_hash"],
                labels={"timestamp": "Time (UTC)", "confidence": "ML Model Confidence"}
            )
            fig_timeline.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="#111827",
                font=dict(color="#9CA3AF"),
                margin=dict(t=20, b=20, l=20, r=20),
                height=280,
                xaxis=dict(showgrid=True, gridcolor="#1F2937"),
                yaxis=dict(showgrid=True, gridcolor="#1F2937", range=[0.4, 1.05]),
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1,
                    bgcolor="rgba(0,0,0,0)"
                )
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("No session activity recorded for the selected data source.")

    # 5. Recent Activity Table
    st.subheader("Recent Network Sessions")
    recent = db.get_all_sessions(limit=10, data_source=data_source_filter)
    if recent:
        display_rows = []
        for r in recent:
            badge_class = f"badge-{r['prediction'].lower()}"
            pred_html = f"<span class='{badge_class}'>{r['prediction']}</span>"
            audit_html = f"<span class='hash-pill'>Block #{r['block_index']}</span>" if r['audited'] else "<span style='color:#6B7280;'>Pending</span>"
            
            src_val = r.get("data_source", "SYNTHETIC_DEMO")
            if src_val == "LIVE_NETWORK":
                source_badge = "<span class='badge-source-live'>LIVE</span>"
            elif src_val == "PUBLIC_DATASET":
                source_badge = "<span class='badge-source-public'>DATASET</span>"
            elif src_val == "CONTROLLED_LAB":
                source_badge = "<span class='badge-purple'>LAB</span>"
            else:
                source_badge = "<span class='badge-source-demo'>DEMO</span>"

            display_rows.append({
                "Session ID": r["session_id"],
                "Timestamp (UTC)": r["timestamp"][:19].replace("T", " "),
                "Origin": source_badge,
                "Source (Anonymized)": r["src_ip_hash"],
                "Destination": f"{r['dst_ip_hash']}:{r['dst_port']}",
                "Protocol": r["protocol"],
                "Classification": pred_html,
                "Confidence": f"{r['confidence']*100:.1f}%",
                "Ledger Status": audit_html
            })

        df_display = pd.DataFrame(display_rows)
        st.write(df_display.to_html(escape=False, index=False), unsafe_allow_html=True)
    else:
        st.write("No session records found for the selected data source.")
                "Timestamp (UTC)": r["timestamp"][:19].replace("T", " "),
                "Source (Anonymized)": r["src_ip_hash"],
                "Destination": f"{r['dst_ip_hash']}:{r['dst_port']}",
                "Protocol": r["protocol"],
                "Classification": pred_html,
                "Confidence": f"{r['confidence']*100:.1f}%",
                "Ledger Status": audit_html
            })

        df_display = pd.DataFrame(display_rows)
        st.write(df_display.to_html(escape=False, index=False), unsafe_allow_html=True)
    else:
        st.write("No session records found.")

