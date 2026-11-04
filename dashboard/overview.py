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
    """Render the executive SOC Overview page."""
    db = get_db()
    ledger = get_ledger()

    # 1. Fetch real-time statistics directly from SQLite
    stats = db.get_session_stats()
    chain = ledger.get_chain()
    verification = verify_chain_integrity(chain, difficulty=2)

    total_sessions = stats["total_sessions"]
    normal_count = stats["normal_sessions"]
    suspicious_count = stats["suspicious_sessions"]
    malicious_count = stats["malicious_sessions"]
    threat_pct = stats["threat_pct"]
    total_blocks = len(chain)

    st.markdown("""
        <div class="soc-header">
            <h1>🛡️ SOC Command Center & Telemetry</h1>
            <p>Live monitoring of encrypted network session metadata classified by Random Forest & audited via SHA-256 Hash-Chain.</p>
        </div>
    """, unsafe_allow_html=True)

    # 2. Key Telemetry Metric Cards
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
        sessions = db.get_all_sessions(limit=50)
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
            st.info("No historical session activity recorded.")

    # 5. Recent Activity Table
    st.subheader("Recent Network Sessions")
    recent = db.get_all_sessions(limit=8)
    if recent:
        display_rows = []
        for r in recent:
            badge_class = f"badge-{r['prediction'].lower()}"
            pred_html = f"<span class='{badge_class}'>{r['prediction']}</span>"
            audit_html = f"<span class='hash-pill'>Block #{r['block_index']}</span>" if r['audited'] else "<span style='color:#6B7280;'>Pending</span>"
            display_rows.append({
                "Session ID": r["session_id"],
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
