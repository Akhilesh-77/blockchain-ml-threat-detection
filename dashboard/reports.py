"""
Forensic Reports and Data Export Dashboard View.
Allows SOC analysts to filter historical sessions, download detection reports as CSV,
and export cryptographic ledger audit proofs as JSON.
"""

from datetime import datetime, timezone
import json
import pandas as pd
import streamlit as st
from blockchain.ledger import get_ledger
from database.db import get_db


def render_reports_view() -> None:
    """Render Forensic Reports and Export page."""
    st.markdown("""
        <div class="soc-header">
            <h1>📑 Forensic Reports & Cryptographic Export</h1>
            <p>Query historical detection telemetry, generate compliance reports, and export tamper-evident blockchain ledger proofs for third-party audit.</p>
        </div>
    """, unsafe_allow_html=True)

    db = get_db()
    ledger = get_ledger()

    sessions = db.get_all_sessions()
    chain = ledger.get_chain()

    if not sessions:
        st.info("No network sessions recorded in database yet.")
        return

    # Filter Controls
    st.subheader("1. Filter Telemetry Records")
    fcol1, fcol2, fcol3 = st.columns(3)

    with fcol1:
        class_filter = st.multiselect(
            "Filter by Threat Classification:",
            ["Normal", "Suspicious", "Malicious"],
            default=["Normal", "Suspicious", "Malicious"]
        )

    with fcol2:
        min_conf = st.slider("Minimum Model Confidence:", 0.0, 1.0, 0.50, step=0.05)

    with fcol3:
        audit_only = st.checkbox("Show Only Audited Sessions (Mined on Ledger)", value=False)

    # Filter dataframe
    df_raw = pd.DataFrame(sessions)
    filtered_df = df_raw[
        (df_raw["prediction"].isin(class_filter)) &
        (df_raw["confidence"] >= min_conf)
    ]
    if audit_only:
        filtered_df = filtered_df[filtered_df["audited"] == 1]

    st.write(f"Displaying **{len(filtered_df):,}** of **{len(df_raw):,}** total sessions.")

    # 2. Export Actions
    st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
    st.subheader("2. Export Detection Reports & Ledger Proofs")

    exp_col1, exp_col2 = st.columns(2)

    with exp_col1:
        st.markdown("**Download Filtered Detection Report (CSV)**")
        # Flatten features dict for clean CSV export
        export_rows = []
        for _, row in filtered_df.iterrows():
            r_dict = dict(row)
            feats = r_dict.pop("features", {})
            r_dict.update(feats)
            export_rows.append(r_dict)

        export_csv_df = pd.DataFrame(export_rows)
        csv_bytes = export_csv_df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="📥 Download Detection Report (CSV)",
            data=csv_bytes,
            file_name=f"soc_threat_detection_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )

    with exp_col2:
        st.markdown("**Export Cryptographic Blockchain Ledger (JSON)**")
        ledger_export_data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "ledger_type": "SHA-256 Tamper-Evident Hash-Chain",
            "total_blocks": len(chain),
            "blocks": [b.to_dict() for b in chain]
        }
        json_bytes = json.dumps(ledger_export_data, indent=2).encode("utf-8")

        st.download_button(
            label="📥 Export Ledger Cryptographic Proofs (JSON)",
            data=json_bytes,
            file_name=f"blockchain_audit_ledger_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )

    # 3. Interactive Data Table
    st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
    st.subheader("3. Forensic Session Records")

    if not filtered_df.empty:
        display_list = []
        for _, r in filtered_df.iterrows():
            b_class = f"badge-{r['prediction'].lower()}"
            display_list.append({
                "Session ID": r["session_id"],
                "Timestamp (UTC)": r["timestamp"][:19].replace("T", " "),
                "Source Hash": r["src_ip_hash"],
                "Destination": f"{r['dst_ip_hash']}:{r['dst_port']}",
                "Protocol": r["protocol"],
                "Classification": f"<span class='{b_class}'>{r['prediction']}</span>",
                "Confidence": f"{float(r['confidence'])*100:.1f}%",
                "Ledger Block": f"Block #{r['block_index']}" if r["block_index"] is not None else "Pending"
            })

        st.write(pd.DataFrame(display_list).to_html(escape=False, index=False), unsafe_allow_html=True)
    else:
        st.warning("No records match the current filter criteria.")

    # 4. Audit Log Trail
    st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
    st.subheader("4. System Audit Activity Log")
    logs = db.get_audit_logs(limit=25)
    if logs:
        st.dataframe(pd.DataFrame(logs), use_container_width=True)
    else:
        st.write("No system audit events recorded.")

