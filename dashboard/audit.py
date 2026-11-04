"""
Blockchain Audit Ledger Dashboard View.
Provides cryptographic hash-chain inspection, real-time integrity verification,
detailed block forensic explorer, and an interactive Tamper Simulation Stress Test.
"""

import json
import pandas as pd
import streamlit as st
from blockchain.ledger import get_ledger
from blockchain.verification import verify_chain_integrity
from config import PALETTE
from database.db import get_db


def render_audit_view() -> None:
    """Render the Blockchain Audit Ledger page."""
    st.markdown("""
        <div class="soc-header">
            <h1>⛓️ Cryptographic Blockchain Audit Ledger</h1>
            <p>Local SHA-256 hash-chain maintaining immutable, tamper-evident audit records for every ML detection event. Zero sensitive packet payload data stored.</p>
        </div>
    """, unsafe_allow_html=True)

    db = get_db()
    ledger = get_ledger()

    # Fetch chain
    chain = ledger.get_chain()
    total_blocks = len(chain)

    # 1. Top Integrity Action Bar
    st.subheader("1. Cryptographic Ledger Integrity Verification")

    vcol1, vcol2 = st.columns([3, 1])
    with vcol1:
        st.markdown(f"""
            Total Mined Blocks: **{total_blocks:,}** (Genesis Block + **{max(total_blocks - 1, 0):,}** Threat Detection Events)  
            *Each block binds index, previous hash, timestamp, event ID, prediction, confidence, and metadata into a SHA-256 digest.*
        """)

    with vcol2:
        run_verify = st.button("🔍 Verify Entire Ledger Integrity", type="primary", use_container_width=True)

    # Perform verification
    report = verify_chain_integrity(chain, difficulty=2)

    if report.is_valid:
        st.markdown(f"""
            <div class="valid-alert">
                <div style="font-size: 1.05rem; font-weight: 700; color: #34D399; margin-bottom: 4px;">
                    ✅ HASH-CHAIN INTEGRITY VERIFIED — ZERO TAMPERING DETECTED
                </div>
                <div style="font-size: 0.88rem; color: #A7F3D0;">
                    All <strong>{total_blocks}</strong> blocks verified successfully. Every cryptographic digest strictly matches its canonical payload, and all previous-hash pointers maintain unbroken continuity to the Genesis root.
                </div>
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
            <div class="tamper-alert">
                <div style="font-size: 1.05rem; font-weight: 700; color: #F87171; margin-bottom: 4px;">
                    🚨 CRYPTOGRAPHIC TAMPERING DETECTED!
                </div>
                <div style="font-size: 0.88rem; color: #FECACA;">
                    <strong>Violation Type:</strong> {report.error_type} at <strong>Block #{report.tampered_block_index}</strong><br/>
                    <strong>Forensic Details:</strong> {report.error_message}
                </div>
            </div>
        """, unsafe_allow_html=True)

    # 2. Interactive Tamper Simulation Panel
    st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
    st.subheader("2. 🧪 Tamper Simulation & Stress Test")
    st.markdown("""
        > [!CAUTION]
        > **Demonstrate Tamper-Evidence:** As an auditor or evaluator, test the blockchain's integrity protection by deliberately modifying an existing audit record in the database *without* updating its cryptographic hash. The verification engine will immediately identify the corruption.
    """)

    if total_blocks > 1:
        tcol1, tcol2, tcol3 = st.columns([2, 2, 2])

        with tcol1:
            block_indices = [b.index_num for b in chain if b.index_num > 0]
            selected_block_idx = st.selectbox("Select Block to Alter:", block_indices, index=min(len(block_indices)-1, 0))

        with tcol2:
            current_target_block = next((b for b in chain if b.index_num == selected_block_idx), None)
            current_val = current_target_block.prediction if current_target_block else "Malicious"
            st.markdown(f"**Current Authentic Label:** `{current_val}`")
            tamper_choice = st.selectbox("Change Prediction to (Unauthorized Edit):", ["Normal", "Suspicious", "Malicious"])

        with tcol3:
            st.markdown("<div style='height: 25px;'></div>", unsafe_allow_html=True)
            if st.button("⚠️ Simulate Unauthorized Database Alteration", type="secondary", use_container_width=True):
                db.tamper_block_for_testing(selected_block_idx, tamper_choice)
                st.error(f"Altered Block #{selected_block_idx} prediction to '{tamper_choice}' in SQLite without cryptographic re-mining.")
                st.rerun()

        # Repair / Reset controls
        rcol1, rcol2 = st.columns(2)
        with rcol1:
            if not report.is_valid:
                if st.button("🛠️ Restore / Repair Block Authentic State", use_container_width=True):
                    # Restore original from event if possible, or revert to Malicious/Suspicious
                    db.repair_block(report.tampered_block_index, "Malicious")
                    st.success(f"Repaired Block #{report.tampered_block_index} back to authentic prediction.")
                    st.rerun()
        with rcol2:
            if st.button("🔄 Reset Ledger to Genesis", help="Clears existing blocks and restarts fresh ledger"):
                db.clear_blockchain()
                ledger._ensure_genesis_block()
                st.success("Ledger reset to Genesis state.")
                st.rerun()
    else:
        st.info("Ingest traffic sessions in the Traffic Analysis tab to generate blocks for testing.")

    # 3. Block Forensic Inspector
    st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
    st.subheader("3. 🔍 Block Forensic Inspector")

    inspect_idx = st.selectbox("Inspect Block Details:", [b.index_num for b in reversed(chain)], index=0)
    inspect_block = next((b for b in chain if b.index_num == inspect_idx), None)

    if inspect_block:
        icol1, icol2 = st.columns([2, 1])

        with icol1:
            st.markdown(f"**Canonical Cryptographic Payload (Pre-Image String):**")
            st.code(inspect_block.serialize_payload(), language="text")

            st.markdown("**Sanitized Metadata Attributes (Zero-PII):**")
            st.json(inspect_block.metadata_json)

        with icol2:
            st.markdown(f"**Block Number:** `{inspect_block.index_num}`")
            st.markdown(f"**Event UUID:** `{inspect_block.event_id}`")
            st.markdown(f"**Timestamp (UTC):** `{inspect_block.timestamp}`")
            st.markdown(f"**Prediction:** `{inspect_block.prediction}`")
            st.markdown(f"**Confidence Score:** `{inspect_block.confidence*100:.2f}%`")
            st.markdown(f"**Mining Nonce:** `{inspect_block.nonce}`")

            st.markdown("**Current SHA-256 Digest:**")
            st.markdown(f"<span class='hash-pill'>{inspect_block.current_hash}</span>", unsafe_allow_html=True)

            st.markdown("**Previous Block Link Digest:**")
            st.markdown(f"<span class='hash-pill'>{inspect_block.prev_hash}</span>", unsafe_allow_html=True)

    # 4. Hash-Chain Explorer Table
    st.markdown("<hr style='border-color: #1f2937;'/>", unsafe_allow_html=True)
    st.subheader("4. 📋 Hash-Chain Ledger Explorer")

    table_data = []
    for b in reversed(chain):
        status_badge = "<span class='badge-normal'>VALID</span>"
        if not report.is_valid and b.index_num == report.tampered_block_index:
            status_badge = "<span class='badge-malicious'>TAMPERED</span>"

        pred_badge = f"<span class='badge-{b.prediction.lower()}'>{b.prediction}</span>" if b.index_num > 0 else "<span class='badge-cyan'>GENESIS</span>"

        table_data.append({
            "Block #": b.index_num,
            "Event ID": b.event_id,
            "Timestamp (UTC)": b.timestamp[:19].replace("T", " "),
            "Prediction": pred_badge,
            "Confidence": f"{b.confidence*100:.1f}%",
            "Current Hash": f"<span class='hash-pill'>{b.current_hash[:16]}...</span>",
            "Previous Hash": f"<span class='hash-pill'>{b.prev_hash[:16]}...</span>",
            "Nonce": b.nonce,
            "Integrity": status_badge
        })

    df_table = pd.DataFrame(table_data)
    st.write(df_table.to_html(escape=False, index=False), unsafe_allow_html=True)

