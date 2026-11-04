"""
Main Application Entry Point for Blockchain-Audited ML System for Encrypted Threat Detection.
Orchestrates SOC telemetry, traffic analysis, machine learning evaluation, and blockchain ledger audit.
"""

from pathlib import Path
import sys
import streamlit as st

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blockchain.ledger import get_ledger
from blockchain.verification import verify_chain_integrity
from dashboard.about import render_about_view
from dashboard.analysis import render_traffic_analysis_view
from dashboard.audit import render_audit_view
from dashboard.ml_view import render_ml_view
from dashboard.overview import render_overview_view
from dashboard.reports import render_reports_view
from dashboard.styles import SOC_CUSTOM_CSS
from database.db import get_db
from ml.predict import get_predictor


# Page Configuration
st.set_page_config(
    page_title="SOC Sentinel | Blockchain-Audited ML Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Custom SOC Dark CSS
st.markdown(SOC_CUSTOM_CSS, unsafe_allow_html=True)


def init_system() -> None:
    """Initialize SQLite database, Blockchain Genesis, and ML Model artifacts if needed."""
    db = get_db()
    ledger = get_ledger()
    predictor = get_predictor()

    # If database has no sessions, seed initial demo sessions
    if db.get_block_count() <= 1 and len(db.get_all_sessions()) == 0:
        from database.seed_data import seed_initial_soc_data
        seed_initial_soc_data(count=20)


def main() -> None:
    """Main application loop."""
    init_system()

    db = get_db()
    ledger = get_ledger()
    chain = ledger.get_chain()
    verification = verify_chain_integrity(chain, difficulty=2)

    # --- Sidebar Navigation ---
    with st.sidebar:
        st.markdown("""
            <div style="padding: 10px 0 15px 0;">
                <div style="font-size: 1.25rem; font-weight: 700; color: #F8FAFC; letter-spacing: -0.02em;">
                    🛡️ SOC SENTINEL
                </div>
                <div style="font-size: 0.78rem; color: #06B6D4; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;">
                    Blockchain &bull; ML &bull; TLS Forensics
                </div>
            </div>
        """, unsafe_allow_html=True)

        st.markdown("<hr style='margin: 5px 0 15px 0; border-color: #1F2937;'/>", unsafe_allow_html=True)

        selected_page = st.radio(
            "Navigation Menu",
            [
                "🛡️ SOC Overview",
                "📡 Traffic Analysis",
                "🧠 Machine Learning",
                "⛓️ Blockchain Audit",
                "📑 Reports & Export",
                "ℹ️ Architecture & About"
            ],
            index=0
        )

        st.markdown("<hr style='margin: 20px 0; border-color: #1F2937;'/>", unsafe_allow_html=True)

        # Telemetry & Status Badges in Sidebar
        st.markdown("**System Health & Telemetry**")
        st.markdown("<span class='badge-normal'>● ML ENGINE ACTIVE</span>", unsafe_allow_html=True)

        if verification.is_valid:
            st.markdown("<span class='badge-normal'>● LEDGER UNTAMPERED</span>", unsafe_allow_html=True)
        else:
            st.markdown("<span class='badge-malicious'>● TAMPER DETECTED</span>", unsafe_allow_html=True)

        st.markdown(f"""
            <div style="margin-top: 15px; font-size: 0.8rem; color: #9CA3AF; line-height: 1.6;">
                <strong>Database:</strong> SQLite 3<br/>
                <strong>Hashing:</strong> SHA-256 (Canonical)<br/>
                <strong>Total Mined Blocks:</strong> {len(chain)}<br/>
                <strong>Encrypted Flows:</strong> {db.get_block_count() - 1 if db.get_block_count() > 0 else 0}
            </div>
        """, unsafe_allow_html=True)

        st.markdown("<hr style='margin: 20px 0; border-color: #1F2937;'/>", unsafe_allow_html=True)
        st.markdown("""
            <div style="font-size: 0.75rem; color: #6B7280;">
                Google DeepMind Advanced Engineering<br/>
                Autonomous Cyber-Defense & Forensics
            </div>
        """, unsafe_allow_html=True)

    # --- Render Selected Page ---
    if "SOC Overview" in selected_page:
        render_overview_view()
    elif "Traffic Analysis" in selected_page:
        render_traffic_analysis_view()
    elif "Machine Learning" in selected_page:
        render_ml_view()
    elif "Blockchain Audit" in selected_page:
        render_audit_view()
    elif "Reports & Export" in selected_page:
        render_reports_view()
    elif "Architecture & About" in selected_page:
        render_about_view()


if __name__ == "__main__":
    main()
