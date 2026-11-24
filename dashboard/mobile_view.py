"""
Mobile Device Security Dashboard View for CyberNex.
Provides USB-connected Android endpoint monitoring via ADB, installed package auditing,
high-risk permission analysis, MITRE ATT&CK threat classification, blockchain audit records,
and Apple iOS feasibility assessment.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from blockchain.ledger import get_ledger
from blockchain.verification import verify_chain_integrity
from config import PALETTE
from database.db import get_db
from mobile.adb_manager import ConnectedDevice, get_adb_manager
from mobile.ios_investigation import get_ios_feasibility_analysis
from mobile.security_scanner import (
    CRITICAL_ANDROID_PERMISSIONS,
    DeviceSecurityPosture,
    InstalledApp,
    MobileSecurityScanner,
)
from mobile.threat_classifier import (
    DeviceSecurityAssessment,
    MobileThreatClassifier,
    ThreatFinding,
)


def render_mobile_view() -> None:
    """Render the Mobile Device Security management view."""
    st.markdown("""
        <div class="soc-header">
            <h1>📱 CyberNex — Mobile Device Security Monitoring</h1>
            <p>Authorized USB Android endpoint auditing, dangerous permission detection, OS hardening checks & blockchain-audited forensics.</p>
        </div>
    """, unsafe_allow_html=True)

    adb = get_adb_manager()
    db = get_db()
    ledger = get_ledger()

    # Initialize session state for mobile view
    if "mobile_selected_device_serial" not in st.session_state:
        st.session_state.mobile_selected_device_serial = None
    if "mobile_current_posture" not in st.session_state:
        st.session_state.mobile_current_posture = None
    if "mobile_current_assessment" not in st.session_state:
        st.session_state.mobile_current_assessment = None
    if "mobile_monitoring_active" not in st.session_state:
        st.session_state.mobile_monitoring_active = True
    if "mobile_include_simulated" not in st.session_state:
        st.session_state.mobile_include_simulated = True

    # Main Tabs
    tab_devices, tab_analysis, tab_threats, tab_history, tab_ios = st.tabs([
        "🔌 A. Connected Devices",
        "📋 B. Security Analysis",
        "🚨 C. Threat Monitoring & Scoring",
        "📜 D. Device History",
        "🍏 E. Apple iOS Investigation"
    ])

    # Enumerate devices
    detected_devices = adb.detect_devices(include_simulated=st.session_state.mobile_include_simulated)

    # =========================================================================
    # TAB A: CONNECTED DEVICES
    # =========================================================================
    with tab_devices:
        st.subheader("1. USB Device Detection & Connection Management")

        # Top diagnostic bar
        col_adb, col_ctrl = st.columns([2, 1])
        with col_adb:
            if adb.is_available:
                st.markdown(
                    f"<span class='badge-normal'>● ADB ACTIVE: {adb.adb_path}</span> &nbsp; "
                    f"<span class='hash-pill'>{adb.get_adb_version()}</span>",
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    "<span class='badge-suspicious'>⚠️ ADB NOT ON PATH — SIMULATION BENCHMARK ACTIVE</span>",
                    unsafe_allow_html=True
                )
                st.caption(
                    "Physical Android monitoring requires Android SDK platform-tools (`adb.exe`). "
                    "Demonstration profiles are active below for immediate testing."
                )

        with col_ctrl:
            col_b1, col_b2 = st.columns(2)
            with col_b1:
                if st.button("🔄 Refresh Devices", use_container_width=True):
                    st.rerun()
            with col_b2:
                sim_label = "Disable Demo Devices" if st.session_state.mobile_include_simulated else "Enable Demo Devices"
                if st.button(sim_label, use_container_width=True):
                    st.session_state.mobile_include_simulated = not st.session_state.mobile_include_simulated
                    st.rerun()

        st.markdown("<hr style='margin: 12px 0;'/>", unsafe_allow_html=True)

        if not detected_devices:
            st.warning("⚠️ No connected Android devices detected via USB. Please connect a device or enable demo devices.")
        else:
            # Device Selector
            device_options = {d.serial: f"{d.display_name} [{d.status.upper()}] — {d.device_hash}" for d in detected_devices}
            current_choice = st.session_state.mobile_selected_device_serial
            default_index = 0
            if current_choice and current_choice in device_options:
                default_index = list(device_options.keys()).index(current_choice)

            selected_serial = st.selectbox(
                "Select Active USB Device to Inspect:",
                options=list(device_options.keys()),
                format_func=lambda s: device_options[s],
                index=default_index
            )
            st.session_state.mobile_selected_device_serial = selected_serial

            # Find active device object
            active_dev = next((d for d in detected_devices if d.serial == selected_serial), detected_devices[0])

            # Device Telemetry Card
            st.markdown(f"""
                <div style="background: #111827; border: 1px solid #1F2937; border-left: 4px solid #06B6D4; border-radius: 8px; padding: 18px; margin: 15px 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <span style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC;">
                            {active_dev.display_name}
                        </span>
                        <span class="{'badge-normal' if active_dev.is_authorized else 'badge-malicious'}">
                            STATUS: {active_dev.status.upper()}
                        </span>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 0.85rem; color: #94A3B8;">
                        <div><strong>Manufacturer:</strong> <span style="color: #F8FAFC;">{active_dev.manufacturer}</span></div>
                        <div><strong>Model:</strong> <span style="color: #F8FAFC;">{active_dev.model}</span></div>
                        <div><strong>Android OS:</strong> <span style="color: #06B6D4;">Version {active_dev.android_version} (API {active_dev.sdk_level})</span></div>
                        <div><strong>Privacy Device ID:</strong> <span class="hash-pill">{active_dev.device_hash}</span></div>
                        <div><strong>Connection Type:</strong> <span style="color: #F8FAFC;">{active_dev.connection_type}</span></div>
                        <div><strong>USB Debugging:</strong> <span style="color: #10B981;">{'Active / Enabled' if active_dev.usb_debugging else 'Disabled'}</span></div>
                        <div><strong>SELinux Mode:</strong> <span style="color: {'#10B981' if active_dev.selinux_mode.lower() == 'enforcing' else '#EF4444'}; font-weight: 600;">{active_dev.selinux_mode}</span></div>
                        <div><strong>Build Profile:</strong> <span style="color: #F8FAFC;">{active_dev.build_tags}</span></div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            # Security Warning for Unauthorized Devices
            if not active_dev.is_authorized:
                st.error("""
                    ⚠️ **Device Is Unauthorized.**
                    Please look at your Android device screen and tap **"Allow USB Debugging"**
                    (check *'Always allow from this computer'*), then click **Refresh Devices**.
                """)

            # Control Action Buttons
            c_scan, c_disc = st.columns([2, 1])
            with c_scan:
                if st.button("🔍 Run Deep Security Scan", type="primary", use_container_width=True, disabled=not active_dev.is_authorized):
                    with st.spinner(f"Auditing packages and security posture on {active_dev.display_name}..."):
                        scanner = MobileSecurityScanner(adb)
                        classifier = MobileThreatClassifier()
                        posture = scanner.scan_device(active_dev)
                        assessment = classifier.assess_device(posture)

                        # Save into session state
                        st.session_state.mobile_current_posture = posture
                        st.session_state.mobile_current_assessment = assessment

                        # Save scan to database
                        scan_record = {
                            "scan_id": f"SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{active_dev.device_hash[-4:]}",
                            "timestamp": assessment.timestamp,
                            "device_hash": posture.device_hash,
                            "manufacturer": posture.manufacturer,
                            "model": posture.model,
                            "android_version": posture.android_version,
                            "total_apps_scanned": posture.total_packages,
                            "safe_count": assessment.safe_count,
                            "low_risk_count": assessment.low_risk_count,
                            "suspicious_count": assessment.suspicious_count,
                            "high_risk_count": assessment.high_risk_count,
                            "security_score": assessment.security_score,
                            "overall_verdict": assessment.overall_verdict,
                            "findings": [f.to_dict() for f in assessment.findings]
                        }
                        db.insert_mobile_scan(scan_record)

                        # Create and mine tamper-evident blockchain audit record
                        block = ledger.create_mobile_scan_record(assessment, posture, scan_id=scan_record["scan_id"])
                        db.update_mobile_scan_block_index(scan_record["scan_id"], block.index_num)

                        st.session_state.mobile_current_scan_id = scan_record["scan_id"]
                        st.session_state.mobile_current_scan_block = block
                        st.success(f"Security audit completed for {active_dev.display_name}! Overall Verdict: {assessment.overall_verdict} • Mined to Blockchain Block #{block.index_num}")
                        st.rerun()

            with c_disc:
                if st.button("🛑 Stop / Disconnect Monitoring", use_container_width=True):
                    ok, msg = adb.disconnect_device(active_dev.serial)
                    st.info(msg)

        # Connection Setup Instructions Expander
        with st.expander("📖 Step-by-Step Android USB Debugging Setup Guide"):
            st.markdown("""
            ### How to Connect and Authorize Your Android Phone:
            1. **Enable Developer Options on Android:**
               - Open **Settings** > **About Phone**.
               - Find **Build Number** and tap it **7 times** consecutively until the prompt says *"You are now a developer!"*.
            2. **Enable USB Debugging:**
               - Go back to **Settings** > **System** > **Developer Options** (or **Settings** > **Additional Settings**).
               - Toggle **USB Debugging** to **ON**.
            3. **Connect USB Cable:**
               - Connect your Android phone to this laptop using a high-quality data USB cable (not charge-only).
            4. **Authorize Computer Prompt:**
               - Unlock your phone. A popup will appear: *"Allow USB debugging? The computer's RSA key fingerprint is..."*.
               - Check the box **"Always allow from this computer"** and tap **Allow**.
            5. **Verify ADB Connection in CyberNex:**
               - Click the **"🔄 Refresh Devices"** button above. Your phone model will appear in the device selector.
            """)

    # Retrieve current posture and assessment from session state (or load default for selected device)
    posture: Optional[DeviceSecurityPosture] = st.session_state.mobile_current_posture
    assessment: Optional[DeviceSecurityAssessment] = st.session_state.mobile_current_assessment

    if posture is None and detected_devices:
        # Default scan on first view for demo convenience
        active_dev = next((d for d in detected_devices if d.serial == st.session_state.mobile_selected_device_serial), detected_devices[0])
        scanner = MobileSecurityScanner(adb)
        classifier = MobileThreatClassifier()
        posture = scanner.scan_device(active_dev)
        assessment = classifier.assess_device(posture)
        st.session_state.mobile_current_posture = posture
        st.session_state.mobile_current_assessment = assessment

    # =========================================================================
    # TAB B: SECURITY ANALYSIS
    # =========================================================================
    with tab_analysis:
        st.subheader("2. Package Inventory & Permission Matrix")

        if posture is None:
            st.info("Run a security scan in Tab A to generate package and permission analysis.")
        else:
            # Package counts metric cards
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.metric("Total Packages", f"{posture.total_packages:,}")
            with c2:
                st.metric("3rd-Party Applications", f"{posture.third_party_packages_count:,}")
            with c3:
                st.metric("System Packages", f"{posture.system_packages_count:,}")
            with c4:
                st.metric("Sideloaded / Unknown", f"{posture.sideloaded_count:,}")

            st.markdown("<hr style='margin: 15px 0;'/>", unsafe_allow_html=True)

            # Application Inventory Table
            st.markdown("#### Installed Third-Party Application Inventory")
            app_filter = st.radio(
                "Filter Applications:",
                ["All Inspected Apps", "Sideloaded Apps Only", "Apps with Critical Privileges Only"],
                horizontal=True
            )

            filtered_apps = posture.apps
            if "Sideloaded Apps Only" in app_filter:
                filtered_apps = [a for a in filtered_apps if a.is_sideloaded]
            elif "Critical Privileges Only" in app_filter:
                filtered_apps = [a for a in filtered_apps if a.has_critical_privileges]

            if not filtered_apps:
                st.info("No applications match the selected filter.")
            else:
                table_rows = []
                for a in filtered_apps:
                    table_rows.append({
                        "Application": a.app_name,
                        "Package Name": a.package_name,
                        "Installer Source": a.install_source,
                        "Sideloaded": "⚠️ Yes (Unverified)" if a.is_sideloaded else "✓ Verified Store",
                        "Target SDK": a.target_sdk,
                        "Critical Privileges": len(a.critical_permissions),
                        "Total Permissions": len(a.permissions)
                    })

                df_apps = pd.DataFrame(table_rows)
                st.dataframe(df_apps, use_container_width=True, hide_index=True)

            st.markdown("<hr style='margin: 20px 0;'/>", unsafe_allow_html=True)

            # Permission Analysis Matrix
            st.markdown("#### High-Risk Permission Analysis")
            col_chart, col_desc = st.columns([1, 1])

            # Aggregate critical permissions across apps
            perm_counts: Dict[str, int] = {}
            for k in CRITICAL_ANDROID_PERMISSIONS.keys():
                count = sum(1 for a in posture.apps if k in a.permissions)
                if count > 0:
                    friendly_name = CRITICAL_ANDROID_PERMISSIONS[k]["name"]
                    perm_counts[friendly_name] = count

            with col_chart:
                if perm_counts:
                    df_perms = pd.DataFrame(list(perm_counts.items()), columns=["Permission", "App Count"]).sort_values("App Count", ascending=True)
                    fig = px.bar(
                        df_perms,
                        x="App Count",
                        y="Permission",
                        orientation="h",
                        title="Distribution of High-Risk Android Permissions",
                        color="App Count",
                        color_continuous_scale=["#06B6D4", "#EF4444"]
                    )
                    fig.update_layout(
                        template="plotly_dark",
                        paper_bgcolor="#111827",
                        plot_bgcolor="#111827",
                        font=dict(family="Inter, sans-serif"),
                        height=320,
                        margin=dict(l=10, r=10, t=40, b=10)
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.success("✓ Zero abusive or high-risk permissions detected across installed applications.")

            with col_desc:
                st.markdown("""
                **Critical Permission Attack Vectors (MITRE ATT&CK Mobile):**
                - **Accessibility Service (`T1452`):** Primary abuse vector for banking trojans. Enables reading screen text, keystroke logging, and autonomous confirmation of financial transfers.
                - **System Alert Window (`T1453`):** Draw overlays atop legitimate apps (tapjacking phishing).
                - **Request Install Packages (`T1475`):** Silent dropper capability downloading unauthorized secondary APKs.
                - **Device Admin (`T1401`):** Persistent locker capability preventing uninstallation.
                """)

            # OS Security Posture Checks
            st.markdown("#### Android OS Security Posture Checks")
            co1, co2, co3, co4 = st.columns(4)
            with co1:
                se_badge = "<span class='badge-normal'>ENFORCING</span>" if posture.selinux_mode.lower() == "enforcing" else "<span class='badge-malicious'>PERMISSIVE</span>"
                st.markdown(f"**SELinux MAC Enforcement**<br/>{se_badge}", unsafe_allow_html=True)
            with co2:
                dbg_badge = "<span class='badge-normal'>USER BUILD (SECURE)</span>" if not posture.is_debuggable_build else "<span class='badge-malicious'>DEBUGGABLE (HIGH RISK)</span>"
                st.markdown(f"**Kernel Debuggability**<br/>{dbg_badge}", unsafe_allow_html=True)
            with co3:
                key_badge = "<span class='badge-normal'>RELEASE KEYS</span>" if not posture.has_test_keys else "<span class='badge-suspicious'>TEST-KEYS (CUSTOM ROM)</span>"
                st.markdown(f"**Firmware Signing Keys**<br/>{key_badge}", unsafe_allow_html=True)
            with co4:
                unk_badge = "<span class='badge-suspicious'>ENABLED</span>" if posture.unknown_sources_enabled else "<span class='badge-normal'>DISABLED (SECURE)</span>"
                st.markdown(f"**Unknown Sources Sideloading**<br/>{unk_badge}", unsafe_allow_html=True)

    # =========================================================================
    # TAB C: THREAT MONITORING & SCORING
    # =========================================================================
    with tab_threats:
        st.subheader("3. Malware Detection, Scoring & Blockchain Audit")

        if assessment is None or posture is None:
            st.info("Run a security scan to evaluate threat classifications.")
        else:
            # Top Score Bar
            col_gauge, col_summary = st.columns([1, 2])

            with col_gauge:
                # Security Score Gauge
                score = assessment.security_score
                gauge_color = "#10B981" if score >= 80 else ("#F59E0B" if score >= 60 else "#EF4444")
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "Device Security Score", 'font': {'size': 18, 'color': '#F8FAFC'}},
                    number={'font': {'size': 44, 'color': gauge_color}, 'suffix': "/100"},
                    gauge={
                        'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#4B5563"},
                        'bar': {'color': gauge_color, 'thickness': 0.28},
                        'bgcolor': "#1F2937",
                        'borderwidth': 1,
                        'bordercolor': "#374151",
                        'steps': [
                            {'range': [0, 50], 'color': 'rgba(239, 68, 68, 0.2)'},
                            {'range': [50, 75], 'color': 'rgba(245, 158, 11, 0.2)'},
                            {'range': [75, 100], 'color': 'rgba(16, 185, 129, 0.2)'}
                        ]
                    }
                ))
                fig_gauge.update_layout(
                    paper_bgcolor="#111827",
                    plot_bgcolor="#111827",
                    height=240,
                    margin=dict(l=20, r=20, t=30, b=10)
                )
                st.plotly_chart(fig_gauge, use_container_width=True)

            with col_summary:
                # Risk level counts
                st.markdown(f"""
                    <div style="background: #111827; border: 1px solid #1F2937; border-radius: 8px; padding: 18px; height: 100%;">
                        <div style="font-size: 1.1rem; font-weight: 700; color: #F8FAFC; margin-bottom: 8px;">
                            Overall Verdict: <span class="{
                                'badge-malicious' if assessment.overall_verdict == 'HIGH RISK'
                                else ('badge-suspicious' if assessment.overall_verdict == 'SUSPICIOUS' else 'badge-normal')
                            }">{assessment.overall_verdict}</span>
                        </div>
                        <div style="font-size: 0.85rem; color: #94A3B8; margin-bottom: 14px;">
                            Device: <strong>{posture.manufacturer} {posture.model}</strong> &bull; Anonymized ID: <span class="hash-pill">{posture.device_hash}</span>
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;">
                            <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; padding: 10px; text-align: center;">
                                <div style="font-size: 1.4rem; font-weight: 700; color: #EF4444;">{assessment.high_risk_count}</div>
                                <div style="font-size: 0.72rem; color: #F87171; font-weight: 600;">HIGH RISK</div>
                            </div>
                            <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 6px; padding: 10px; text-align: center;">
                                <div style="font-size: 1.4rem; font-weight: 700; color: #F59E0B;">{assessment.suspicious_count}</div>
                                <div style="font-size: 0.72rem; color: #FBBF24; font-weight: 600;">SUSPICIOUS</div>
                            </div>
                            <div style="background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); border-radius: 6px; padding: 10px; text-align: center;">
                                <div style="font-size: 1.4rem; font-weight: 700; color: #06B6D4;">{assessment.low_risk_count}</div>
                                <div style="font-size: 0.72rem; color: #38BDF8; font-weight: 600;">LOW RISK</div>
                            </div>
                            <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 6px; padding: 10px; text-align: center;">
                                <div style="font-size: 1.4rem; font-weight: 700; color: #10B981;">{assessment.safe_count}</div>
                                <div style="font-size: 0.72rem; color: #34D399; font-weight: 600;">SAFE</div>
                            </div>
                        </div>
                    </div>
                """, unsafe_allow_html=True)

            st.markdown("<hr style='margin: 20px 0;'/>", unsafe_allow_html=True)

            # Categorized Findings Detail List
            st.markdown("#### Detailed Threat & Posture Findings")
            for idx, finding in enumerate(assessment.findings, 1):
                badge_class = {
                    "HIGH RISK": "badge-malicious",
                    "SUSPICIOUS": "badge-suspicious",
                    "LOW RISK": "badge-cyan",
                    "SAFE": "badge-normal"
                }.get(finding.risk_level, "badge-cyan")

                with st.expander(f"Finding #{idx}: [{finding.risk_level}] {finding.name}", expanded=(finding.risk_level in ["HIGH RISK", "SUSPICIOUS"])):
                    st.markdown(f"""
                        <div style="margin-bottom: 8px;">
                            <span class="{badge_class}">{finding.risk_level}</span> &nbsp;
                            <span style="font-size: 0.8rem; color: #9CA3AF;">Category: {finding.category}</span> &nbsp;
                            {f"<span class='hash-pill'>MITRE ATT&CK: {finding.mitre_attack_id}</span>" if finding.mitre_attack_id else ""} &nbsp;
                            <span style="font-size: 0.8rem; color: #06B6D4;">ML/Heuristic Confidence: {finding.ml_confidence * 100:.1f}%</span>
                        </div>
                        <div style="font-size: 0.88rem; color: #E2E8F0; margin-bottom: 8px;">
                            <strong>Detection Reason:</strong> {finding.detection_reason}
                        </div>
                        <div style="background: rgba(15, 23, 42, 0.7); border-left: 3px solid #06B6D4; padding: 8px 12px; border-radius: 4px; font-size: 0.84rem; color: #94A3B8;">
                            <strong style="color: #38BDF8;">Recommended Remediation:</strong> {finding.recommended_action}
                        </div>
                    """, unsafe_allow_html=True)

            st.markdown("<hr style='margin: 20px 0;'/>", unsafe_allow_html=True)

            # Blockchain Commitment Section
            st.markdown("#### Cryptographic Blockchain Ledger Audit Record")
            st.markdown("""
                Every mobile security audit is sealed into the persistent SHA-256 blockchain hash-chain.
                The record contains an anonymized device identifier, security score, categorized threat tally,
                and a cryptographic SHA-256 digest of all detection findings.
                **Privacy Guarantee:** Raw hardware serials, IMEI numbers, phone numbers, or user messages are strictly excluded.
            """)

            scan_id_val = st.session_state.get("mobile_current_scan_id", f"SCAN-LIVE-{posture.device_hash[-4:]}")
            if st.button("⛓️ Mine & Commit Mobile Scan to Blockchain", type="primary", use_container_width=True):
                with st.spinner("Mining Proof-of-Work SHA-256 block for mobile scan..."):
                    block = ledger.create_mobile_scan_record(assessment, posture, scan_id=scan_id_val)
                    db.update_mobile_scan_block_index(scan_id_val, block.index_num)
                    st.session_state.mobile_current_scan_block = block
                    st.success(f"""
                        ✓ Audit Block #{block.index_num} successfully mined and committed to the ledger!
                    """)
                    st.markdown(f"""
                        <div style="background: #111827; border: 1px solid #1F2937; border-left: 4px solid #10B981; border-radius: 6px; padding: 14px; font-family: monospace; font-size: 0.82rem;">
                            <strong>Block Index:</strong> #{block.index_num}<br/>
                            <strong>Event ID:</strong> {block.event_id}<br/>
                            <strong>Data Source:</strong> MOBILE_SECURITY<br/>
                            <strong>Previous Hash:</strong> <span class="hash-pill">{block.prev_hash}</span><br/>
                            <strong>Current Hash:</strong> <span class="hash-pill">{block.current_hash}</span><br/>
                            <strong>Mining Nonce:</strong> {block.nonce} (Proof-of-Work verified)
                        </div>
                    """, unsafe_allow_html=True)

    # =========================================================================
    # TAB D: DEVICE HISTORY
    # =========================================================================
    with tab_history:
        st.subheader("4. Device Audit History & Posture Tracking")

        if posture is None:
            st.info("Select a device in Tab A to view its historical audit trail.")
        else:
            history = db.get_mobile_device_history(posture.device_hash)
            st.markdown(f"**Audit History for Device:** <span class='hash-pill'>{posture.device_hash}</span> ({posture.manufacturer} {posture.model})", unsafe_allow_html=True)

            if not history:
                st.info("No prior scans recorded for this device.")
            else:
                hist_rows = []
                for h in history:
                    block_idx = f"Block #{h['block_index']}" if h.get("block_index") is not None else "Uncommitted"
                    hist_rows.append({
                        "Scan ID": h["scan_id"],
                        "Timestamp (UTC)": h["timestamp"][:19].replace("T", " "),
                        "Security Score": f"{h['security_score']}/100",
                        "Verdict": h["overall_verdict"],
                        "High Risk": h["high_risk_count"],
                        "Suspicious": h["suspicious_count"],
                        "Low Risk": h["low_risk_count"],
                        "Safe": h["safe_count"],
                        "Blockchain Block": block_idx
                    })

                df_hist = pd.DataFrame(hist_rows)
                st.dataframe(df_hist, use_container_width=True, hide_index=True)

                # Score Trend over Time if multiple scans exist
                if len(history) > 1:
                    df_chart = pd.DataFrame([
                        {"timestamp": h["timestamp"], "score": h["security_score"]}
                        for h in reversed(history)
                    ])
                    fig_trend = px.line(
                        df_chart,
                        x="timestamp",
                        y="score",
                        title="Security Score Evolution Over Time",
                        markers=True,
                        line_shape="linear"
                    )
                    fig_trend.update_layout(
                        template="plotly_dark",
                        paper_bgcolor="#111827",
                        plot_bgcolor="#111827",
                        height=260,
                        margin=dict(l=10, r=10, t=35, b=10)
                    )
                    st.plotly_chart(fig_trend, use_container_width=True)

    # =========================================================================
    # TAB E: APPLE IOS INVESTIGATION
    # =========================================================================
    with tab_ios:
        st.subheader("5. Apple iOS USB Monitoring Feasibility & Architectural Analysis")

        analysis = get_ios_feasibility_analysis()

        st.markdown(f"""
            <div style="background: #111827; border: 1px solid #1F2937; border-left: 4px solid #A855F7; border-radius: 8px; padding: 18px; margin-bottom: 20px;">
                <div style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 6px;">
                    {analysis['title']}
                </div>
                <div style="margin-bottom: 10px;">
                    <span class="badge-purple">{analysis['verdict']}</span> &nbsp;
                    <span style="font-size: 0.8rem; color: #94A3B8;">Feasibility: {analysis['feasibility_level']}</span>
                </div>
                <p style="color: #CBD5E1; font-size: 0.88rem; line-height: 1.6; margin: 0;">
                    {analysis['executive_summary']}
                </p>
            </div>
        """, unsafe_allow_html=True)

        # 1. Sandbox Architecture
        st.markdown("#### 1. Kernel-Enforced Apple App Sandbox Isolation")
        st.markdown(f"""
        ```
        ┌────────────────────────────────────────────────────────────────────────┐
        │                        HOST PC (WINDOWS / LINUX)                       │
        │                          USB Lightning / Type-C                        │
        └───────────────────────────────────┬────────────────────────────────────┘
                                            │ usbmuxd (TCP Multiplexer)
                                            ▼
        ┌────────────────────────────────────────────────────────────────────────┐
        │                        APPLE LOCKDOWN DAEMON (lockdownd)               │
        │  • Enforces cryptographic host pairing ('Trust This Computer')         │
        │  • Exposes basic device metadata only (iOS version, model, serial)     │
        │  • BLOCKS ARBITRARY SHELL EXECUTION (Zero Android-ADB equivalent)      │
        └───────────────────────────────────┬────────────────────────────────────┘
                                            │
                                            ▼
        ┌────────────────────────────────────────────────────────────────────────┐
        │                   XNU KERNEL MANDATORY ACCESS CONTROL (MAC)            │
        │  ┌───────────────────────────┐       ┌───────────────────────────────┐ │
        │  │ App A Container Sandbox   │       │ App B Container Sandbox       │ │
        │  │ (/private/var/mobile/...) │       │ (/private/var/mobile/...)     │ │
        │  │ Zero inter-process read   │  ◄-X-►│ Zero inter-process read       │ │
        │  └───────────────────────────┘       └───────────────────────────────┘ │
        └────────────────────────────────────────────────────────────────────────┘
        ```
        """)
        st.markdown(f"*{analysis['sandbox_architecture']['details']}*")

        st.markdown("<hr style='margin: 20px 0;'/>", unsafe_allow_html=True)

        # 2. Comparison Matrix Table
        st.markdown("#### 2. Android ADB vs Apple iOS USB Diagnostic Capabilities")
        df_comp = pd.DataFrame(analysis["comparison_matrix"])
        df_comp.columns = ["Security Dimension", "Android ADB Diagnostic", "Apple iOS Architecture"]
        st.dataframe(df_comp, use_container_width=True, hide_index=True)

        st.markdown("<hr style='margin: 20px 0;'/>", unsafe_allow_html=True)

        # 3. Available Diagnostic Protocols
        st.markdown("#### 3. Available iOS Diagnostic Interfaces on External Hosts")
        col_p1, col_p2 = st.columns(2)
        for i, proto in enumerate(analysis["usb_protocols_available"]):
            target_col = col_p1 if i % 2 == 0 else col_p2
            with target_col:
                st.markdown(f"""
                    <div style="background: #111827; border: 1px solid #1F2937; border-radius: 6px; padding: 14px; margin-bottom: 12px;">
                        <strong style="color: #38BDF8;">{proto['protocol']}</strong><br/>
                        <span style="font-size: 0.75rem; color: #9CA3AF;">Platforms: {proto['platform_support']}</span>
                        <div style="font-size: 0.82rem; color: #E2E8F0; margin-top: 6px;">
                            <strong>Capabilities:</strong> {proto['capabilities']}
                        </div>
                        <div style="font-size: 0.80rem; color: #F87171; margin-top: 4px;">
                            <strong>Limitation:</strong> {proto['limitations']}
                        </div>
                    </div>
                """, unsafe_allow_html=True)

        st.markdown("<hr style='margin: 20px 0;'/>", unsafe_allow_html=True)

        # 4. Enterprise Alternatives & Tradeoffs
        st.markdown("#### 4. Enterprise Alternatives & Security Trade-Offs")
        for alt in analysis["enterprise_alternatives"]:
            st.markdown(f"""
                <div style="background: #111827; border: 1px solid #1F2937; border-left: 3px solid #06B6D4; padding: 12px 16px; border-radius: 6px; margin-bottom: 10px;">
                    <strong style="color: #F8FAFC;">{alt['solution']}</strong> &bull; <span style="color: #06B6D4; font-size: 0.8rem;">{alt['frameworks']}</span>
                    <p style="font-size: 0.84rem; color: #94A3B8; margin: 6px 0 0 0;">{alt['description']}</p>
                </div>
            """, unsafe_allow_html=True)

        st.markdown("##### Security and Privacy Trade-Off Matrix")
        for trade in analysis["security_privacy_tradeoffs"]:
            st.markdown(f"""
                - **{trade['dimension']}:** {trade['analysis']}
            """)

