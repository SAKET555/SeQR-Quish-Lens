"""
SeQR QuishLens (Smart QR Code & Quishing Defense Tool)
Main Streamlit Application with Modern Cybersecurity Theme & High-Contrast Light/Dark Support.
"""

import os
from typing import Any, List, Dict
from datetime import datetime
import pandas as pd
import streamlit as st
import plotly.graph_objects as go

from core.qr_parser import QRParser
from core.virustotal_client import VirusTotalClient
from core.redirect_analyzer import RedirectAnalyzer
from core.heuristic_analyzer import HeuristicAnalyzer
from core.dns_analyzer import DNSAnalyzer
from core.risk_scorer import RiskScorer
from core.stego_analyzer import StegoAnalyzer
from core.report_generator import ReportGenerator


# Configure Streamlit Page
st.set_page_config(
    page_title="SeQR QuishLens | Quishing Defense Tool",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session Scan History
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

# Enforce High-Contrast Cybersecurity Theme across Light & Dark System/Streamlit Settings
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

    html, body, [data-testid="stAppViewContainer"], .stApp {
        background-color: #0b1120 !important;
        color: #f1f5f9 !important;
        font-family: 'Inter', system-ui, -apple-system, sans-serif !important;
    }

    .stApp p, .stApp span, .stApp label, .stApp h1, .stApp h2, .stApp h3, 
    .stApp h4, .stApp h5, .stApp h6, .stApp div, .stApp li {
        color: #e2e8f0;
    }

    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
        background-color: #151e30 !important;
        color: #38bdf8 !important;
        border: 1px solid #24344d !important;
        border-radius: 6px !important;
    }

    [data-testid="stSidebar"] {
        background-color: #0f172a !important;
        border-right: 1px solid #1e293b !important;
    }
    [data-testid="stSidebar"] p, [data-testid="stSidebar"] span, 
    [data-testid="stSidebar"] label, [data-testid="stSidebar"] h1, 
    [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
        color: #e2e8f0 !important;
    }
    [data-testid="stSidebar"] .stMarkdown h3 {
        color: #38bdf8 !important;
        font-size: 1.1rem !important;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 0.4rem;
        margin-top: 1rem;
    }

    [data-testid="stWidgetLabel"] label, [data-testid="stWidgetLabel"] p {
        color: #f8fafc !important;
        font-weight: 600 !important;
        font-size: 0.92rem !important;
    }

    div[data-baseweb="input"] > div, div[data-baseweb="select"] > div {
        background-color: #151e30 !important;
        color: #f8fafc !important;
        border: 1px solid #24344d !important;
        border-radius: 8px !important;
        box-shadow: inset 0 1px 2px rgba(0,0,0,0.3) !important;
    }
    input {
        color: #f8fafc !important;
    }
    div[data-baseweb="select"] span {
        color: #f8fafc !important;
    }

    div[data-baseweb="popover"], div[data-baseweb="menu"], ul[role="listbox"] {
        background-color: #151e30 !important;
        border: 1px solid #334155 !important;
        border-radius: 8px !important;
    }
    div[data-baseweb="menu"] li, ul[role="listbox"] li {
        color: #f8fafc !important;
    }
    div[data-baseweb="menu"] li:hover, ul[role="listbox"] li[aria-selected="true"] {
        background-color: #24344d !important;
        color: #38bdf8 !important;
    }

    [data-testid="stSlider"] div {
        color: #cbd5e1 !important;
    }

    button[data-baseweb="tab"] {
        color: #94a3b8 !important;
        background-color: transparent !important;
        border-radius: 8px 8px 0 0 !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
        padding: 0.6rem 1.2rem !important;
        border: none !important;
        transition: all 0.2s ease !important;
    }
    button[data-baseweb="tab"]:hover {
        color: #e2e8f0 !important;
        background-color: rgba(255, 255, 255, 0.03) !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #38bdf8 !important;
        border-bottom: 3px solid #38bdf8 !important;
        background-color: rgba(56, 189, 248, 0.1) !important;
    }

    div.stButton > button {
        background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%) !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.65rem 1.5rem !important;
        box-shadow: 0 4px 14px rgba(2, 132, 199, 0.35) !important;
        transition: all 0.2s ease-in-out !important;
    }
    div.stButton > button:hover {
        background: linear-gradient(135deg, #0369a1 0%, #075985 100%) !important;
        box-shadow: 0 6px 20px rgba(2, 132, 199, 0.55) !important;
        transform: translateY(-1px) !important;
    }

    [data-testid="stFileUploader"] {
        background-color: #151e30 !important;
        border: 2px dashed #334155 !important;
        border-radius: 12px !important;
        padding: 1.2rem !important;
    }

    [data-testid="stDataFrame"] {
        background-color: #151e30 !important;
        border: 1px solid #24344d !important;
        border-radius: 8px !important;
    }

    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
        padding: 2.2rem;
        border-radius: 16px;
        border: 1px solid #334155;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        margin-bottom: 2rem;
        text-align: center;
        position: relative;
    }
    .header-badge {
        display: inline-block;
        background: rgba(56, 189, 248, 0.12);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.3);
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 1px;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        margin-bottom: 0.8rem;
    }
    .main-title {
        color: #f8fafc !important;
        font-size: 2.3rem;
        font-weight: 800;
        margin-bottom: 0.4rem;
        letter-spacing: -0.5px;
    }
    .main-subtitle {
        color: #94a3b8 !important;
        font-size: 1.05rem;
        font-weight: 400;
    }

    .verdict-card {
        padding: 2rem;
        border-radius: 14px;
        text-align: center;
        margin-bottom: 1.8rem;
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.35);
        backdrop-filter: blur(10px);
    }
    .verdict-score {
        display: inline-block;
        padding: 0.4rem 1.2rem;
        border-radius: 20px;
        font-size: 1.1rem;
        font-weight: 700;
        margin-top: 0.6rem;
    }

    .metric-box {
        background: #151e30;
        padding: 1.3rem 1rem;
        border-radius: 12px;
        border: 1px solid #24344d;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        text-align: center;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-box:hover {
        border-color: #38bdf8;
        transform: translateY(-2px);
    }
    .metric-icon {
        font-size: 1.3rem;
        margin-bottom: 0.2rem;
    }
    .metric-value {
        font-size: 1.75rem;
        font-weight: 800;
        color: #f8fafc !important;
    }
    .metric-label {
        font-size: 0.82rem;
        font-weight: 600;
        color: #94a3b8 !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 0.2rem;
    }

    .flag-card {
        background: #151e30;
        padding: 1.2rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        border: 1px solid #24344d;
        border-left: 5px solid #ef4444;
    }
    .flag-card-critical { border-left-color: #dc2626; background: rgba(220, 38, 38, 0.08); }
    .flag-card-high { border-left-color: #ef4444; background: rgba(239, 68, 68, 0.08); }
    .flag-card-medium { border-left-color: #f59e0b; background: rgba(245, 158, 11, 0.08); }
    .flag-card-low { border-left-color: #3b82f6; background: rgba(59, 130, 246, 0.08); }
    .flag-card-info { border-left-color: #10b981; background: rgba(16, 185, 129, 0.08); }

    .severity-badge {
        font-size: 0.75rem;
        font-weight: 800;
        padding: 0.25rem 0.6rem;
        border-radius: 4px;
        letter-spacing: 0.5px;
        display: inline-block;
    }
    .severity-critical { background: #dc2626; color: #ffffff !important; }
    .severity-high { background: #ef4444; color: #ffffff !important; }
    .severity-medium { background: #f59e0b; color: #000000 !important; }
    .severity-low { background: #3b82f6; color: #ffffff !important; }
    .severity-info { background: #10b981; color: #ffffff !important; }

    .hop-card {
        background: #151e30;
        padding: 1rem 1.2rem;
        border-radius: 10px;
        border: 1px solid #24344d;
        margin-bottom: 0.8rem;
    }
    .status-code-badge {
        padding: 0.2rem 0.6rem;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.8rem;
    }
    .status-200 { background: rgba(16, 185, 129, 0.2); color: #34d399 !important; border: 1px solid #10b981; }
    .status-redirect { background: rgba(245, 158, 11, 0.2); color: #fbbf24 !important; border: 1px solid #f59e0b; }
    </style>
""", unsafe_allow_html=True)


def render_header():
    """Renders main dashboard header."""
    st.markdown("""
        <div class="main-header">
            <div class="header-badge">🛡️ SeQR QUISHLENS v3.0 • PRODUCTION ENGINE</div>
            <div class="main-title">SeQR QuishLens</div>
            <div class="main-subtitle">Production Quishing Defense Platform with Live DNS Lookup, VirusTotal API v3 & Image Tampering Audits</div>
        </div>
    """, unsafe_allow_html=True)


def render_sidebar():
    """Renders sidebar controls, API key settings, and session export."""
    st.sidebar.markdown("### ⚙️ Engine Configuration")

    env_vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    vt_key_input = st.sidebar.text_input(
        "VirusTotal API Key (v3)",
        value=env_vt_key,
        type="password",
        help="Enter your VirusTotal API Key. If left blank, the analyzer operates in Heuristic Fallback Mode."
    )

    if vt_key_input.strip():
        st.sidebar.success("🔑 VT API Key Configured")
    else:
        st.sidebar.warning("⚠️ Operating in Heuristic Fallback Mode (No VT Key)")

    st.sidebar.markdown("### 🛠️ Scan Settings")
    max_hops = st.sidebar.slider("Max Redirect Hops", min_value=1, max_value=10, value=5)
    timeout_sec = st.sidebar.slider("HTTP Timeout (seconds)", min_value=2, max_value=15, value=6)

    st.sidebar.markdown("### 💡 Quick Test Samples")
    sample_choice = st.sidebar.selectbox(
        "Load Sample QR Scenario",
        [
            "None (Upload or Custom Input)",
            "Safe Link (Wikipedia)",
            "Phishing URL (IP Host + Suspicious TLD)",
            "Shortened URL (TinyURL)",
            "Open Wi-Fi QR (No Password)"
        ],
        index=0
    )

    # Session Threat Log & CSV Export
    st.sidebar.markdown("### 📜 Session History")
    if st.session_state.scan_history:
        st.sidebar.info(f"Recorded Scans: {len(st.session_state.scan_history)}")
        df_hist = pd.DataFrame(st.session_state.scan_history)
        csv_bytes = df_hist.to_csv(index=False).encode('utf-8')
        st.sidebar.download_button(
            label="📥 Export Session Log (CSV)",
            data=csv_bytes,
            file_name=f"seqr_quishlens_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    else:
        st.sidebar.caption("No scans performed in this session yet.")

    return vt_key_input, max_hops, timeout_sec, sample_choice


def run_full_analysis(input_data: Any, is_raw_text: bool, vt_key: str, max_hops: int, timeout_sec: int):
    """
    Executes full multi-stage security pipeline.
    """
    with st.spinner("🔍 Decoding Payload & Executing Live Security Audit..."):
        # Step 1: QR Parsing
        qr_result = QRParser.parse(input_data, is_raw_text=is_raw_text)

        if not qr_result["success"]:
            st.error(f"❌ QR Decoding Failed: {qr_result.get('error')}")
            return

        raw_text = qr_result["raw_text"]
        payload_type = qr_result["payload_type"]
        parsed_details = qr_result["parsed_details"]

        # Step 2: Image Metadata Audit (if image file provided)
        image_metadata = {}
        if not is_raw_text and input_data is not None:
            image_metadata = StegoAnalyzer.audit_image(input_data)

        # Step 3: Payload Specific Scans
        heuristic_result = {"heuristic_score": 0, "flag_count": 0, "flags": []}
        redirect_result = {"success": False, "is_shortened": False, "chain": [], "redirect_count": 0}
        vt_result = {"fallback_mode": True, "reason": "Not a URL payload", "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}}
        dns_result = {"resolved": False, "ip": None, "error": "N/A"}

        if payload_type == "URL":
            # Extract domain for DNS lookup
            from urllib.parse import urlparse
            parsed_u = urlparse(raw_text if raw_text.startswith("http") else f"http://{raw_text}")
            hostname = parsed_u.hostname or ""

            dns_result = DNSAnalyzer.audit_domain(hostname)

            # Heuristic URL & DNS Scan
            heuristic_result = HeuristicAnalyzer.audit_url(raw_text)

            # Redirect Trace
            redirect_result = RedirectAnalyzer.trace_redirects(raw_text, max_hops=max_hops, timeout=timeout_sec)

            # Target URL for VT
            target_vt_url = redirect_result.get("final_url", raw_text) if redirect_result.get("success") else raw_text

            # VirusTotal Audit
            vt_client = VirusTotalClient(api_key=vt_key)
            vt_result = vt_client.analyze_url(target_vt_url)

        elif payload_type == "WIFI":
            heuristic_result = HeuristicAnalyzer.audit_wifi(parsed_details)

        # Merge Image Tampering Flags into Heuristics if present
        if image_metadata.get("tampering_flags"):
            for flag in image_metadata["tampering_flags"]:
                heuristic_result["flags"].append(flag)
                heuristic_result["flag_count"] = len(heuristic_result["flags"])

        # Step 4: Compute Unified Risk Score
        risk_summary = RiskScorer.calculate_risk(
            payload_type=payload_type,
            heuristic_result=heuristic_result,
            redirect_result=redirect_result,
            vt_result=vt_result
        )

        # Step 5: Save to Session Log
        st.session_state.scan_history.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": raw_text[:60],
            "type": payload_type,
            "verdict": risk_summary["verdict"],
            "risk_score": risk_summary["risk_score"],
            "dns_resolved": dns_result.get("resolved", False),
            "vt_malicious": vt_result.get("stats", {}).get("malicious", 0)
        })

        # Display Results Dashboard
        render_results_dashboard(
            raw_text, payload_type, parsed_details, heuristic_result,
            redirect_result, vt_result, risk_summary, dns_result, image_metadata
        )


def run_batch_analysis(urls_list: List[str], vt_key: str, max_hops: int, timeout_sec: int):
    """
    Executes batch threat intelligence scan over multiple URLs.
    """
    results = []
    progress_bar = st.progress(0.0)

    for idx, raw_url in enumerate(urls_list):
        clean_u = raw_url.strip()
        if not clean_u:
            continue

        parsed_u = QRParser.parse(clean_u, is_raw_text=True)
        p_type = parsed_u.get("payload_type", "URL")

        from urllib.parse import urlparse
        hostname = urlparse(clean_u if clean_u.startswith("http") else f"http://{clean_u}").hostname or ""
        dns_res = DNSAnalyzer.audit_domain(hostname)

        heur_res = HeuristicAnalyzer.audit_url(clean_u)
        redir_res = RedirectAnalyzer.trace_redirects(clean_u, max_hops=max_hops, timeout=timeout_sec)

        vt_client = VirusTotalClient(api_key=vt_key)
        vt_res = vt_client.analyze_url(clean_u)

        risk_res = RiskScorer.calculate_risk(p_type, heur_res, redir_res, vt_res)

        results.append({
            "Target URL": clean_u,
            "Payload Format": p_type,
            "Verdict": risk_res["verdict"],
            "Risk Score": risk_res["risk_score"],
            "DNS Resolved": "Yes" if dns_res.get("resolved") else "No (NXDOMAIN)",
            "VT Malicious": vt_res.get("stats", {}).get("malicious", 0),
            "Flags Triggered": heur_res.get("flag_count", 0)
        })

        st.session_state.scan_history.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": clean_u[:60],
            "type": p_type,
            "verdict": risk_res["verdict"],
            "risk_score": risk_res["risk_score"],
            "dns_resolved": dns_res.get("resolved", False),
            "vt_malicious": vt_res.get("stats", {}).get("malicious", 0)
        })

        progress_bar.progress((idx + 1) / len(urls_list))

    df_results = pd.DataFrame(results)
    st.markdown("### 📦 Batch Audit Summary Matrix")
    st.dataframe(df_results, use_container_width=True)

    csv_batch = df_results.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Download Batch Results (CSV)",
        data=csv_batch,
        file_name=f"seqr_quishlens_batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        use_container_width=True
    )


def render_results_dashboard(
    raw_text: str,
    payload_type: str,
    parsed_details: dict,
    heuristic_result: dict,
    redirect_result: dict,
    vt_result: dict,
    risk_summary: dict,
    dns_result: dict,
    image_metadata: dict
):
    """
    Renders top metrics cards and detail tabs with high contrast and visual polish.
    """
    verdict = risk_summary["verdict"]
    score = risk_summary["risk_score"]
    color = risk_summary["verdict_color"]
    icon = risk_summary["badge_icon"]

    st.markdown("---")

    # Top Verdict Banner
    st.markdown(f"""
        <div class="verdict-card" style="background: linear-gradient(135deg, {color}18 0%, #0f172a 100%); border: 2px solid {color}; box-shadow: 0 0 25px {color}33;">
            <div style="font-size: 0.85rem; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; color: {color}; margin-bottom: 0.3rem;">SECURITY AUDIT VERDICT</div>
            <h1 style="color: {color}; margin: 0; font-size: 2.2rem; font-weight: 800;">{icon} VERDICT: {verdict}</h1>
            <div class="verdict-score" style="background: {color}25; color: #ffffff; border: 1px solid {color}55;">
                Calculated Risk Score: <strong>{score}</strong> / 100
            </div>
            <p style="color: #cbd5e1; font-size: 1.05rem; margin-top: 0.8rem; margin-bottom: 0; line-height: 1.5;">{risk_summary['summary']}</p>
        </div>
    """, unsafe_allow_html=True)

    # 1-Click PDF Report Export Button
    pdf_bytes = ReportGenerator.generate_pdf(
        raw_text, payload_type, heuristic_result, redirect_result, vt_result, risk_summary, dns_result
    )
    st.download_button(
        label="📄 Download Official Executive PDF Security Audit Report",
        data=pdf_bytes,
        file_name=f"SeQR_QuishLens_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        mime="application/pdf",
        type="primary",
        use_container_width=True
    )
    st.markdown("<br>", unsafe_allow_html=True)

    # Top Metrics Grid
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
            <div class="metric-box">
                <div class="metric-icon">🎯</div>
                <div class="metric-value" style="color: {color};">{score}/100</div>
                <div class="metric-label">Risk Gauge</div>
            </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
            <div class="metric-box">
                <div class="metric-icon">📦</div>
                <div class="metric-value" style="color: #38bdf8;">{payload_type}</div>
                <div class="metric-label">Payload Format</div>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
            <div class="metric-box">
                <div class="metric-icon">🚨</div>
                <div class="metric-value" style="color: #f59e0b;">{heuristic_result.get('flag_count', 0)}</div>
                <div class="metric-label">Heuristic Triggers</div>
            </div>
        """, unsafe_allow_html=True)
    with c4:
        vt_mal = vt_result.get("stats", {}).get("malicious", 0)
        vt_color = "#ef4444" if vt_mal > 0 else "#10b981"
        st.markdown(f"""
            <div class="metric-box">
                <div class="metric-icon">🌐</div>
                <div class="metric-value" style="color: {'#10b981' if dns_result.get('resolved') else '#ef4444'};">
                    {'RESOLVED' if dns_result.get('resolved') else 'NXDOMAIN'}
                </div>
                <div class="metric-label">DNS Status</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Detailed Tabs
    tab_overview, tab_heuristics, tab_dns, tab_vt, tab_redirects, tab_stego, tab_payload = st.tabs([
        "🛡️ Overview & Advice",
        "🔍 Heuristic Audit",
        "🌐 DNS Resolution",
        "🦠 VirusTotal Intelligence",
        "🔗 Redirect Chain",
        "🖼️ Image EXIF Metadata",
        "📱 Raw Payload"
    ])

    # Tab 1: Overview
    with tab_overview:
        col_left, col_right = st.columns([1, 1])
        with col_left:
            st.markdown("### 📋 Executive Summary")
            st.info(risk_summary["summary"])

            st.markdown("### 📊 Risk Score Breakdown")
            breakdown = risk_summary.get("score_breakdown", {})
            st.write(f"**Analysis Mode**: `{breakdown.get('mode')}`")

            st.progress(score / 100.0)

            if breakdown.get("vt_score_contrib", 0) > 0:
                st.write(f"- 🦠 **VirusTotal Component**: +{breakdown.get('vt_score_contrib')} pts")
            st.write(f"- 🔍 **Heuristic Component**: +{breakdown.get('heuristic_score_contrib')} pts")
            if breakdown.get("redirect_penalty", 0) > 0:
                st.write(f"- 🔗 **Redirect Penalty**: +{breakdown.get('redirect_penalty')} pts")

        with col_right:
            st.markdown("### 🛡️ Recommended Actions")
            for rec in risk_summary.get("recommendations", []):
                st.markdown(f"- {rec}")

    # Tab 2: Heuristic Audit
    with tab_heuristics:
        st.markdown("### 🔍 Zero-Day Heuristic Rule Audit")
        flags = heuristic_result.get("flags", [])
        if not flags:
            st.success("✅ No suspicious heuristic patterns detected. Payload passed all heuristic filters.")
        else:
            for flag in flags:
                severity = flag.get("severity", "MEDIUM").upper()
                sev_class = severity.lower()
                st.markdown(f"""
                    <div class="flag-card flag-card-{sev_class}">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                            <span class="severity-badge severity-{sev_class}">[{severity}]</span>
                            <span style="font-weight: 700; color: #ef4444; font-size: 0.9rem;">+{flag.get('points')} Risk Pts</span>
                        </div>
                        <h4 style="margin: 0; color: #f8fafc; font-size: 1.05rem;">{flag.get('title')}</h4>
                        <p style="margin-top: 0.4rem; margin-bottom: 0; color: #cbd5e1; font-size: 0.95rem; line-height: 1.4;">{flag.get('description')}</p>
                    </div>
                """, unsafe_allow_html=True)

    # Tab 3: DNS Resolution
    with tab_dns:
        st.markdown("### 🌐 Real-Time DNS & Host Audit")
        if dns_result.get("resolved"):
            st.success(f"✅ Domain successfully resolved to IP: `{dns_result.get('ip')}`")
            st.write(f"**Host**: `{dns_result.get('hostname')}`")
            st.write(f"**All IPs**: `{', '.join(dns_result.get('all_ips', []))}`")
            if dns_result.get("is_private"):
                st.error("⚠️ WARNING: Host resolves to an internal RFC1918 private network IP address.")
        else:
            st.error(f"❌ DNS Lookup Failed (NXDOMAIN): `{dns_result.get('error')}`")
            st.warning("⚠️ Non-existent domains in QR codes are high-risk indicators for domain hijacking or dead phishing links.")

    # Tab 4: VirusTotal
    with tab_vt:
        st.markdown("### 🦠 VirusTotal Vendor Detection Engine")
        if vt_result.get("fallback_mode"):
            st.info(f"ℹ️ {vt_result.get('reason')}")
        else:
            stats = vt_result.get("stats", {})
            col_chart, col_stats = st.columns([1, 1])

            with col_chart:
                labels = ["Malicious", "Suspicious", "Harmless", "Undetected"]
                values = [
                    stats.get("malicious", 0),
                    stats.get("suspicious", 0),
                    stats.get("harmless", 0),
                    stats.get("undetected", 0)
                ]
                colors_list = ["#ef4444", "#f59e0b", "#10b981", "#64748b"]

                fig = go.Figure(data=[go.Pie(
                    labels=labels,
                    values=values,
                    hole=.55,
                    marker_colors=colors_list,
                    textinfo="label+value",
                    hoverinfo="label+value+percent"
                )])
                fig.update_layout(
                    showlegend=True,
                    margin=dict(t=10, b=10, l=10, r=10),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#f8fafc", family="Inter, sans-serif"),
                    legend=dict(font=dict(color="#f8fafc"))
                )
                st.plotly_chart(fig, use_container_width=True)

            with col_stats:
                st.markdown(f"**Reputation Score**: `{vt_result.get('reputation', 0)}`")
                st.markdown(f"**Tags**: `{', '.join(vt_result.get('tags', [])) or 'None'}`")

                st.markdown("#### Security Vendor Verdict Highlights")
                vendor_results = vt_result.get("vendor_results", {})
                if vendor_results:
                    data_rows = []
                    for v_name, v_info in list(vendor_results.items())[:12]:
                        data_rows.append({"Vendor": v_name, "Category": v_info.get("category"), "Verdict": v_info.get("result")})
                    st.dataframe(data_rows, use_container_width=True)

    # Tab 5: Redirect Chain
    with tab_redirects:
        st.markdown("### 🔗 HTTP Redirect Trace & Unshortener")
        if payload_type != "URL":
            st.info("ℹ️ Redirect tracing is only applicable to URL payloads.")
        elif not redirect_result.get("success"):
            st.warning(f"⚠️ {redirect_result.get('error', 'Redirect scan failed')}")
        else:
            if redirect_result.get("is_shortened"):
                st.warning("⚠️ Target link uses a URL Shortening service. Multiple redirect hops detected.")
            else:
                st.success("✅ Target link is a direct URL without shortening disguises.")

            chain = redirect_result.get("chain", [])
            for hop in chain:
                st_code = hop.get('status_code', 200)
                st_badge_cls = "status-200" if st_code == 200 else "status-redirect"
                st.markdown(f"""
                    <div class="hop-card">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-weight: 700; color: #38bdf8; font-size: 1rem;">Hop {hop['step']}</span>
                            <span class="status-code-badge {st_badge_cls}">HTTP {st_code}</span>
                        </div>
                        <div style="font-family: 'JetBrains Mono', monospace; color: #f8fafc; font-size: 0.95rem; margin: 0.5rem 0; word-break: break-all;">
                            {hop['url']}
                        </div>
                        <div style="font-size: 0.85rem; color: #94a3b8;">
                            Server: <strong style="color: #cbd5e1;">{hop['server']}</strong> | Content-Type: <strong style="color: #cbd5e1;">{hop['content_type']}</strong>
                        </div>
                    </div>
                """, unsafe_allow_html=True)

    # Tab 6: Image EXIF Metadata
    with tab_stego:
        st.markdown("### 🖼️ Image Metadata & Tampering Audit")
        if not image_metadata or "error" in image_metadata:
            st.info("ℹ️ Image metadata audit is available when uploading QR image files directly.")
        else:
            col_m1, col_m2 = st.columns(2)
            with col_m1:
                st.write(f"**Image Format**: `{image_metadata.get('format')}`")
                st.write(f"**Dimensions**: `{image_metadata.get('size_pixels')}`")
                st.write(f"**Color Mode**: `{image_metadata.get('mode')}`")
            with col_m2:
                st.write(f"**EXIF Data Found**: `{'Yes' if image_metadata.get('has_exif') else 'No'}`")
                st.write(f"**Software Signature**: `{image_metadata.get('software') or 'Clean (None)'}`")

            if image_metadata.get("tampering_flags"):
                st.markdown("#### 🚨 Detected Image Anomaly Flags")
                for tf in image_metadata["tampering_flags"]:
                    st.warning(f"**{tf['title']}**: {tf['description']}")

    # Tab 7: Raw Payload
    with tab_payload:
        st.markdown("### 📱 Decoded Payload Details")
        st.code(raw_text, language="text")

        if payload_type == "WIFI" and parsed_details:
            st.markdown("#### Wi-Fi Configuration Parameters")
            st.json(parsed_details)


def main():
    render_header()
    vt_key, max_hops, timeout_sec, sample_choice = render_sidebar()

    st.markdown("### 📥 Select Security Scan Mode")
    input_tab1, input_tab2, input_tab3 = st.tabs([
        "📷 Upload QR Image",
        "🔗 Raw URL / Payload Text",
        "📦 Batch / Bulk Scanner"
    ])

    input_data = None
    is_raw_text = False

    # Preset sample handler vs Custom scan tabs
    if sample_choice != "None (Upload or Custom Input)":
        st.markdown("<br>", unsafe_allow_html=True)
        if sample_choice == "Safe Link (Wikipedia)":
            st.info("💡 **Loaded Preset**: Legitimate Wikipedia URL (`https://www.wikipedia.org`)")
            if st.button("🚀 Launch Security Audit Scan (Wikipedia Preset)", type="primary", use_container_width=True):
                run_full_analysis("https://www.wikipedia.org", True, vt_key, max_hops, timeout_sec)

        elif sample_choice == "Phishing URL (IP Host + Suspicious TLD)":
            st.info("💡 **Loaded Preset**: Phishing URL with IP Host & Suspicious TLD (`http://192.168.1.100/login.xyz`)")
            if st.button("🚀 Launch Security Audit Scan (Phishing Preset)", type="primary", use_container_width=True):
                run_full_analysis("http://192.168.1.100/login.xyz?auth=user@chase.com", True, vt_key, max_hops, timeout_sec)

        elif sample_choice == "Shortened URL (TinyURL)":
            st.info("💡 **Loaded Preset**: Shortened Link (`https://tinyurl.com/2p8v2h8z`)")
            if st.button("🚀 Launch Security Audit Scan (Shortened Preset)", type="primary", use_container_width=True):
                run_full_analysis("https://tinyurl.com/2p8v2h8z", True, vt_key, max_hops, timeout_sec)

        elif sample_choice == "Open Wi-Fi QR (No Password)":
            st.info("💡 **Loaded Preset**: Insecure Open Wi-Fi Payload (`WIFI:S:Free_Coffee_Guest;T:nopass;;`)")
            if st.button("🚀 Launch Security Audit Scan (Wi-Fi Preset)", type="primary", use_container_width=True):
                run_full_analysis("WIFI:S:Free_Coffee_Guest;T:nopass;;", True, vt_key, max_hops, timeout_sec)

        st.caption("To upload custom QR images or scan your own URLs, set 'Load Sample QR Scenario' to 'None (Upload or Custom Input)' in the sidebar.")
    else:
        # Render clean tabs for user custom scans
        input_tab1, input_tab2, input_tab3 = st.tabs([
            "📷 Upload QR Image",
            "🔗 Raw URL / Payload Text",
            "📦 Batch / Bulk Scanner"
        ])

        with input_tab1:
            uploaded_file = st.file_uploader(
                "Upload QR Code Image (PNG, JPG, JPEG, WEBP)",
                type=["png", "jpg", "jpeg", "webp"],
                help="Upload a QR code image to decode and analyze for security threats."
            )
            if uploaded_file is not None:
                st.image(uploaded_file, caption="Uploaded QR Code Image", width=240)
                if st.button("🚀 Launch Security Audit Scan (Uploaded QR)", type="primary", use_container_width=True):
                    run_full_analysis(uploaded_file, False, vt_key, max_hops, timeout_sec)

        with input_tab2:
            raw_input = st.text_input(
                "Enter Raw Payload or Target URL",
                placeholder="e.g. https://example.com or WIFI:S:MyNet;T:WPA;P:secret;;",
                help="Directly enter a URL or QR payload string to perform a security audit."
            )
            if raw_input.strip():
                if st.button("🚀 Launch Security Audit Scan (Target URL)", type="primary", use_container_width=True):
                    run_full_analysis(raw_input.strip(), True, vt_key, max_hops, timeout_sec)

        with input_tab3:
            st.markdown("#### 📦 Bulk Threat Scanner")
            bulk_text = st.text_area(
                "Enter List of URLs / Payloads (one per line)",
                placeholder="https://wikipedia.org\nhttp://abcd.com\nhttps://tinyurl.com/2p8v2h8z",
                height=140
            )
            if st.button("🚀 Launch Batch Threat Audit", type="primary", use_container_width=True):
                urls = [u.strip() for u in bulk_text.splitlines() if u.strip()]
                if urls:
                    run_batch_analysis(urls, vt_key, max_hops, timeout_sec)
                else:
                    st.warning("Please enter at least one URL or payload to run a batch scan.")


if __name__ == "__main__":
    main()
