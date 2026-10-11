"""
VanGuard: Enterprise Network Threat Defense Platform.
Autonomous Transport-Layer Threat Intelligence & Forensics.
"""

import os
import sys
import time
import json
import html
from datetime import datetime
import streamlit as st
import pandas as pd
import numpy as np

# Ensure root path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from agentndr.config import DEFAULT_CONFIG
from agentndr.flow_extractor import FlowExtractor, NetworkFlow
from agentndr.isolation_forest import IsolationForestDetector
from agentndr.traffic_generator import TrafficGenerator, AttackCategory
from agentndr.alert_queue import AlertQueueManager, AnomalyAlert
from agentndr.benchmark_suite import Phase1BenchmarkSuite
from agentndr.live_sniffer import LivePacketSniffer
from agentndr.service_resolver import GLOBAL_RESOLVER

# Forward & backward compatibility wrapper for st.dataframe (prevents PyArrow crashes & width deprecation)
_original_st_dataframe = st.dataframe
def _compat_st_dataframe(data=None, *args, **kwargs):
    if data is not None and isinstance(data, pd.DataFrame):
        if "Value" in data.columns:
            data["Value"] = data["Value"].astype(str)
    try:
        return _original_st_dataframe(data, *args, **kwargs)
    except (TypeError, ValueError) as err:
        if "width" in kwargs and kwargs["width"] in ["stretch", "content"]:
            w_val = kwargs.pop("width")
            kwargs["use_container_width"] = (w_val == "stretch")
            return _original_st_dataframe(data, *args, **kwargs)
        raise err
st.dataframe = _compat_st_dataframe

# Page configuration
st.set_page_config(
    page_title="VanGuard - Network Security Monitor",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise UI Design System (Cloudflare / CrowdStrike Matte Palette)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Disable full-screen dimming and opacity drops during reruns */
    [data-testid="stAppViewContainer"],
    .stApp,
    section.main,
    [data-testid="stVerticalBlock"],
    [data-testid="stVerticalBlockBorderWrapper"],
    .element-container {
        opacity: 1 !important;
        filter: none !important;
        transition: none !important;
    }

    /* Hide the top-right running/status indicator animation */
    [data-testid="stStatusWidget"],
    .stStatusWidget {
        display: none !important;
        visibility: hidden !important;
    }

    /* Completely hide Streamlit header anchor link icons and action containers */
    [data-testid="stHeaderActionElements"],
    a.header-anchor,
    .css-15zrgzn,
    span[data-testid="stHeaderActionElements"],
    .stMarkdown a[href^="#"],
    h1 a, h2 a, h3 a, h4 a, h5 a, h6 a {
        display: none !important;
        visibility: hidden !important;
        pointer-events: none !important;
        width: 0 !important;
        height: 0 !important;
    }

    /* Header transparency */
    header[data-testid="stHeader"] {
        background: transparent !important;
    }

    /* Solid Dark Matte App Canvas */
    .stApp {
        background-color: #0B0F19 !important;
        background-image: none !important;
        color: #F1F5F9 !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        letter-spacing: -0.01em;
    }

    /* Enterprise Dark Slate Sidebar */
    [data-testid="stSidebar"] {
        background-color: #0F172A !important;
        background-image: none !important;
        border-right: 1px solid #1E293B !important;
        backdrop-filter: none !important;
    }

    /* Typography Defaults */
    h1, h2, h3, h4, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
        color: #F1F5F9 !important;
        font-weight: 600 !important;
        letter-spacing: -0.02em !important;
    }

    p, span, label, div {
        color: #F1F5F9;
    }

    .text-muted {
        color: #94A3B8 !important;
    }

    /* Enterprise Status Dots */
    .status-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-right: 8px;
        vertical-align: middle;
    }
    .dot-emerald { background-color: #10B981; }
    .dot-crimson { background-color: #F43F5E; }
    .dot-sky     { background-color: #38BDF8; }
    .dot-slate   { background-color: #64748B; }

    /* Brand Header */
    .brand-title {
        font-size: 1.75rem;
        font-weight: 700;
        letter-spacing: -0.03em;
        color: #F1F5F9;
        display: inline-block;
        line-height: 1.2;
    }

    .brand-pill {
        display: inline-block;
        background: #1E293B;
        border: 1px solid #334155;
        color: #38BDF8;
        font-size: 0.72rem;
        font-weight: 600;
        padding: 3px 9px;
        border-radius: 4px;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        vertical-align: middle;
        margin-left: 10px;
    }

    .brand-subtitle {
        color: #94A3B8;
        font-size: 0.88rem;
        margin-top: 2px;
        font-weight: 400;
    }

    /* Flat Enterprise Status Banner */
    .status-banner {
        background-color: #151E2E;
        border: 1px solid #26334D;
        border-radius: 8px;
        padding: 18px 22px;
        margin-bottom: 20px;
    }

    .status-banner.clean {
        border-left: 4px solid #10B981;
    }

    .status-banner.alert {
        border-left: 4px solid #F43F5E;
    }

    .status-banner.paused {
        border-left: 4px solid #64748B;
    }

    .status-headline {
        font-size: 1.05rem;
        font-weight: 600;
        letter-spacing: -0.01em;
        margin-bottom: 4px;
        display: flex;
        align-items: center;
    }

    .status-subtext {
        color: #94A3B8;
        font-size: 0.88rem;
        line-height: 1.5;
    }

    /* Flat Enterprise Metric Cards */
    .stat-card {
        background-color: #151E2E;
        border: 1px solid #26334D;
        border-radius: 8px;
        padding: 16px 20px;
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }

    .stat-label {
        color: #94A3B8;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 8px;
    }

    .stat-value {
        font-size: 1.5rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        font-variant-numeric: tabular-nums;
        line-height: 1.2;
    }

    .stat-sublabel {
        font-size: 0.82rem;
        color: #94A3B8;
        margin-top: 6px;
    }

    /* Bordered Container (Controls Card & Surfaces) */
    [data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #151E2E !important;
        border: 1px solid #26334D !important;
        border-radius: 8px !important;
        padding: 16px 20px !important;
    }

    /* Segmented Pill View Switcher */
    div[data-testid="stRadio"] > div[role="radiogroup"] {
        background-color: #151E2E !important;
        border: 1px solid #26334D !important;
        border-radius: 6px !important;
        padding: 3px !important;
        gap: 4px !important;
    }

    div[data-testid="stRadio"] label {
        background: transparent !important;
        border-radius: 4px !important;
        padding: 5px 14px !important;
        color: #94A3B8 !important;
        font-weight: 500 !important;
        font-size: 0.84rem !important;
        cursor: pointer !important;
    }

    div[data-testid="stRadio"] label[data-checked="true"],
    div[data-testid="stRadio"] label:has(input:checked) {
        background: #1E293B !important;
        color: #F1F5F9 !important;
        border: 1px solid #334155 !important;
    }

    /* Sliding Command Taskbar (Forensic View Dock) */
    .sliding-taskbar {
        background: #151E2E;
        border: 1px solid #26334D;
        border-radius: 8px;
        padding: 12px 18px;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    /* Flat Buttons */
    button[kind="primary"] {
        background-color: #0284C7 !important;
        border: 1px solid #0369A1 !important;
        border-radius: 6px !important;
        color: #FFFFFF !important;
        font-weight: 500 !important;
        font-size: 0.86rem !important;
        letter-spacing: 0 !important;
        box-shadow: none !important;
        transition: background-color 0.15s ease !important;
    }

    button[kind="primary"]:hover {
        background-color: #0369A1 !important;
        border-color: #075985 !important;
    }

    button[kind="secondary"] {
        background-color: #1E293B !important;
        border: 1px solid #334155 !important;
        border-radius: 6px !important;
        color: #F1F5F9 !important;
        font-weight: 500 !important;
        font-size: 0.86rem !important;
        transition: background-color 0.15s ease !important;
    }

    button[kind="secondary"]:hover {
        background-color: #334155 !important;
        border-color: #475569 !important;
        color: #FFFFFF !important;
    }

    /* Flat Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #0F172A !important;
        border: 1px solid #1E293B !important;
        border-radius: 6px !important;
        padding: 4px !important;
        gap: 4px !important;
        margin-bottom: 20px !important;
    }

    .stTabs [data-baseweb="tab"] {
        background: transparent !important;
        color: #94A3B8 !important;
        border-radius: 4px !important;
        font-weight: 500 !important;
        font-size: 0.85rem !important;
        padding: 7px 16px !important;
        border: none !important;
    }

    .stTabs [aria-selected="true"] {
        background: #1E293B !important;
        color: #38BDF8 !important;
        border: 1px solid #334155 !important;
    }

    /* Metrics & Dataframes */
    [data-testid="stMetric"] {
        background-color: #151E2E !important;
        border: 1px solid #26334D !important;
        border-radius: 8px !important;
        padding: 14px 18px !important;
    }

    [data-testid="stMetricLabel"] {
        color: #94A3B8 !important;
        font-size: 0.78rem !important;
        font-weight: 500 !important;
    }

    [data-testid="stMetricValue"] {
        color: #F1F5F9 !important;
        font-weight: 600 !important;
        font-variant-numeric: tabular-nums;
    }

    [data-testid="stDataFrame"] {
        background-color: #151E2E !important;
        border: 1px solid #26334D !important;
        border-radius: 8px !important;
        overflow: hidden !important;
    }

    /* Custom Scrollbars */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: #0B0F19;
    }
    ::-webkit-scrollbar-thumb {
        background: #334155;
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #475569;
    }
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# Session State Initialization (Persistent Across Views)
# -------------------------------------------------------------
if "detector" not in st.session_state:
    st.session_state.detector = IsolationForestDetector()
    st.session_state.detector.initialize_benign_baseline(num_samples=300)
if "alert_mgr" not in st.session_state:
    st.session_state.alert_mgr = AlertQueueManager()
if "last_flow" not in st.session_state:
    st.session_state.last_flow = None
if "last_score" not in st.session_state:
    st.session_state.last_score = None
if "last_path" not in st.session_state:
    st.session_state.last_path = None
if "last_lat" not in st.session_state:
    st.session_state.last_lat = None
if "last_ano" not in st.session_state:
    st.session_state.last_ano = None
if "last_cat" not in st.session_state:
    st.session_state.last_cat = None
if "live_mode" not in st.session_state:
    st.session_state.live_mode = True
if "live_history" not in st.session_state:
    st.session_state.live_history = []
if "total_scans" not in st.session_state:
    st.session_state.total_scans = 0
if "total_alerts" not in st.session_state:
    st.session_state.total_alerts = 0
if "total_cycles" not in st.session_state:
    st.session_state.total_cycles = 0
if "latest_scan_flows" not in st.session_state:
    st.session_state.latest_scan_flows = {}
if "sniffer" not in st.session_state:
    st.session_state.sniffer = LivePacketSniffer()
if "threat_incident_log" not in st.session_state:
    st.session_state.threat_incident_log = []
if "scan_interval" not in st.session_state:
    st.session_state.scan_interval = 5
if "scan_window" not in st.session_state:
    st.session_state.scan_window = st.session_state.scan_interval
if "ingestion_mode" not in st.session_state:
    st.session_state.ingestion_mode = "Simulation (5 Attack Profiles)"
if "sniffer_active" not in st.session_state:
    st.session_state.sniffer_active = True
if "app_view_mode" not in st.session_state:
    st.session_state.app_view_mode = "Overview"
elif st.session_state.app_view_mode in ["Simple Overview", "Overview"]:
    st.session_state.app_view_mode = "Overview"
elif st.session_state.app_view_mode in ["Forensic / Expert Mode", "Advanced Forensic"]:
    st.session_state.app_view_mode = "Advanced Forensic"
if "whitelist_trusted" not in st.session_state:
    st.session_state.whitelist_trusted = True
if "trusted_providers" not in st.session_state:
    st.session_state.trusted_providers = [
        "Google & YouTube",
        "WhatsApp & Meta",
        "Cloudflare CDN",
        "Microsoft & Teams",
        "Apple Services",
        "Amazon AWS"
    ]
if "hide_trusted" not in st.session_state:
    st.session_state.hide_trusted = False

detector: IsolationForestDetector = st.session_state.detector
alert_mgr: AlertQueueManager = st.session_state.alert_mgr
sniffer: LivePacketSniffer = st.session_state.sniffer

# -------------------------------------------------------------
# Incident Queue Purge & Reset Function
# -------------------------------------------------------------
def purge_incident_queue():
    """
    Purges all false-positive entries from vanguard_incident_queue.json,
    the alert manager, and persistent disk storage so the incident log starts fresh.
    """
    # 1. Clear alert manager in-memory & disk
    alert_mgr.clear()

    # 2. Reset session state incident records and counters
    st.session_state.threat_incident_log = []
    st.session_state.total_alerts = 0
    if "latest_scan_flows" in st.session_state:
        for fk in st.session_state.latest_scan_flows:
            st.session_state.latest_scan_flows[fk]["is_ano"] = False

    # 3. Purge disk files
    queue_paths = [
        DEFAULT_CONFIG.alert_queue_path,
        os.path.join(DEFAULT_CONFIG.project_root, "vanguard_incident_queue.json"),
        os.path.join(os.path.abspath(os.path.dirname(__file__)), "vanguard_incident_queue.json"),
        os.path.join(DEFAULT_CONFIG.project_root, "alerts", "vanguard_incident_queue.json"),
    ]
    for qp in queue_paths:
        try:
            if os.path.exists(qp):
                with open(qp, "w", encoding="utf-8") as f:
                    json.dump([], f, indent=2)
        except Exception:
            pass

    # Ensure empty file exists at vanguard_incident_queue.json in project root
    try:
        root_vanguard_path = os.path.join(DEFAULT_CONFIG.project_root, "vanguard_incident_queue.json")
        with open(root_vanguard_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
    except Exception:
        pass

# -------------------------------------------------------------
# Top-Level Brand Header & Dual-View Switcher
# -------------------------------------------------------------
col_brand, col_switch = st.columns([3.2, 2.3])
with col_brand:
    st.markdown("""
    <div style="display:flex; align-items:center; margin-bottom: 8px;">
        <div>
            <div style="display:flex; align-items:center;">
                <span class="brand-title">VanGuard</span>
                <span class="brand-pill">Network Defense</span>
            </div>
            <div class="brand-subtitle">Network Security Monitor</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_switch:
    st.write("")
    is_overview_selected = st.session_state.app_view_mode in ["Overview", "Simple Overview"]
    selected_view = st.radio(
        "Interface View",
        options=["Overview", "Advanced Forensic"],
        index=0 if is_overview_selected else 1,
        horizontal=True,
        label_visibility="collapsed",
        key="view_pill_toggle"
    )
    st.session_state.app_view_mode = selected_view

# -------------------------------------------------------------
# Unified Sidebar (Adapts Cleanly to Active View)
# -------------------------------------------------------------
is_expert = (st.session_state.app_view_mode == "Advanced Forensic")

if not is_expert:
    # Minimal Enterprise Sidebar for Overview
    st.sidebar.markdown("""
    <div style="padding:10px 0 16px 0;">
        <div style="font-weight:700; color:#F1F5F9; font-size:1.05rem;">VanGuard System Control</div>
        <div style="display:flex; align-items:center; margin-top:4px;">
            <span class="status-dot dot-emerald"></span>
            <span style="color:#10B981; font-size:0.8rem; font-weight:600; text-transform:uppercase; letter-spacing:0.04em;">Live Inspection: Active</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.sidebar.divider()
    st.sidebar.markdown("**Inspection Mode:** `Live Inspection: Active`")
    st.sidebar.markdown("**Network Engine:** `Packet Inspection (TCP/UDP)`")
    st.sidebar.markdown("**Detection Engine:** `Isolation Forest`")
    st.sidebar.divider()
    st.sidebar.subheader("Scan Timing")
    scan_window = st.sidebar.slider(
        "Scan Window Timing",
        min_value=3,
        max_value=10,
        value=int(st.session_state.get("scan_window", 5)),
        step=1,
        format="%d s",
        key="scan_window_slider_simple",
        help="Time window in seconds between automatic surveillance scans and sliding-window flow evaluation."
    )
    st.session_state.scan_window = scan_window
    st.session_state.scan_interval = scan_window
    DEFAULT_CONFIG.flow.window_duration_sec = float(scan_window)

    st.sidebar.divider()
    if st.sidebar.button("Purge False Positives & Reset Queue", key="sb_purge_simple", use_container_width=True, help="Purges recorded incident history and resets triage state."):
        purge_incident_queue()
        st.toast("Incident records purged successfully.")
        st.rerun()
    st.sidebar.caption("Note: Switch to Advanced Forensic view at the top right to inspect raw network sockets, model partitions, or comparative benchmarks.")
else:
    # Enterprise Sidebar for Advanced Forensic
    st.sidebar.markdown("""
    <div style="margin-bottom:12px;">
        <div style="font-weight:700; color:#F1F5F9; font-size:1.05rem;">Forensic Console</div>
        <div style="color:#38BDF8; font-size:0.75rem; font-weight:600; text-transform:uppercase; letter-spacing:0.04em;">Diagnostic Mode</div>
    </div>
    """, unsafe_allow_html=True)

    st.sidebar.divider()
    st.sidebar.subheader("Ingestion Pipeline")
    ingestion_mode = st.sidebar.radio(
        "Data Source",
        options=[
            "Simulation (5 Attack Profiles)",
            "Live Network Sniffer (Wi-Fi / Ethernet)"
        ],
        index=0 if st.session_state.ingestion_mode == "Simulation (5 Attack Profiles)" else 1,
        help="Select whether to ingest simulated attack traffic or live wire packets from your network interface."
    )
    st.session_state.ingestion_mode = ingestion_mode

    st.sidebar.divider()
    st.sidebar.subheader("Detection Sensitivity")
    threshold = st.sidebar.slider(
        "Decision Boundary",
        min_value=0.50,
        max_value=0.90,
        value=float(detector.config.anomaly_threshold),
        step=0.05,
        help="Scores exceeding this threshold trigger security incident staging."
    )
    detector.config.anomaly_threshold = threshold

    st.sidebar.divider()
    st.sidebar.subheader("Scan Timing")
    scan_window = st.sidebar.slider(
        "Scan Window Timing",
        min_value=3,
        max_value=10,
        value=int(st.session_state.get("scan_window", 5)),
        step=1,
        format="%d s",
        key="scan_window_slider_expert",
        help="Time window in seconds between automatic surveillance scans and sliding-window flow evaluation."
    )
    st.session_state.scan_window = scan_window
    st.session_state.scan_interval = scan_window
    DEFAULT_CONFIG.flow.window_duration_sec = float(scan_window)

    st.sidebar.markdown(f"**Sliding Window ($\\Delta t$):** `{scan_window}s`")
    st.sidebar.markdown(f"**Forest Estimators ($n$):** `{detector.config.n_estimators}`")
    st.sidebar.markdown(f"**Contamination Factor:** `{detector.config.contamination}`")

    st.sidebar.divider()
    st.sidebar.subheader("Trusted Network Whitelist")
    st.sidebar.caption("Exclude verified trusted CDNs and cloud infrastructure from alerts:")

    st.session_state.whitelist_trusted = st.sidebar.toggle(
        "Whitelist Trusted Sources",
        value=st.session_state.whitelist_trusted,
        help="When enabled, traffic to/from verified trusted services (e.g., Google, YouTube, WhatsApp, Cloudflare) is automatically verified clean."
    )

    if st.session_state.whitelist_trusted:
        st.session_state.trusted_providers = st.sidebar.multiselect(
            "Active Whitelist Providers:",
            options=list(GLOBAL_RESOLVER.TRUSTED_PROVIDER_GROUPS.keys()),
            default=st.session_state.trusted_providers,
            help="Select which external services should be exempted from anomaly alerts."
        )
        st.session_state.hide_trusted = st.sidebar.checkbox(
            "Hide trusted flows from active table",
            value=st.session_state.hide_trusted,
            help="Check this to hide trusted flows entirely from the Active Network Traffic matrix."
        )

    st.sidebar.divider()
    if st.sidebar.button("Purge False Positives & Reset Queue", key="sb_purge_expert", use_container_width=True, help="Purges recorded incident history and resets triage state."):
        purge_incident_queue()
        st.toast("Incident records purged successfully.")
        st.rerun()

# Effective settings
scan_window = int(st.session_state.get("scan_window", 5))
scan_interval = scan_window
whitelist_trusted = st.session_state.whitelist_trusted
trusted_providers = st.session_state.trusted_providers
hide_trusted = st.session_state.hide_trusted

# -------------------------------------------------------------
# Core Autonomous Ingestion & Scoring Engine
# -------------------------------------------------------------
def execute_surveillance_cycle():
    """
    Executes a single perception & scoring cycle across either Simulation or Live Wire Sniffer.
    Updates st.session_state.latest_scan_flows, live_history, threat_incident_log, and counters.
    """
    mode = st.session_state.ingestion_mode
    is_active = st.session_state.sniffer_active if mode == "Live Network Sniffer (Wi-Fi / Ethernet)" else st.session_state.live_mode

    if mode == "Simulation (5 Attack Profiles)":
        current_scan_results = []
        cycle_alerts = 0
        vector_scores = {}
        sim_cycle_dict = {}

        for cat in AttackCategory:
            flow = TrafficGenerator.generate_flow(cat)
            is_local_infra = GLOBAL_RESOLVER.is_local_infrastructure_flow(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port)
            if is_local_infra:
                is_ano = False
                score = 0.08
                path_len = 9.2
                lat = 0.02
                is_trusted_flow = True
            else:
                is_ano, score, path_len, lat = detector.predict_flow(flow)

                # Check trusted source whitelist policy
                is_trusted_flow = False
                if whitelist_trusted and GLOBAL_RESOLVER.is_flow_trusted(flow.src_ip, flow.dst_ip, trusted_providers, flow.src_port, flow.dst_port):
                    is_trusted_flow = True
                    is_ano = False
                    score = min(score, 0.18)

            if is_ano:
                cycle_alerts += 1
                alert_mgr.enqueue_alert(flow, score, path_len, lat)

                clean_endpoints = GLOBAL_RESOLVER.format_connection(flow.src_ip, flow.dst_ip)
                if flow.dst_port:
                    clean_endpoints += f":{flow.dst_port}"

                dest_svc = GLOBAL_RESOLVER.resolve_ip(flow.dst_ip)
                threat_type = cat.value.split(" (")[0]
                if dest_svc:
                    threat_type += f" ({dest_svc})"

                threat_entry = {
                    "Time": datetime.now().strftime("%H:%M:%S"),
                    "Threat Type": threat_type,
                    "Connection": clean_endpoints,
                    "Risk Level": "Critical" if score >= 0.8 else "High" if score >= 0.7 else "Moderate",
                    "Threat Score": f"{score:.2f}",
                    "Action Taken": "Alert Logged"
                }
                if not any(
                    t.get("Connection") == clean_endpoints and 
                    t.get("Threat Type") == threat_entry["Threat Type"] and 
                    t.get("Time") == threat_entry["Time"]
                    for t in st.session_state.threat_incident_log[:10]
                ):
                    st.session_state.threat_incident_log.insert(0, threat_entry)
                    if len(st.session_state.threat_incident_log) > 40:
                        st.session_state.threat_incident_log.pop()

            result_entry = {
                "category": cat.value,
                "category_short": cat.value.split(" (")[0],
                "category_key": cat.name,
                "flow": flow,
                "flow_id": flow.flow_id,
                "endpoints": f"{GLOBAL_RESOLVER.format_endpoint(flow.src_ip, flow.src_port)} <-> {GLOBAL_RESOLVER.format_endpoint(flow.dst_ip, flow.dst_port)}",
                "score": round(score, 4),
                "path_len": round(path_len, 2),
                "latency_ms": round(lat, 3),
                "is_ano": is_ano,
                "is_trusted": is_trusted_flow,
                "is_local_infra": is_local_infra,
                "packets": flow.packet_count,
                "bytes": flow.byte_count,
                "duration": f"{flow.duration:.2f}s"
            }
            current_scan_results.append(result_entry)
            sim_cycle_dict[cat.value] = result_entry
            vector_scores[cat.name] = round(score, 4)

        st.session_state.latest_scan_flows = sim_cycle_dict
        st.session_state.total_cycles += 1
        st.session_state.total_scans += len(AttackCategory)
        st.session_state.total_alerts += cycle_alerts

        severe_flow = max(current_scan_results, key=lambda x: x["score"])
        st.session_state.last_flow = severe_flow["flow"]
        st.session_state.last_score = severe_flow["score"]
        st.session_state.last_path = severe_flow["path_len"]
        st.session_state.last_lat = severe_flow["latency_ms"]
        st.session_state.last_ano = severe_flow["is_ano"]

        now_ts = datetime.now().strftime("%H:%M:%S")
        timeline_point = {
            "time": now_ts,
            "Benign HTTPS": vector_scores.get("BENIGN", 0.2),
            "Port Scan (T1046)": vector_scores.get("PORT_SCAN", 0.8),
            "SYN Flood (T1498)": vector_scores.get("SYN_FLOOD", 0.8),
            "Exfiltration (T1041)": vector_scores.get("EXFILTRATION", 0.8),
            "Stealth C2 (T1071)": vector_scores.get("STEALTH_C2", 0.65),
            "Threshold Baseline": detector.config.anomaly_threshold
        }
        st.session_state.live_history.append(timeline_point)
        if len(st.session_state.live_history) > 20:
            st.session_state.live_history.pop(0)

    elif mode == "Live Network Sniffer (Wi-Fi / Ethernet)":
        chosen_iface = st.session_state.get("chosen_iface")
        if not sniffer.is_running and is_active:
            sniffer.start_capture(chosen_iface)

        real_flows = sniffer.flush_real_flows(force_all=True)
        cycle_alerts = 0
        current_cycle_dict = {}

        if real_flows:
            for f in real_flows:
                # 1. Local Protocol & Multicast Fast-Path Sanitization
                # Ignore dst_ip in ['239.255.255.250', '224.0.0.251', '224.0.0.252', '224.0.0.2', 'ff02::fb', 'ff02::16']
                # Ignore dst_port or src_port in [1900 (SSDP), 5353 (mDNS), 137 (NetBIOS-NS), 53 (DNS to local gateway)]
                is_local_infra = GLOBAL_RESOLVER.is_local_infrastructure_flow(f.src_ip, f.dst_ip, f.src_port, f.dst_port)
                if is_local_infra:
                    is_ano = False
                    score = 0.05
                    path_len = 9.5
                    lat = 0.015
                    is_trusted_flow = True
                else:
                    is_ano, score, path_len, lat = detector.predict_flow(f)

                    # 2. Check trusted source whitelist policy
                    is_trusted_flow = False
                    if whitelist_trusted and GLOBAL_RESOLVER.is_flow_trusted(f.src_ip, f.dst_ip, trusted_providers, f.src_port, f.dst_port):
                        is_trusted_flow = True
                        is_ano = False
                        score = min(score, 0.18)

                if is_ano:
                    cycle_alerts += 1
                    alert_mgr.enqueue_alert(f, score, path_len, lat)

                    clean_endpoints = GLOBAL_RESOLVER.format_connection(f.src_ip, f.dst_ip)
                    if f.dst_port:
                        clean_endpoints += f":{f.dst_port}"

                    dest_svc = GLOBAL_RESOLVER.resolve_ip(f.dst_ip)
                    threat_name = f"Suspicious {f.protocol} ({dest_svc})" if dest_svc else f"Suspicious {f.protocol} Flow"

                    threat_entry = {
                        "Time": datetime.now().strftime("%H:%M:%S"),
                        "Threat Type": threat_name,
                        "Connection": clean_endpoints,
                        "Risk Level": "Critical" if score >= 0.8 else "High" if score >= 0.7 else "Moderate",
                        "Threat Score": f"{score:.2f}",
                        "Action Taken": "Alert Logged"
                    }
                    if not any(
                        t.get("Connection") == clean_endpoints and 
                        t.get("Threat Type") == threat_entry["Threat Type"] and 
                        t.get("Time") == threat_entry["Time"]
                        for t in st.session_state.threat_incident_log[:10]
                    ):
                        st.session_state.threat_incident_log.insert(0, threat_entry)
                        if len(st.session_state.threat_incident_log) > 40:
                            st.session_state.threat_incident_log.pop()

                live_dest = GLOBAL_RESOLVER.resolve_ip(f.dst_ip)
                if is_local_infra:
                    category_label = f"Verified Local Infrastructure ({live_dest})" if live_dest else "Verified Local Infrastructure"
                    category_short = "Local Infra"
                elif live_dest:
                    category_label = f"Live {f.protocol} ({live_dest})"
                    category_short = f.protocol
                else:
                    category_label = f"Live {f.protocol}"
                    category_short = f.protocol

                entry = {
                    "category": category_label,
                    "category_short": category_short,
                    "flow": f,
                    "flow_id": f.flow_id,
                    "endpoints": f"{GLOBAL_RESOLVER.format_endpoint(f.src_ip, f.src_port)} <-> {GLOBAL_RESOLVER.format_endpoint(f.dst_ip, f.dst_port)}",
                    "score": round(score, 4),
                    "path_len": round(path_len, 2),
                    "latency_ms": round(lat, 3),
                    "is_ano": is_ano,
                    "is_trusted": is_trusted_flow,
                    "is_local_infra": is_local_infra,
                    "packets": f.packet_count,
                    "bytes": f.byte_count,
                    "duration": f"{f.duration:.2f}s"
                }
                current_cycle_dict[f.flow_id] = entry

            st.session_state.latest_scan_flows = current_cycle_dict
            st.session_state.total_cycles += 1
            st.session_state.total_scans += len(real_flows)
            st.session_state.total_alerts += cycle_alerts

            severe_flow = max(current_cycle_dict.values(), key=lambda x: x["score"])
            st.session_state.last_flow = severe_flow["flow"]
            st.session_state.last_score = severe_flow["score"]
            st.session_state.last_path = severe_flow["path_len"]
            st.session_state.last_lat = severe_flow["latency_ms"]
            st.session_state.last_ano = severe_flow["is_ano"]

            now_ts = datetime.now().strftime("%H:%M:%S")
            timeline_point = {
                "time": now_ts,
                "Peak Wire Flow": severe_flow["score"],
                "Mean Wire Ingestion": float(np.mean([e["score"] for e in current_cycle_dict.values()])),
                "Threshold Baseline": detector.config.anomaly_threshold
            }
            st.session_state.live_history.append(timeline_point)
            if len(st.session_state.live_history) > 20:
                st.session_state.live_history.pop(0)

# -------------------------------------------------------------
# Formatting Helpers for Tables
# -------------------------------------------------------------
def format_simplified_flows(flow_entries, filter_trusted_hidden: bool = False):
    rows = []
    for r in flow_entries:
        flow = r["flow"]
        score = float(r["score"])
        cat = r.get("category", "")
        is_tr = r.get("is_trusted", False)

        if filter_trusted_hidden and is_tr:
            continue

        dest_svc = GLOBAL_RESOLVER.resolve_ip(flow.dst_ip)
        is_local = r.get("is_local_infra", False)
        if "Benign" in cat:
            activity = f"Web & Stream ({dest_svc})" if dest_svc else "Web & Media Stream (HTTPS)"
        elif is_local or "Local Infra" in cat:
            activity = f"Local Network Infrastructure ({dest_svc})" if dest_svc else "Verified Local Infrastructure"
        elif "Port Scan" in cat or "T1046" in cat:
            activity = f"Port Recon Probe ({dest_svc})" if dest_svc else "Port Reconnaissance Probe"
        elif "SYN Flood" in cat or "T1498" in cat:
            activity = f"SYN Denial of Service ({dest_svc})" if dest_svc else "Volumetric SYN Denial of Service"
        elif "Exfiltration" in cat or "T1041" in cat:
            activity = f"Data Exfiltration ({dest_svc})" if dest_svc else "High-Volume Data Exfiltration"
        elif "Stealth" in cat or "T1071" in cat:
            activity = f"C2 Beaconing ({dest_svc})" if dest_svc else "Stealthy C2 Command Beaconing"
        elif "Live" in cat:
            activity = f"Live {flow.protocol} ({dest_svc})" if dest_svc else f"Live {flow.protocol} Traffic"
        else:
            base_cat = cat.split(" (")[0]
            activity = f"{base_cat} ({dest_svc})" if dest_svc else base_cat

        endpoints = GLOBAL_RESOLVER.format_connection(flow.src_ip, flow.dst_ip)

        if is_local:
            risk = "Local Infrastructure"
            status = "Verified Clean"
        elif is_tr:
            risk = "Whitelisted"
            status = "Verified Clean"
        elif score >= 0.75:
            risk = "Critical Risk"
            status = "Alert Flagged"
        elif score >= 0.65:
            risk = "Suspicious"
            status = "Alert Flagged"
        else:
            risk = "Normal"
            status = "Verified Clean"

        rows.append({
            "Activity": activity,
            "Endpoints (From → To)": endpoints,
            "Risk Assessment": risk,
            "Security Status": status
        })
    return rows

def render_threat_log_section(key_prefix: str = "expert"):
    st.markdown("### Flagged Incident Records")
    st.caption("Chronological log of suspicious or anomalous network events detected on this system:")

    # Purge whitelisted or local infrastructure false positives
    if st.session_state.threat_incident_log:
        st.session_state.threat_incident_log = [
            t for t in st.session_state.threat_incident_log
            if not any(
                kw in t.get("Threat Type", "").lower() or kw in t.get("Connection", "").lower()
                for kw in [
                    "google", "youtube", "whatsapp", "cloudflare", "microsoft", "apple", "amazon",
                    "ssdp", "mdns", "239.255.255.250", "224.0.0.251", "224.0.0.252", "224.0.0.2",
                    "ff02::fb", "ff02::16", ":137", ":5353", ":1900", "multicast", "local infrastructure"
                ]
            )
        ]

    if st.session_state.threat_incident_log:
        col_lh, col_lc, col_lp = st.columns([3.5, 1.2, 1.3])
        with col_lh:
            st.markdown(f"**Total Incidents Logged:** `{len(st.session_state.threat_incident_log)}` (Newest first)")
        with col_lc:
            if st.button("Clear Log", key=f"clear_threat_log_{key_prefix}", use_container_width=True):
                purge_incident_queue()
                st.rerun()
        with col_lp:
            if st.button("Purge False Positives", key=f"purge_threat_log_{key_prefix}", type="secondary", use_container_width=True):
                purge_incident_queue()
                st.toast("Purged false positives and reset incident queue.")
                st.rerun()

        df_threats = pd.DataFrame(st.session_state.threat_incident_log)
        if "Value" in df_threats.columns:
            df_threats["Value"] = df_threats["Value"].astype(str)
        st.dataframe(df_threats, hide_index=True, width="stretch")
    else:
        st.markdown("""
        <div style="background:#151E2E; border:1px solid #26334D; border-left:4px solid #10B981; border-radius:6px; padding:12px 16px; margin-bottom:12px; display:flex; align-items:center;">
            <span class="status-dot dot-emerald"></span>
            <span style="color:#94A3B8; font-size:0.88rem;">All monitored network traffic is normal. No active security incidents detected.</span>
        </div>
        """, unsafe_allow_html=True)


def translate_threat_name(raw_name: str) -> str:
    """Translates technical attack descriptors into human-readable plain English."""
    n = raw_name.lower()
    if "exfiltration" in n:
        return "High volume of data sent to an unknown server"
    elif "port scan" in n or "recon" in n or "probe" in n:
        return "An external address probed your connection"
    elif "syn flood" in n or "denial of service" in n or "flood" in n:
        return "Excessive connection attempts overwhelming your network"
    elif "dns tunnel" in n:
        return "Hidden data transfer disguised as domain lookups"
    elif "beacon" in n or "c2" in n or "botnet" in n:
        return "Repeated automated check-ins with an external server"
    elif "tcp" in n:
        return "Unusual high-frequency data exchange detected"
    elif "udp" in n:
        return "Unusual streaming or burst traffic detected"
    elif "icmp" in n:
        return "Unusual ping or network diagnostic requests detected"
    else:
        return "Unusual traffic pattern exceeding normal baseline behavior"


def format_simple_parties(conn_str: str) -> tuple[str, str]:
    """Extracts human-friendly source and destination labels from connection strings."""
    if not conn_str:
        return ("Local Device", "External Host")
    separator = " -> " if " -> " in conn_str else (" <-> " if " <-> " in conn_str else None)
    if not separator:
        return ("Local Device", f"External Host ({conn_str})")

    parts = conn_str.split(separator, 1)
    src_raw, dst_raw = parts[0].strip(), parts[1].strip()

    # Clean source
    src_ip = src_raw.split(":")[0].strip()
    if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172.") or src_ip == "127.0.0.1":
        source_label = "Local Device"
    else:
        source_label = f"External Host ({src_ip})"

    # Clean destination
    dst_cleaned = dst_raw
    if ":" in dst_cleaned and not dst_cleaned.endswith(")"):
        dst_cleaned = dst_cleaned.rsplit(":", 1)[0]

    if any(k in dst_cleaned for k in ["Google", "YouTube", "Meta", "WhatsApp", "Microsoft", "Apple", "Cloudflare", "Amazon"]):
        dest_label = dst_cleaned
    elif dst_cleaned.startswith("192.168.") or dst_cleaned.startswith("10.") or dst_cleaned.startswith("127.0.0.1"):
        dest_label = "Local Network Device"
    else:
        dest_label = f"External Host ({dst_cleaned})"

    return (source_label, dest_label)


# =============================================================
# VIEW 1: OVERVIEW (Enterprise Security Dashboard)
# =============================================================
if not is_expert:
    is_running = st.session_state.sniffer_active if st.session_state.ingestion_mode == "Live Network Sniffer (Wi-Fi / Ethernet)" else st.session_state.live_mode
    scan_window = int(st.session_state.get("scan_window", 5))

    @st.fragment(run_every=scan_window if is_running else None)
    def render_simple_overview_dynamic():
        # Execute automated surveillance cycle
        if is_running or (len(st.session_state.latest_scan_flows) == 0):
            execute_surveillance_cycle()

        latest_results = list(st.session_state.latest_scan_flows.values())
        threats_count = sum(1 for r in latest_results if r.get("is_ano", False))
        active_flows_count = len(latest_results)
        avg_lat = float(np.mean([r["latency_ms"] for r in latest_results])) if latest_results else 0.42
        has_incidents = (threats_count > 0) or (len(st.session_state.threat_incident_log) > 0)

        # 1. Status Banner (Flat status bar with 4px left-accent border)
        if not is_running:
            st.markdown("""
            <div class="status-banner paused">
                <div class="status-headline" style="color:#94A3B8;">
                    <span class="status-dot dot-slate"></span>System Status: Monitoring Paused
                </div>
                <div class="status-subtext">Packet screening is suspended. Click Resume Inspection below to activate defense.</div>
            </div>
            """, unsafe_allow_html=True)
        elif has_incidents:
            if st.session_state.threat_incident_log:
                top_incident = st.session_state.threat_incident_log[0]
                raw_threat_type = top_incident.get("Threat Type", "Unusual Traffic Burst")
                conn_raw = top_incident.get("Connection", "")
            else:
                ano_f = next((r for r in latest_results if r.get("is_ano", False)), {})
                raw_threat_type = ano_f.get("category", "Unusual Traffic Burst")
                conn_raw = ano_f.get("endpoints", "")

            friendly_threat = translate_threat_name(raw_threat_type)
            src_label, dst_label = format_simple_parties(conn_raw)

            st.markdown(f"""
            <div class="status-banner alert">
                <div class="status-headline" style="color:#F43F5E;">
                    <span class="status-dot dot-crimson"></span>Alert: Unusual Traffic Detected
                </div>
                <div class="status-subtext" style="margin-top:6px;">
                    <div><b>Event Summary:</b> {friendly_threat} (Indicator: <code>{html.escape(raw_threat_type)}</code>)</div>
                    <div style="margin-top:3px;"><b>Endpoints:</b> Source: {html.escape(src_label)} &nbsp;|&nbsp; Target Host: {html.escape(dst_label)} &nbsp;|&nbsp; Posture: Monitored & Alerted</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            col_btn1, col_btn2 = st.columns([1, 1])
            with col_btn1:
                if st.button("View Forensic Log", key="simple_view_expert_btn", type="primary", use_container_width=True):
                    st.session_state.app_view_mode = "Advanced Forensic"
                    st.session_state.view_pill_toggle = "Advanced Forensic"
                    st.session_state.expert_active_tab = "Incident Queue"
                    st.rerun()
            with col_btn2:
                if st.button("Dismiss / Purge", key="simple_dismiss_btn", type="secondary", use_container_width=True):
                    purge_incident_queue()
                    st.toast("Alert dismissed & incident queue purged.")
                    st.rerun()

            st.write("")
        else:
            st.markdown("""
            <div class="status-banner clean">
                <div class="status-headline" style="color:#10B981;">
                    <span class="status-dot dot-emerald"></span>System Status: Protected
                </div>
                <div class="status-subtext">Network traffic is normal across active interfaces.</div>
            </div>
            """, unsafe_allow_html=True)

        # 2. Stat Row (3 cleanly aligned cards with equal height, clear numbers, muted sub-labels)
        c_m1, c_m2, c_m3 = st.columns(3)
        with c_m1:
            if not is_running:
                stat1_val = "Paused"
                stat1_color = "#94A3B8"
                stat1_sub = "Monitoring Suspended"
            elif has_incidents:
                stat1_val = "Alert: Flagged"
                stat1_color = "#F43F5E"
                stat1_sub = "Review incident log"
            else:
                stat1_val = "Active & Inspected"
                stat1_color = "#10B981"
                stat1_sub = f"{active_flows_count} Active Flows"

            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-label">Network Status</div>
                <div class="stat-value" style="color:{stat1_color};">{stat1_val}</div>
                <div class="stat-sublabel">{stat1_sub}</div>
            </div>
            """, unsafe_allow_html=True)

        with c_m2:
            threat_color = "#10B981" if not has_incidents else "#F43F5E"
            display_threats = len(st.session_state.threat_incident_log) or threats_count
            threat_sub = "Trusted Whitelist Active" if st.session_state.whitelist_trusted else "Full Spectrum Inspection"
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-label">Threats Flagged</div>
                <div class="stat-value" style="color:{threat_color};">{display_threats} Threats</div>
                <div class="stat-sublabel">{threat_sub}</div>
            </div>
            """, unsafe_allow_html=True)

        with c_m3:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-label">Processing Latency</div>
                <div class="stat-value" style="color:#38BDF8;">{avg_lat:.2f} ms</div>
                <div class="stat-sublabel">Line-Rate Target &lt; 1.0 ms</div>
            </div>
            """, unsafe_allow_html=True)

        # Active Threat Incident Log if incidents exist
        if has_incidents and st.session_state.threat_incident_log:
            st.write("")
            render_threat_log_section(key_prefix="simple_overview")

    # Render dynamic fragment
    render_simple_overview_dynamic()

    # 3. Protection Controls (Unified nested container card - OUTSIDE fragment so controls are never re-rendered on timer)
    st.write("")
    with st.container(border=True):
        ctl_c1, ctl_c2, ctl_c3 = st.columns([1.1, 1.4, 1.3])

        with ctl_c1:
            st.markdown("<div class='stat-label'>Inspection State</div>", unsafe_allow_html=True)
            btn_label = "Pause Inspection" if is_running else "Resume Inspection"
            btn_kind = "secondary" if is_running else "primary"
            if st.button(btn_label, type=btn_kind, use_container_width=True, key="simple_toggle_btn"):
                new_state = not is_running
                st.session_state.sniffer_active = new_state
                st.session_state.live_mode = new_state
                if not new_state and sniffer.is_running:
                    sniffer.stop_capture()
                elif new_state and not sniffer.is_running and st.session_state.ingestion_mode == "Live Network Sniffer (Wi-Fi / Ethernet)":
                    sniffer.start_capture(st.session_state.get("chosen_iface"))
                st.rerun()
            st.caption("Toggle continuous packet screening on network interfaces.")

        with ctl_c2:
            st.markdown("<div class='stat-label'>Detection Sensitivity</div>", unsafe_allow_html=True)
            cur_th = detector.config.anomaly_threshold
            default_sens = "Balanced"
            if cur_th >= 0.72:
                default_sens = "Low"
            elif cur_th <= 0.58:
                default_sens = "High"

            chosen_sens = st.select_slider(
                "Sensitivity Level",
                options=["Low", "Balanced", "High"],
                value=default_sens,
                label_visibility="collapsed",
                key="simple_sens_select",
                help="Low: Lenient threshold (0.75). Balanced: Standard baseline (0.65). High: Strict boundary (0.55)."
            )
            if chosen_sens == "Low":
                detector.config.anomaly_threshold = 0.75
            elif chosen_sens == "High":
                detector.config.anomaly_threshold = 0.55
            else:
                detector.config.anomaly_threshold = 0.65
            st.caption(f"Decision Boundary: `{detector.config.anomaly_threshold:.2f}`")

        with ctl_c3:
            st.markdown("<div class='stat-label'>Trusted Network Whitelist</div>", unsafe_allow_html=True)
            wh_on = st.toggle(
                "Bypass Verified Providers",
                value=st.session_state.whitelist_trusted,
                key="simple_wh_toggle",
                help="Exempts verified services (Google, YouTube, Meta, Microsoft, Apple, Cloudflare) from generating alerts."
            )
            st.session_state.whitelist_trusted = wh_on
            st.caption("Exempts Google, Microsoft, Meta, Apple, and Cloudflare.")


# =============================================================
# VIEW 2: ADVANCED FORENSIC (Technical Diagnostic Tabs)
# =============================================================
else:
    mode = st.session_state.ingestion_mode

    # Reset scan buffers cleanly when switching modes
    if "current_pipeline_mode" not in st.session_state:
        st.session_state.current_pipeline_mode = mode
    elif st.session_state.current_pipeline_mode != mode:
        st.session_state.current_pipeline_mode = mode
        st.session_state.latest_scan_flows = {}
        st.session_state.live_history = []
        if sniffer.is_running and mode != "Live Network Sniffer (Wi-Fi / Ethernet)":
            sniffer.stop_capture()

    # Hardware Adapter Setup (if Live Wire Sniffer)
    if mode == "Live Network Sniffer (Wi-Fi / Ethernet)":
        ifaces = LivePacketSniffer.get_network_interfaces()
        iface_map = {i["display"]: i["dev_name"] for i in ifaces}
        iface_options = list(iface_map.keys())

        col_if1, col_if2 = st.columns([3, 1])
        with col_if1:
            selected_label = st.selectbox(
                "Network Adapter Interface (Wi-Fi / Ethernet):",
                options=iface_options if iface_options else ["[Wi-Fi] Default Hardware Adapter"],
                index=0,
                key="expert_adapter_select",
                help="Select your physical network adapter to capture wire packets directly."
            )
            chosen_iface = iface_map.get(selected_label) if iface_map else None

            if "last_chosen_iface" not in st.session_state:
                st.session_state.last_chosen_iface = chosen_iface
            elif st.session_state.last_chosen_iface != chosen_iface:
                st.session_state.last_chosen_iface = chosen_iface
                st.session_state.latest_scan_flows = {}
                st.session_state.live_history = []
                sniffer.clear_buffers()
                if sniffer.is_running:
                    sniffer.stop_capture()
                    sniffer.start_capture(chosen_iface)

            st.session_state.chosen_iface = chosen_iface
            st.session_state.chosen_iface_label = selected_label
        with col_if2:
            st.write("")
            st.write("")
            force_wire_scan = st.button("Scan Wire Now", type="primary", use_container_width=True)
    else:
        chosen_iface = None
        selected_label = "Multi-Vector Simulation"
        force_wire_scan = False

    # 4 Forensic Tabs (Pure client-side tab switching without page reload)
    tab_options = [
        "Activity Timeline",
        "Flow Matrix",
        "Model Benchmarks",
        "Incident Queue"
    ]
    tab_radar, tab_detailed, tab_bench, tab_queue = st.tabs(tab_options)

    # -------------------------------------------------------------
    # TAB 1: Activity Timeline
    # -------------------------------------------------------------
    with tab_radar:
        # Taskbar Dock & Controls
        dock_c1, dock_c2, dock_c3 = st.columns([2.5, 3.5, 1.5])
        with dock_c1:
            active_state = st.session_state.sniffer_active if mode == "Live Network Sniffer (Wi-Fi / Ethernet)" else st.session_state.live_mode
            toggle_live = st.toggle(
                f"Continuous Inspection ({scan_window}s Interval)",
                value=active_state,
                key="expert_live_toggle"
            )
            if mode == "Live Network Sniffer (Wi-Fi / Ethernet)":
                st.session_state.sniffer_active = toggle_live
                if toggle_live and not sniffer.is_running:
                    sniffer.start_capture(chosen_iface)
                elif not toggle_live and not force_wire_scan and sniffer.is_running:
                    sniffer.stop_capture()
            else:
                st.session_state.live_mode = toggle_live

        with dock_c2:
            st.write("")
            st.caption(f"Inspection Mode: {mode} on `{selected_label}` (Window: {scan_window}s).")

        with dock_c3:
            st.write("")
            trigger_manual = st.button("Run Inspection Cycle", type="primary", use_container_width=True, key="expert_force_scan")

        # Live surveillance fragment
        is_stream_active = st.session_state.sniffer_active if mode == "Live Network Sniffer (Wi-Fi / Ethernet)" else st.session_state.live_mode

        @st.fragment(run_every=scan_window if is_stream_active else None)
        def render_expert_surveillance():
            should_run = is_stream_active or trigger_manual or force_wire_scan or (len(st.session_state.latest_scan_flows) == 0)
            if should_run:
                execute_surveillance_cycle()

            if not st.session_state.latest_scan_flows:
                st.info(f"Listening for network traffic on `{selected_label}`... Generate network traffic to capture flows.")
                return

            latest_results = list(st.session_state.latest_scan_flows.values())
            threats_in_cycle = sum(1 for r in latest_results if r.get("is_ano", False))
            benign_in_cycle = len(latest_results) - threats_in_cycle
            avg_cycle_lat = sum(r["latency_ms"] for r in latest_results) / max(len(latest_results), 1)

            now_str = datetime.now().strftime("%H:%M:%S")
            status_mode = f"Inspection Active ({now_str})" if is_stream_active else "Inspection Paused"
            status_dot_cls = "dot-emerald" if is_stream_active else "dot-slate"
            posture_text = "Alert Active" if threats_in_cycle > 0 else "System Normal"
            posture_color = "#F43F5E" if threats_in_cycle > 0 else "#10B981"

            # Elevated Sliding Taskbar
            st.markdown(
                f"""<div class="sliding-taskbar">
                    <div style="display:flex; align-items:center;">
                        <span class="status-dot {status_dot_cls}"></span>
                        <span style="font-weight:600; color:#F1F5F9; font-size:0.9rem;">{status_mode}</span>
                        <span style="background:#1E293B; border:1px solid #334155; padding:2px 8px; border-radius:4px; font-size:0.75rem; color:#38BDF8; font-family:'JetBrains Mono',monospace; margin-left:12px;">Cycle #{st.session_state.total_cycles}</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:20px;">
                        <div style="font-size:0.82rem; color:#94A3B8;">
                            Inferences: <b style="color:#F1F5F9; font-family:'JetBrains Mono',monospace;">{st.session_state.total_scans}</b>
                        </div>
                        <div style="font-size:0.82rem; color:#94A3B8;">
                            Incidents: <b style="color:{'#F43F5E' if st.session_state.total_alerts > 0 else '#10B981'}; font-family:'JetBrains Mono',monospace;">{st.session_state.total_alerts}</b>
                        </div>
                        <div style="font-size:0.82rem; color:#94A3B8;">
                            Status: <b style="color:{posture_color}; font-weight:600;">{posture_text}</b>
                        </div>
                    </div>
                </div>""",
                unsafe_allow_html=True
            )

            # 4 HUD Metric Cards
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Monitored Flows", f"{len(latest_results)} Active", delta="Line-Rate Telemetry", delta_color="normal")
            c2.metric("Threats Flagged", f"{threats_in_cycle} / {len(latest_results)}", delta=f"{threats_in_cycle} Flagged" if threats_in_cycle > 0 else "Zero Anomalies", delta_color="inverse" if threats_in_cycle > 0 else "normal")
            c3.metric("Filter Efficiency", f"{benign_in_cycle} Clean", delta="Whitelisted" if whitelist_trusted else "Unfiltered", delta_color="normal")
            c4.metric("Inference Speed", f"{avg_cycle_lat:.3f} ms", delta="< 1.0 ms Target", delta_color="normal" if avg_cycle_lat < 1.0 else "off")

            # Active Network Traffic Table
            st.markdown("### Active Network Traffic")
            simplified_data = format_simplified_flows(latest_results, filter_trusted_hidden=hide_trusted)
            if not simplified_data and hide_trusted:
                st.info("All active network flows belong to whitelisted trusted services (hidden by your policy filter). Untick 'Hide trusted flows' in the sidebar to view them.")
            else:
                df_active = pd.DataFrame(simplified_data)
                if "Value" in df_active.columns:
                    df_active["Value"] = df_active["Value"].astype(str)
                st.dataframe(df_active, hide_index=True, width="stretch")

            # Flagged Threat Incident Log
            st.divider()
            render_threat_log_section(key_prefix="expert_surveillance")

            # Real-Time Multi-Vector Threat Timeline Graph
            if len(st.session_state.live_history) > 1:
                st.divider()
                st.subheader("Threat Activity Timeline")
                st.caption(f"Rolling scores across active traffic vectors vs Decision Threshold Baseline ({detector.config.anomaly_threshold:.2f}):")
                df_chart = pd.DataFrame(st.session_state.live_history)
                chart_data = df_chart.set_index("time")
                st.line_chart(chart_data)

        render_expert_surveillance()

    # -------------------------------------------------------------
    # TAB 2: Flow Matrix & Feature Telemetry
    # -------------------------------------------------------------
    with tab_detailed:
        st.subheader("Flow Telemetry & Feature Matrix")
        st.markdown("Network telemetry, Isolation Forest tree partition depths, and inference latency per flow:")

        if st.session_state.latest_scan_flows:
            det_results = list(st.session_state.latest_scan_flows.values())

            # HUD summary
            d_c1, d_c2, d_c3, d_c4 = st.columns(4)
            d_c1.metric("Active Flows", f"{len(det_results)}")
            d_c2.metric("Flagged Anomalies", f"{sum(1 for r in det_results if r['is_ano'])}")
            d_c3.metric("Decision Boundary", f"{detector.config.anomaly_threshold:.2f}")
            d_c4.metric("Avg Latency", f"{sum(r['latency_ms'] for r in det_results)/max(len(det_results), 1):.3f} ms")

            table_rows = []
            for r in reversed(det_results):
                fl = r["flow"]
                dest_svc = GLOBAL_RESOLVER.resolve_ip(fl.dst_ip)
                is_tr = r.get("is_trusted", False)
                if hide_trusted and is_tr:
                    continue

                status_str = "Whitelisted" if is_tr else ("Alert Flagged" if r["is_ano"] else "Normal")
                table_rows.append({
                    "Traffic Profile": r["category"],
                    "Destination / Service": dest_svc if dest_svc else "External Host",
                    "Endpoints (From → To)": GLOBAL_RESOLVER.format_connection(fl.src_ip, fl.dst_ip),
                    "5-Tuple Socket": f"{fl.protocol}:{fl.src_ip}:{fl.src_port} <-> {fl.dst_ip}:{fl.dst_port}",
                    "Volume": f"{r['packets']} pkts | {r['bytes']:,} B",
                    "Duration": r["duration"],
                    "Anomaly Score": f"{r['score']:.4f}",
                    "Tree Path E(h(x))": f"{r['path_len']:.2f}",
                    "Latency": f"{r['latency_ms']} ms",
                    "Status": status_str
                })
            df_table_rows = pd.DataFrame(table_rows)
            if "Value" in df_table_rows.columns:
                df_table_rows["Value"] = df_table_rows["Value"].astype(str)
            st.dataframe(df_table_rows, hide_index=True, width="stretch")

            # Feature Telemetry Explorer (Integrated directly inside Tab 2)
            st.divider()
            st.subheader("Statistical Flow Feature Vectors")
            st.markdown("Inspect the 15 transport-layer statistical moments extracted across any active network flow:")

            vector_choices = list(st.session_state.latest_scan_flows.keys())
            selected_vector_name = st.selectbox(
                "Select Flow to Inspect Statistical Moments:",
                options=vector_choices,
                index=0,
                key="expert_flow_vector_select"
            )

            flow_entry = st.session_state.latest_scan_flows[selected_vector_name]
            flow = flow_entry["flow"]
            f_dict = flow.to_dict()
            dest_name = GLOBAL_RESOLVER.resolve_ip(flow.dst_ip) or "External Host"

            st.caption(f"Inspecting Flow: **{flow.flow_id}** | Destination: **{dest_name}** | Score: **{flow_entry['score']:.4f}** | Status: **{'Alert Flagged' if flow_entry['is_ano'] else 'Normal'}**")

            col_f1, col_f2 = st.columns(2)
            with col_f1:
                st.markdown("**Volumetric & Timing Moments:**")
                df_vol = pd.DataFrame([
                    {"Feature": "Packet Count", "Value": f_dict["packet_count"], "Unit": "packets"},
                    {"Feature": "Byte Count", "Value": f_dict["byte_count"], "Unit": "bytes"},
                    {"Feature": "Flow Duration", "Value": f_dict["duration"], "Unit": "seconds"},
                    {"Feature": "Mean Packet Size", "Value": f_dict["mean_packet_size"], "Unit": "bytes"},
                    {"Feature": "Packet Size Std Dev", "Value": f_dict["std_packet_size"], "Unit": "bytes"},
                    {"Feature": "Packet Size Variance", "Value": f_dict["var_packet_size"], "Unit": "bytes^2"},
                    {"Feature": "Mean Inter-Arrival Time (IAT)", "Value": f_dict["mean_iat"], "Unit": "seconds"},
                    {"Feature": "IAT Std Dev", "Value": f_dict["std_iat"], "Unit": "seconds"},
                ])
                if "Value" in df_vol.columns:
                    df_vol["Value"] = df_vol["Value"].astype(str)
                st.dataframe(df_vol, hide_index=True, width="stretch")

            with col_f2:
                st.markdown("**TCP Flags & Rate Distribution:**")
                df_flags = pd.DataFrame([
                    {"Feature": "SYN Flags", "Value": f_dict["syn_flag_count"], "Significance": "Connection initiation probes"},
                    {"Feature": "ACK Flags", "Value": f_dict["ack_flag_count"], "Significance": "Handshake acknowledgements"},
                    {"Feature": "RST Flags", "Value": f_dict["rst_flag_count"], "Significance": "Abrupt termination / rejected ports"},
                    {"Feature": "PSH Flags", "Value": f_dict["psh_flag_count"], "Significance": "Immediate data push"},
                    {"Feature": "FIN Flags", "Value": f_dict["fin_flag_count"], "Significance": "Graceful session teardown"},
                    {"Feature": "Packet Rate", "Value": f"{f_dict['packet_rate']} pkt/s", "Significance": "Volumetric intensity"},
                    {"Feature": "Byte Rate", "Value": f"{f_dict['byte_rate']} B/s", "Significance": "Throughput volume"},
                ])
                if "Value" in df_flags.columns:
                    df_flags["Value"] = df_flags["Value"].astype(str)
                st.dataframe(df_flags, hide_index=True, width="stretch")
        else:
            st.info("No active flows captured yet. Start the real-time scanner or live sniffer to populate the detailed matrix.")

    # -------------------------------------------------------------
    # TAB 3: Model Benchmarks
    # -------------------------------------------------------------
    with tab_bench:
        st.subheader("Model Performance & Architecture Benchmark")
        st.markdown("Comparative performance metrics across candidate anomaly detection architectures on identical flow telemetry:")

        col_bench_ctrl, _ = st.columns([1, 2])
        with col_bench_ctrl:
            run_bench = st.button("Run Comparative Benchmark", type="primary", use_container_width=True, key="expert_run_bench")

        if run_bench:
            with st.spinner("Training baseline Autoencoder & evaluating comparative test set..."):
                suite = Phase1BenchmarkSuite(detector)
                bench_results = suite.run_comparative_benchmark(n_benign=120, n_attack=40)
                st.session_state.bench_results = bench_results

        if "bench_results" in st.session_state:
            res = st.session_state.bench_results
            if_res = res["isolation_forest"]
            ae_res = res["autoencoder"]

            st.divider()
            st.markdown(f"**Evaluation Dataset:** {res['dataset_samples']} flows ({res['benign_samples']} Benign, {res['attack_samples']} Attack)")

            col_if_card, col_ae_card = st.columns(2)
            with col_if_card:
                st.markdown("### Isolation Forest (Active Model)")
                st.markdown(f"- **Avg Inference Latency:** `{if_res['avg_inference_latency_ms']:.4f} ms`")
                st.markdown(f"- **P95 Latency:** `{if_res['p95_inference_latency_ms']:.4f} ms`")
                st.markdown(f"- **Precision:** `{if_res['precision'] * 100:.1f}%`")
                st.markdown(f"- **Recall:** `{if_res['recall'] * 100:.1f}%`")
                st.markdown(f"- **F1-Score:** `{if_res['f1_score']:.4f}`")
                st.markdown(f"- **False Positive Rate (FPR):** `{if_res['false_positive_rate'] * 100:.2f}%`")
                st.markdown(f"- **Memory Overhead:** `{if_res['memory_delta_mb']} MB`")

            with col_ae_card:
                st.markdown("### Deep Autoencoder (Baseline Model)")
                st.markdown(f"- **Avg Inference Latency:** `{ae_res['avg_inference_latency_ms']:.4f} ms`")
                st.markdown(f"- **P95 Latency:** `{ae_res['p95_inference_latency_ms']:.4f} ms`")
                st.markdown(f"- **Precision:** `{ae_res['precision'] * 100:.1f}%`")
                st.markdown(f"- **Recall:** `{ae_res['recall'] * 100:.1f}%`")
                st.markdown(f"- **F1-Score:** `{ae_res['f1_score']:.4f}`")
                st.markdown(f"- **False Positive Rate (FPR):** `{ae_res['false_positive_rate'] * 100:.2f}%`")
                st.markdown(f"- **Memory Overhead:** `{ae_res['memory_delta_mb']} MB`")

    # -------------------------------------------------------------
    # TAB 4: Incident Dispatch Queue
    # -------------------------------------------------------------
    with tab_queue:
        st.subheader("Security Incident Dispatch Queue")
        st.markdown("Staged security incident records flagged by the detection engine, containing complete flow telemetry for forensic triage:")

        alerts = alert_mgr.get_all_alerts()
        if alerts:
            records = [a.to_dict() for a in alerts]
            df_alerts = pd.DataFrame(records)
            cols_to_show = ["alert_id"]
            if "destination_service" in df_alerts.columns:
                cols_to_show.append("destination_service")
            cols_to_show.extend(["flow_id", "anomaly_score", "inference_time_ms", "status"])
            df_alerts_disp = df_alerts[cols_to_show].copy()
            if "Value" in df_alerts_disp.columns:
                df_alerts_disp["Value"] = df_alerts_disp["Value"].astype(str)
            st.dataframe(df_alerts_disp, width="stretch")

            col_dl, col_clr, col_purge = st.columns([1, 1, 1.2])
            with col_dl:
                json_blob = json.dumps(records, indent=2)
                st.download_button(
                    "Export Incidents (JSON)",
                    data=json_blob,
                    file_name="vanguard_incident_records.json",
                    mime="application/json",
                    use_container_width=True
                )
            with col_clr:
                if st.button("Clear Incident Queue", use_container_width=True, key="expert_clear_queue"):
                    purge_incident_queue()
                    st.rerun()
            with col_purge:
                if st.button("Purge False Positives", use_container_width=True, key="expert_purge_queue", type="secondary"):
                    purge_incident_queue()
                    st.toast("Incident records purged successfully.")
                    st.rerun()
        elif st.session_state.threat_incident_log:
            df_threats = pd.DataFrame(st.session_state.threat_incident_log)
            if "Value" in df_threats.columns:
                df_threats["Value"] = df_threats["Value"].astype(str)
            st.dataframe(df_threats, width="stretch")
            col_dl, col_clr, col_purge = st.columns([1, 1, 1.2])
            with col_dl:
                json_blob = json.dumps(st.session_state.threat_incident_log, indent=2)
                st.download_button(
                    "Export Incidents (JSON)",
                    data=json_blob,
                    file_name="vanguard_incident_records.json",
                    mime="application/json",
                    use_container_width=True
                )
            with col_clr:
                if st.button("Clear Incident Queue", use_container_width=True, key="expert_clear_threat_log"):
                    purge_incident_queue()
                    st.rerun()
            with col_purge:
                if st.button("Purge False Positives", use_container_width=True, key="expert_purge_threat_queue", type="secondary"):
                    purge_incident_queue()
                    st.toast("Incident records purged successfully.")
                    st.rerun()
        else:
            st.markdown("""
            <div style="background:#151E2E; border:1px solid #26334D; border-left:4px solid #10B981; border-radius:6px; padding:14px 18px; margin-bottom:14px; display:flex; align-items:center;">
                <span class="status-dot dot-emerald"></span>
                <span style="color:#94A3B8; font-size:0.88rem;">No security incidents currently queued. Monitored network flows are clean and within baseline thresholds.</span>
            </div>
            """, unsafe_allow_html=True)
