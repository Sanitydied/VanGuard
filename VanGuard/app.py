"""
AgentNDR: Real-Time Network Threat Detection & Anomaly Analysis Platform.
Inspired by Cisco Secure Networking & Threat Intelligence Design System.
"""

import os
import sys
import time
import json
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
from agentndr.pcap_loader import PCAPLoader
from agentndr.live_sniffer import LivePacketSniffer

# Page configuration
st.set_page_config(
    page_title="AgentNDR - Secure Network Threat Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling: Cisco Enterprise Design System & Cerulean/Cyan Mesh Gradient
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Transparent Streamlit Header to reveal ambient gradient */
    header[data-testid="stHeader"] {
        background: transparent !important;
    }

    /* Cisco Enterprise Canvas - Signature Oceanic Navy & Cerulean Mesh Gradient */
    .stApp {
        background: 
            radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0, 188, 235, 0.22), transparent 75%),
            radial-gradient(circle at 10% 25%, rgba(4, 159, 217, 0.16) 0%, transparent 45%),
            radial-gradient(circle at 90% 20%, rgba(36, 100, 198, 0.20) 0%, transparent 50%),
            radial-gradient(circle at 50% 85%, rgba(0, 184, 113, 0.08) 0%, transparent 50%),
            linear-gradient(180deg, #020b18 0%, #07172e 40%, #041021 100%) !important;
        background-attachment: fixed !important;
        color: #e2e8f0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        letter-spacing: -0.01em;
    }

    /* Cisco Signature Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, rgba(3, 13, 29, 0.96) 0%, rgba(2, 9, 20, 0.98) 100%) !important;
        border-right: 1px solid rgba(0, 188, 235, 0.15) !important;
        backdrop-filter: blur(24px) !important;
    }

    /* Cisco Animated Golden Gate / Soundwave Bridge Motif */
    .cisco-bridge-bars {
        display: inline-flex;
        align-items: flex-end;
        gap: 3px;
        height: 22px;
        margin-right: 12px;
        vertical-align: middle;
    }
    .cisco-bridge-bars span {
        width: 3.5px;
        background: linear-gradient(180deg, #00bceb 0%, #049fd9 100%);
        border-radius: 2px;
        animation: cisco-wave 1.8s ease-in-out infinite alternate;
    }
    .cisco-bridge-bars span:nth-child(1) { height: 7px; animation-delay: 0.1s; }
    .cisco-bridge-bars span:nth-child(2) { height: 13px; animation-delay: 0.25s; }
    .cisco-bridge-bars span:nth-child(3) { height: 19px; animation-delay: 0.4s; }
    .cisco-bridge-bars span:nth-child(4) { height: 11px; animation-delay: 0.55s; }
    .cisco-bridge-bars span:nth-child(5) { height: 21px; animation-delay: 0.7s; }
    .cisco-bridge-bars span:nth-child(6) { height: 14px; animation-delay: 0.85s; }
    .cisco-bridge-bars span:nth-child(7) { height: 8px; animation-delay: 1.0s; }

    @keyframes cisco-wave {
        0% { transform: scaleY(0.7); opacity: 0.75; }
        50% { transform: scaleY(1.15); opacity: 1; filter: drop-shadow(0 0 5px #00bceb); }
        100% { transform: scaleY(0.85); opacity: 0.85; }
    }

    /* Cisco Brand Header */
    .brand-title {
        font-size: 2.35rem;
        font-weight: 800;
        letter-spacing: -0.035em;
        background: linear-gradient(135deg, #ffffff 0%, #00bceb 50%, #049fd9 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        display: inline-block;
        margin-bottom: 0.15rem;
    }

    .brand-pill {
        display: inline-block;
        background: rgba(0, 188, 235, 0.12);
        border: 1px solid rgba(0, 188, 235, 0.35);
        color: #00bceb;
        font-size: 0.72rem;
        font-weight: 700;
        padding: 4px 11px;
        border-radius: 9999px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        vertical-align: middle;
        margin-left: 10px;
        box-shadow: 0 0 14px rgba(0, 188, 235, 0.22);
    }

    .brand-subtitle {
        color: #8da2be;
        font-size: 0.95rem;
        margin-bottom: 1.2rem;
        font-weight: 400;
        letter-spacing: -0.01em;
    }

    /* Cisco Sliding Command Taskbar (Sticky Dock) */
    .sliding-taskbar {
        background: rgba(8, 24, 48, 0.82);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid rgba(0, 188, 235, 0.25);
        border-radius: 16px;
        padding: 13px 22px;
        margin-bottom: 22px;
        box-shadow: 0 12px 36px -10px rgba(0, 10, 25, 0.75), inset 0 1px 0 rgba(0, 188, 235, 0.2);
        display: flex;
        align-items: center;
        justify-content: space-between;
        transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .sliding-taskbar:hover {
        border-color: rgba(0, 188, 235, 0.5);
        box-shadow: 0 16px 42px -8px rgba(0, 188, 235, 0.28);
    }

    /* Cisco Live Pulse Beacon */
    .pulse-beacon {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 8px;
        vertical-align: middle;
        animation: cisco-beacon-pulse 1.8s infinite ease-in-out;
    }

    @keyframes cisco-beacon-pulse {
        0% { transform: scale(0.9); box-shadow: 0 0 0 0 rgba(0, 184, 113, 0.85); }
        70% { transform: scale(1.15); box-shadow: 0 0 0 8px rgba(0, 184, 113, 0); }
        100% { transform: scale(0.9); box-shadow: 0 0 0 0 rgba(0, 184, 113, 0); }
    }

    /* Cisco Sliding Segmented Pill Tabs */
    div[data-baseweb="tab-list"] {
        background: rgba(6, 19, 39, 0.85) !important;
        backdrop-filter: blur(16px) !important;
        border-radius: 14px !important;
        padding: 6px !important;
        gap: 6px !important;
        border: 1px solid rgba(0, 188, 235, 0.18) !important;
        box-shadow: 0 8px 28px rgba(0, 10, 25, 0.45) !important;
        margin-bottom: 22px !important;
    }

    button[data-baseweb="tab"] {
        border-radius: 10px !important;
        padding: 9px 22px !important;
        color: #8da2be !important;
        font-weight: 600 !important;
        font-size: 0.92rem !important;
        border: none !important;
        transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1) !important;
        background: transparent !important;
    }

    button[data-baseweb="tab"]:hover {
        color: #ffffff !important;
        background: rgba(0, 188, 235, 0.08) !important;
    }

    button[data-baseweb="tab"][aria-selected="true"] {
        background: linear-gradient(135deg, #00bceb 0%, #049fd9 50%, #2464c6 100%) !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        box-shadow: 0 4px 20px rgba(0, 188, 235, 0.45) !important;
    }

    div[data-baseweb="tab-highlight"], div[data-baseweb="tab-border"] {
        display: none !important;
    }

    /* Cisco HUD Metric Cards */
    div[data-testid="stMetric"] {
        background: rgba(7, 21, 42, 0.72) !important;
        backdrop-filter: blur(16px) !important;
        border: 1px solid rgba(0, 188, 235, 0.15) !important;
        border-radius: 14px !important;
        padding: 18px 22px !important;
        box-shadow: 0 8px 30px rgba(0, 10, 25, 0.5) !important;
        transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }

    div[data-testid="stMetric"]:hover {
        transform: translateY(-3px) !important;
        border-color: rgba(0, 188, 235, 0.5) !important;
        box-shadow: 0 12px 35px rgba(0, 188, 235, 0.25) !important;
    }

    div[data-testid="stMetricLabel"] p {
        color: #8da2be !important;
        font-size: 0.8rem !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.06em !important;
    }

    div[data-testid="stMetricValue"] div {
        color: #ffffff !important;
        font-weight: 800 !important;
        font-size: 1.85rem !important;
        letter-spacing: -0.02em !important;
    }

    /* Cisco Glass Tables */
    div[data-testid="stDataFrame"] {
        border-radius: 14px !important;
        overflow: hidden !important;
        border: 1px solid rgba(0, 188, 235, 0.16) !important;
        box-shadow: 0 10px 35px rgba(0, 10, 25, 0.6) !important;
        background: rgba(6, 18, 36, 0.75) !important;
        backdrop-filter: blur(14px) !important;
    }

    /* Cisco Gradient Action Buttons */
    button[kind="primary"] {
        background: linear-gradient(135deg, #00bceb 0%, #049fd9 50%, #2464c6 100%) !important;
        border: none !important;
        border-radius: 10px !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        letter-spacing: 0.02em !important;
        box-shadow: 0 4px 18px rgba(0, 188, 235, 0.4) !important;
        transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }

    button[kind="primary"]:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 26px rgba(0, 188, 235, 0.6) !important;
    }

    button[kind="secondary"] {
        background: rgba(10, 27, 54, 0.75) !important;
        border: 1px solid rgba(0, 188, 235, 0.22) !important;
        border-radius: 10px !important;
        color: #dbeafe !important;
        transition: all 0.2s ease !important;
    }

    button[kind="secondary"]:hover {
        background: rgba(14, 38, 77, 0.9) !important;
        border-color: rgba(0, 188, 235, 0.45) !important;
    }

    /* Cisco Custom Scrollbars */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: rgba(2, 9, 20, 0.6);
    }
    ::-webkit-scrollbar-thumb {
        background: rgba(0, 188, 235, 0.3);
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(0, 188, 235, 0.6);
    }
</style>
""", unsafe_allow_html=True)

# Session State Initialization
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
if "pcap_loader" not in st.session_state:
    st.session_state.pcap_loader = PCAPLoader()
if "ingestion_mode" not in st.session_state:
    st.session_state.ingestion_mode = "Simulation (5 Attack Profiles)"
if "sniffer_active" not in st.session_state:
    st.session_state.sniffer_active = True

detector: IsolationForestDetector = st.session_state.detector
alert_mgr: AlertQueueManager = st.session_state.alert_mgr
sniffer: LivePacketSniffer = st.session_state.sniffer
pcap_loader: PCAPLoader = st.session_state.pcap_loader

# Sidebar: Cisco Secure Operations Center
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=55)
st.sidebar.title("Cisco-Style NDR")
st.sidebar.markdown("**Network Security Center**")

st.sidebar.divider()
st.sidebar.subheader("🌐 Ingestion Pipeline")
ingestion_mode = st.sidebar.radio(
    "Data Source",
    options=[
        "Simulation (5 Attack Profiles)",
        "Live Network Sniffer (Wi-Fi / Ethernet)",
        "PCAP Capture Analysis (Wireshark)"
    ],
    index=0,
    help="Select whether to ingest mathematically modeled attack traffic, real live wire packets from your network interface, or Wireshark PCAP files."
)
st.session_state.ingestion_mode = ingestion_mode

st.sidebar.divider()
st.sidebar.subheader("⚙️ Detection Sensitivity")
threshold = st.sidebar.slider(
    "Decision Boundary",
    min_value=0.50,
    max_value=0.90,
    value=float(DEFAULT_CONFIG.model.anomaly_threshold),
    step=0.05,
    help="Scores exceeding this threshold trigger security incident staging."
)
detector.config.anomaly_threshold = threshold

st.sidebar.markdown(f"**Sliding Window ($\\Delta t$):** `{DEFAULT_CONFIG.flow.window_duration_sec}s`")
st.sidebar.markdown(f"**Forest Estimators ($n$):** `{detector.config.n_estimators}`")
st.sidebar.markdown(f"**Contamination Factor:** `{detector.config.contamination}`")

# Cisco Brand Header with Soundwave Bridge Animation
st.markdown("""
<div>
    <div style="display:flex; align-items:center;">
        <div class="cisco-bridge-bars">
            <span></span><span></span><span></span><span></span><span></span><span></span><span></span>
        </div>
        <span class="brand-title">AGENT NDR</span>
        <span class="brand-pill">CISCO-INSPIRED SECURE NETWORKING</span>
    </div>
    <div class="brand-subtitle">AI Infrastructure & Autonomous Transport-Layer Threat Intelligence</div>
</div>
""", unsafe_allow_html=True)

# Cisco Segmented Sliding Tabs
tab_radar, tab_features, tab_benchmark, tab_queue = st.tabs([
    "🎯 Live Surveillance",
    "📊 Flow Telemetry",
    "🧪 Model Benchmarks",
    "📬 Incident Queue"
])

# -------------------------------------------------------------
# TAB 1: Live Multi-Vector Surveillance Radar
# -------------------------------------------------------------
with tab_radar:
    mode = st.session_state.ingestion_mode

    # Reset scan buffers cleanly when switching between Simulation and Live Network
    if "current_pipeline_mode" not in st.session_state:
        st.session_state.current_pipeline_mode = mode
    elif st.session_state.current_pipeline_mode != mode:
        st.session_state.current_pipeline_mode = mode
        st.session_state.latest_scan_flows = {}
        st.session_state.live_history = []
        if sniffer.is_running and mode != "Live Network Sniffer (Wi-Fi / Ethernet)":
            sniffer.stop_capture()

    if mode == "Simulation (5 Attack Profiles)":
        # Sticky Sliding Command Taskbar (Controls & Live Telemetry)
        dock_c1, dock_c2, dock_c3 = st.columns([2.5, 3.5, 1.5])
        with dock_c1:
            live_active = st.toggle(
                "🟢 Real-Time 5s Auto-Scan",
                value=st.session_state.live_mode,
                help="Continuously analyzes all 5 network profiles simultaneously every 5 seconds."
            )
            st.session_state.live_mode = live_active

        with dock_c2:
            st.write("")
            st.caption("🛡️ **Surveillance Mode:** Multi-vector benchmark simulation (CICIDS2017 & UNSW-NB15).")

        with dock_c3:
            st.write("")
            trigger_manual = st.button("⚡ Scan All Now", type="primary", use_container_width=True, help="Force an immediate scan cycle.")

        # 5-Second Autonomous All-Vector Stream Fragment
        @st.fragment(run_every=5 if st.session_state.live_mode else None)
        def render_simulation_monitor():
            should_ingest = st.session_state.live_mode or trigger_manual or (len(st.session_state.latest_scan_flows) == 0)

            if should_ingest:
                current_scan_results = []
                cycle_alerts = 0
                vector_scores = {}
                sim_cycle_dict = {}

                for cat in AttackCategory:
                    flow = TrafficGenerator.generate_flow(cat)
                    is_ano, score, path_len, lat = detector.predict_flow(flow)

                    if is_ano:
                        cycle_alerts += 1
                        alert_mgr.enqueue_alert(flow, score, path_len, lat)

                    result_entry = {
                        "category": cat.value,
                        "category_short": cat.value.split(" (")[0],
                        "category_key": cat.name,
                        "flow": flow,
                        "flow_id": flow.flow_id,
                        "endpoints": f"{flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port}",
                        "score": round(score, 4),
                        "path_len": round(path_len, 2),
                        "latency_ms": round(lat, 3),
                        "is_ano": is_ano,
                        "packets": flow.packet_count,
                        "bytes": flow.byte_count,
                        "duration": f"{flow.duration:.2f}s"
                    }
                    current_scan_results.append(result_entry)
                    sim_cycle_dict[cat.value] = result_entry
                    vector_scores[cat.name] = round(score, 4)

                # Overwrite latest_scan_flows so Simulation is STRICTLY the 5 vectors
                st.session_state.latest_scan_flows = sim_cycle_dict

                # Update sessions
                st.session_state.total_cycles += 1
                st.session_state.total_scans += len(AttackCategory)
                st.session_state.total_alerts += cycle_alerts

                # Store default flow
                severe_flow = max(current_scan_results, key=lambda x: x["score"])
                st.session_state.last_flow = severe_flow["flow"]
                st.session_state.last_score = severe_flow["score"]
                st.session_state.last_path = severe_flow["path_len"]
                st.session_state.last_lat = severe_flow["latency_ms"]
                st.session_state.last_ano = severe_flow["is_ano"]
                st.session_state.last_cat = next((c for c in AttackCategory if c.name == severe_flow["category_key"]), AttackCategory.BENIGN)

                # Record in rolling timeline (keep last 20 cycles)
                now_ts = datetime.now().strftime("%H:%M:%S")
                timeline_point = {
                    "time": now_ts,
                    "Benign HTTPS": vector_scores.get("BENIGN", 0.2),
                    "Port Scan (T1046)": vector_scores.get("PORT_SCAN", 0.8),
                    "SYN Flood (T1498)": vector_scores.get("SYN_FLOOD", 0.8),
                    "Exfiltration (T1041)": vector_scores.get("EXFILTRATION", 0.8),
                    "Stealth C2 (T1071)": vector_scores.get("STEALTH_C2", 0.65),
                    "Threshold Baseline": threshold
                }
                st.session_state.live_history.append(timeline_point)
                if len(st.session_state.live_history) > 20:
                    st.session_state.live_history.pop(0)

            # Retrieve current display state
            if not st.session_state.latest_scan_flows:
                st.info("Initializing multi-vector surveillance stream...")
                return

            now_str = datetime.now().strftime("%H:%M:%S")
            status_mode = f"SURVEILLANCE ONLINE ({now_str})" if st.session_state.live_mode else "SURVEILLANCE PAUSED"
            status_color = "#00b871" if st.session_state.live_mode else "#ff7300"

            latest_results = list(st.session_state.latest_scan_flows.values())
            threats_in_cycle = sum(1 for r in latest_results if r["is_ano"])
            benign_in_cycle = len(latest_results) - threats_in_cycle
            avg_cycle_lat = sum(r["latency_ms"] for r in latest_results) / max(len(latest_results), 1)

            posture_text = "SECURITY ALERT ACTIVE" if threats_in_cycle > 0 else "ALL SYSTEMS SECURE"
            posture_color = "#ff5c5c" if threats_in_cycle > 0 else "#00b871"

            # Cisco Sliding Taskbar Header
            st.markdown(
                f"""<div class="sliding-taskbar">
                    <div style="display:flex; align-items:center;">
                        <span class="pulse-beacon" style="background:{status_color};"></span>
                        <span style="font-weight:700; color:#ffffff; font-size:0.95rem; letter-spacing:0.02em;">{status_mode}</span>
                        <span style="background:rgba(0,188,235,0.12); border:1px solid rgba(0,188,235,0.25); padding:3px 10px; border-radius:6px; font-size:0.75rem; color:#00bceb; font-family:'JetBrains Mono',monospace; margin-left:12px;">Cycle #{st.session_state.total_cycles}</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:24px;">
                        <div style="font-size:0.85rem; color:#8da2be;">
                            Inferences: <b style="color:#00bceb; font-family:'JetBrains Mono',monospace;">{st.session_state.total_scans}</b>
                        </div>
                        <div style="font-size:0.85rem; color:#8da2be;">
                            Incidents: <b style="color:#ff5c5c; font-family:'JetBrains Mono',monospace;">{st.session_state.total_alerts}</b>
                        </div>
                        <div style="font-size:0.85rem; color:#8da2be;">
                            Posture: <b style="color:{posture_color}; font-weight:700;">{posture_text}</b>
                        </div>
                    </div>
                </div>""",
                unsafe_allow_html=True
            )

            # 4 Elevated HUD Metric Cards (Strictly 5 Profiles in Simulation)
            c1, c2, c3, c4 = st.columns(4)
            c1.metric(
                "Monitored Vectors",
                "5 Profiles",
                delta="Simultaneous Scan",
                delta_color="normal"
            )
            c2.metric(
                "Threats Flagged",
                f"{threats_in_cycle} / 5",
                delta=f"{threats_in_cycle} Staged to Queue" if threats_in_cycle > 0 else "Zero Anomalies",
                delta_color="inverse" if threats_in_cycle > 0 else "normal"
            )
            c3.metric(
                "Filter Efficiency",
                f"{benign_in_cycle} / 5 Clean",
                delta="Line-Rate Filter",
                delta_color="normal"
            )
            c4.metric(
                "Inference Speed",
                f"{avg_cycle_lat:.3f} ms",
                delta="< 1.0 ms Target",
                delta_color="normal" if avg_cycle_lat < 1.0 else "off"
            )

            # Live Multi-Vector Stream Matrix
            st.markdown("### 📡 Active Flow Inspection Matrix")
            table_rows = []
            for r in latest_results:
                table_rows.append({
                    "Traffic Profile": r["category"],
                    "Endpoints (5-Tuple)": r["endpoints"],
                    "Volume": f"{r['packets']} pkts | {r['bytes']:,} B",
                    "Duration": r["duration"],
                    "Anomaly Score": f"{r['score']:.4f}",
                    "Tree Path E(h(x))": f"{r['path_len']:.2f}",
                    "Latency": f"{r['latency_ms']} ms",
                    "Status": "🚨 ALERT QUEUED" if r["is_ano"] else "✅ CLEAN"
                })
            st.dataframe(pd.DataFrame(table_rows), hide_index=True, use_container_width=True)

            # Real-Time Multi-Vector Threat Timeline Chart
            if len(st.session_state.live_history) > 1:
                st.divider()
                st.subheader("📈 Real-Time Multi-Vector Threat Radar Timeline")
                st.caption(f"Rolling scores across all 5 active traffic profiles vs Decision Threshold Baseline ({threshold:.2f}):")
                df_chart = pd.DataFrame(st.session_state.live_history)
                chart_data = df_chart.set_index("time")
                st.line_chart(chart_data)

        render_simulation_monitor()

    elif mode == "Live Network Sniffer (Wi-Fi / Ethernet)":
        pcap_avail = LivePacketSniffer.is_pcap_available()
        if not pcap_avail:
            st.markdown("""
            <div style="background:rgba(255, 92, 92, 0.08); border:1px solid rgba(255, 92, 92, 0.35); border-radius:14px; padding:22px 26px; margin-bottom:20px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
                    <span style="font-size:1.4rem;">⚠️</span>
                    <span style="font-weight:700; color:#ff5c5c; font-size:1.1rem; letter-spacing:-0.01em;">Windows Driver Required for Live Wire Sniffing</span>
                </div>
                <div style="color:#cbd5e1; font-size:0.93rem; line-height:1.6;">
                    To sniff raw Layer 2/3 Ethernet and Wi-Fi packets directly from your machine's hardware adapter, Windows requires the standard <b>Npcap kernel packet driver</b> (the official driver used by Wireshark and Nmap).
                </div>
                <div style="margin-top:16px; display:flex; gap:16px; align-items:center; flex-wrap:wrap;">
                    <a href="https://npcap.com/#download" target="_blank" style="background:linear-gradient(135deg, #00bceb 0%, #049fd9 100%); color:#ffffff; padding:9px 20px; border-radius:9px; font-weight:700; font-size:0.9rem; text-decoration:none; display:inline-block; box-shadow:0 4px 14px rgba(0,188,235,0.4);">📥 Download Free Npcap Installer</a>
                    <span style="color:#8da2be; font-size:0.86rem;">⚠️ Make sure to tick <i>"Install in WinPcap API-compatible Mode"</i> during installation.</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            st.info("💡 **Immediate Alternative:** You can analyze real network traffic right now without installing Npcap! Switch to **PCAP Capture Analysis (Wireshark)** in the sidebar to inspect recorded packet captures.")
        else:
            # 🔌 Hardware Interface Switcher (Directly Inside UI Dropdown)
            ifaces = LivePacketSniffer.get_network_interfaces()
            iface_map = {i["display"]: i["dev_name"] for i in ifaces}
            iface_options = list(iface_map.keys())

            selected_label = st.selectbox(
                "📡 Physical Network Adapter Interface (Wi-Fi / Ethernet):",
                options=iface_options if iface_options else ["[Wi-Fi] Default Hardware Adapter"],
                index=0,
                key="live_hardware_adapter_choice",
                help="Select your physical network adapter (Wi-Fi or Ethernet) to capture live wire traffic directly."
            )
            chosen_iface = iface_map.get(selected_label) if iface_map else None

            # Handle interface switching dynamically
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

            # Sticky Sliding Command Taskbar (Controls & Live Telemetry)
            dock_c1, dock_c2, dock_c3 = st.columns([2.5, 3.5, 1.5])
            with dock_c1:
                live_active = st.toggle(
                    "🟢 Real-Time Live Wire Stream",
                    value=st.session_state.sniffer_active,
                    help="Continuously analyzes live network packets from your physical adapter without delay."
                )
                st.session_state.sniffer_active = live_active

            with dock_c2:
                st.write("")
                st.caption(f"🛡️ **Surveillance Mode:** Real-time live wire capture on `{selected_label}`.")

            with dock_c3:
                st.write("")
                trigger_manual = st.button("⚡ Scan Live Wire Now", type="primary", use_container_width=True, help="Force immediate wire capture & scan.")

            if live_active and not sniffer.is_running:
                sniffer.start_capture(chosen_iface)
            elif not live_active and not trigger_manual and sniffer.is_running:
                sniffer.stop_capture()

            @st.fragment(run_every=1 if st.session_state.sniffer_active else None)
            def render_live_sniffer_monitor():
                should_ingest = st.session_state.sniffer_active or trigger_manual or (len(st.session_state.latest_scan_flows) == 0)

                if should_ingest:
                    if not sniffer.is_running and st.session_state.sniffer_active:
                        sniffer.start_capture(chosen_iface)

                    real_flows = sniffer.flush_real_flows(force_all=True)
                    cycle_alerts = 0
                    current_cycle_dict = {}

                    if real_flows:
                        for f in real_flows:
                            is_ano, score, path_len, lat = detector.predict_flow(f)
                            if is_ano:
                                cycle_alerts += 1
                                alert_mgr.enqueue_alert(f, score, path_len, lat)

                            entry = {
                                "category": f"Live {f.protocol}",
                                "category_short": f.protocol,
                                "flow": f,
                                "flow_id": f.flow_id,
                                "endpoints": f"{f.src_ip}:{f.src_port} <-> {f.dst_ip}:{f.dst_port}",
                                "score": round(score, 4),
                                "path_len": round(path_len, 2),
                                "latency_ms": round(lat, 3),
                                "is_ano": is_ano,
                                "packets": f.packet_count,
                                "bytes": f.byte_count,
                                "duration": f"{f.duration:.2f}s"
                            }
                            current_cycle_dict[f.flow_id] = entry

                        # Overwrite with ONLY this cycle's active flows to prevent unbounded accumulation
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

                        # Rolling timeline
                        now_ts = datetime.now().strftime("%H:%M:%S")
                        timeline_point = {
                            "time": now_ts,
                            "Peak Wire Flow": severe_flow["score"],
                            "Mean Wire Ingestion": float(np.mean([e["score"] for e in current_cycle_dict.values()])),
                            "Threshold Baseline": threshold
                        }
                        st.session_state.live_history.append(timeline_point)
                        if len(st.session_state.live_history) > 20:
                            st.session_state.live_history.pop(0)
                    elif trigger_manual:
                        st.session_state.latest_scan_flows = {}

                # Retrieve current display state
                if not st.session_state.latest_scan_flows:
                    if "Disconnected" in selected_label or "No Cable" in selected_label:
                        st.warning(f"⚠️ **Adapter Disconnected:** `{selected_label}` has no active network link (Ethernet cable unplugged). Connect an Ethernet cable or switch back to **Wi-Fi** in the dropdown to capture live traffic.")
                    else:
                        st.info(f"📡 **Listening for wire packets on `{selected_label}`...** Browse websites or open apps to observe real-time 5-tuple flows.")
                    return

                now_str = datetime.now().strftime("%H:%M:%S")
                status_mode = f"SURVEILLANCE ONLINE ({now_str})" if st.session_state.sniffer_active else "SURVEILLANCE PAUSED"
                status_color = "#00b871" if st.session_state.sniffer_active else "#ff7300"

                latest_results = list(st.session_state.latest_scan_flows.values())
                threats_in_cycle = sum(1 for r in latest_results if r["is_ano"])
                benign_in_cycle = len(latest_results) - threats_in_cycle
                avg_cycle_lat = sum(r["latency_ms"] for r in latest_results) / max(len(latest_results), 1)

                posture_text = "SECURITY ALERT ACTIVE" if threats_in_cycle > 0 else "ALL SYSTEMS SECURE"
                posture_color = "#ff5c5c" if threats_in_cycle > 0 else "#00b871"

                # Cisco Sliding Taskbar Header
                st.markdown(
                    f"""<div class="sliding-taskbar">
                        <div style="display:flex; align-items:center;">
                            <span class="pulse-beacon" style="background:{status_color};"></span>
                            <span style="font-weight:700; color:#ffffff; font-size:0.95rem; letter-spacing:0.02em;">{status_mode}</span>
                            <span style="background:rgba(0,188,235,0.12); border:1px solid rgba(0,188,235,0.25); padding:3px 10px; border-radius:6px; font-size:0.75rem; color:#00bceb; font-family:'JetBrains Mono',monospace; margin-left:12px;">Cycle #{st.session_state.total_cycles}</span>
                        </div>
                        <div style="display:flex; align-items:center; gap:24px;">
                            <div style="font-size:0.85rem; color:#8da2be;">
                                Inferences: <b style="color:#00bceb; font-family:'JetBrains Mono',monospace;">{st.session_state.total_scans}</b>
                            </div>
                            <div style="font-size:0.85rem; color:#8da2be;">
                                Incidents: <b style="color:#ff5c5c; font-family:'JetBrains Mono',monospace;">{st.session_state.total_alerts}</b>
                            </div>
                            <div style="font-size:0.85rem; color:#8da2be;">
                                Posture: <b style="color:{posture_color}; font-weight:700;">{posture_text}</b>
                            </div>
                        </div>
                    </div>""",
                    unsafe_allow_html=True
                )

                # 4 Elevated HUD Metric Cards (Active Wire Telemetry)
                c1, c2, c3, c4 = st.columns(4)
                c1.metric(
                    "Captured Wire Flows",
                    f"{len(latest_results)} Active",
                    delta="Real-Time Live Wire",
                    delta_color="normal"
                )
                c2.metric(
                    "Threats Flagged",
                    f"{threats_in_cycle} / {len(latest_results)}",
                    delta=f"{threats_in_cycle} Staged to Queue" if threats_in_cycle > 0 else "Zero Anomalies",
                    delta_color="inverse" if threats_in_cycle > 0 else "normal"
                )
                c3.metric(
                    "Filter Efficiency",
                    f"{benign_in_cycle} Clean",
                    delta="Line-Rate Filter",
                    delta_color="normal"
                )
                c4.metric(
                    "Inference Speed",
                    f"{avg_cycle_lat:.3f} ms",
                    delta="< 1.0 ms Target",
                    delta_color="normal" if avg_cycle_lat < 1.0 else "off"
                )

                # Live Multi-Vector Stream Matrix
                st.markdown("### 📡 Active Flow Inspection Matrix")
                table_rows = []
                for r in reversed(latest_results):
                    table_rows.append({
                        "Traffic Profile": r["category"],
                        "Endpoints (5-Tuple)": r["endpoints"],
                        "Volume": f"{r['packets']} pkts | {r['bytes']:,} B",
                        "Duration": r["duration"],
                        "Anomaly Score": f"{r['score']:.4f}",
                        "Tree Path E(h(x))": f"{r['path_len']:.2f}",
                        "Latency": f"{r['latency_ms']} ms",
                        "Status": "🚨 ALERT QUEUED" if r["is_ano"] else "✅ CLEAN"
                    })
                st.dataframe(pd.DataFrame(table_rows), hide_index=True, use_container_width=True)

                # Real-Time Multi-Vector Threat Timeline Chart
                if len(st.session_state.live_history) > 1:
                    st.divider()
                    st.subheader("📈 Real-Time Multi-Vector Threat Radar Timeline")
                    st.caption(f"Rolling scores across live wire traffic profiles vs Decision Threshold Baseline ({threshold:.2f}):")
                    df_chart = pd.DataFrame(st.session_state.live_history)
                    chart_data = df_chart.set_index("time")
                    st.line_chart(chart_data)

            render_live_sniffer_monitor()

    elif mode == "PCAP Capture Analysis (Wireshark)":
        st.markdown("### 📁 Real Network Packet Capture Analysis")
        st.markdown("Ingest real-world `.pcap` or `.pcapng` packet captures from Wireshark, tcpdump, or benchmark testbeds:")

        col_p1, col_p2 = st.columns([3, 1.5])
        with col_p1:
            uploaded_pcap = st.file_uploader("Upload Wireshark Capture (.pcap / .pcapng):", type=["pcap", "pcapng"])
        with col_p2:
            st.write("")
            st.write("")
            load_sample = st.button("📦 Load Bundled Real PCAP Sample", help="Loads pre-captured real packets from data/sample_network_capture.pcap", use_container_width=True)

        extracted_pcap_flows = []
        if uploaded_pcap is not None:
            with st.spinner("Extracting 5-tuple conversations and statistical moments from uploaded PCAP..."):
                extracted_pcap_flows = pcap_loader.load_packets_from_bytes(uploaded_pcap.read())
        elif load_sample or ("pcap_analyzed" in st.session_state and st.session_state.pcap_analyzed):
            sample_file = "data/sample_network_capture.pcap"
            if os.path.exists(sample_file):
                with st.spinner("Analyzing data/sample_network_capture.pcap..."):
                    extracted_pcap_flows = pcap_loader.load_pcap_file(sample_file)
                    st.session_state.pcap_analyzed = True

        if extracted_pcap_flows:
            st.success(f"Successfully processed {len(extracted_pcap_flows)} real network conversations from capture file!")
            pcap_results = []
            pcap_alerts = 0
            for f in extracted_pcap_flows:
                is_ano, score, path_len, lat = detector.predict_flow(f)
                if is_ano:
                    pcap_alerts += 1
                    alert_mgr.enqueue_alert(f, score, path_len, lat)
                entry = {
                    "category": f"PCAP: {f.protocol}",
                    "flow": f,
                    "flow_id": f.flow_id,
                    "endpoints": f"{f.src_ip}:{f.src_port} <-> {f.dst_ip}:{f.dst_port}",
                    "score": round(score, 4),
                    "path_len": round(path_len, 2),
                    "latency_ms": round(lat, 3),
                    "is_ano": is_ano,
                    "packets": f.packet_count,
                    "bytes": f.byte_count,
                    "duration": f"{f.duration:.2f}s"
                }
                pcap_results.append(entry)
                st.session_state.latest_scan_flows[f.flow_id] = entry

            # HUD Cards for PCAP
            c1, c2, c3 = st.columns(3)
            c1.metric("Total Flows in PCAP", f"{len(pcap_results)}")
            c2.metric("Anomalies Detected", f"{pcap_alerts}", delta=f"{pcap_alerts} Staged" if pcap_alerts > 0 else "Zero Anomalies", delta_color="inverse" if pcap_alerts > 0 else "normal")
            c3.metric("Clean Conversations", f"{len(pcap_results) - pcap_alerts}")

            # Matrix
            st.markdown("### 📡 PCAP Extracted Flow Matrix")
            st.dataframe(pd.DataFrame([{
                "Endpoints (5-Tuple)": r["endpoints"],
                "Volume": f"{r['packets']} pkts | {r['bytes']:,} B",
                "Duration": r["duration"],
                "Anomaly Score": f"{r['score']:.4f}",
                "Tree Path E(h(x))": f"{r['path_len']:.2f}",
                "Status": "🚨 ALERT QUEUED" if r["is_ano"] else "✅ CLEAN"
            } for r in pcap_results]), hide_index=True, use_container_width=True)
            st.caption("🔍 Switch to the **Flow Telemetry** tab to inspect the 15 exact statistical moments of any flow above.")

# -------------------------------------------------------------
# TAB 2: Flow Telemetry & Features
# -------------------------------------------------------------
with tab_features:
    st.subheader("Statistical Flow Feature Vectors")
    st.markdown("Transport-layer statistical moments extracted across active network flows:")

    if st.session_state.latest_scan_flows:
        vector_choices = list(st.session_state.latest_scan_flows.keys())
        selected_vector_name = st.selectbox(
            "Select Flow from Latest Run to Inspect Statistical Moments:",
            options=vector_choices,
            index=1 if len(vector_choices) > 1 else 0,
            help="Choose any of the 5 vectors analyzed in the real-time scan to view its exact statistical moments."
        )

        flow_entry = st.session_state.latest_scan_flows[selected_vector_name]
        flow = flow_entry["flow"]
        f_dict = flow.to_dict()

        st.caption(f"Inspecting Flow: **{flow.flow_id}** | Anomaly Score: **{flow_entry['score']:.4f}** | Status: **{'🚨 ALERT QUEUED' if flow_entry['is_ano'] else '✅ CLEAN'}**")

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
            st.dataframe(df_vol, hide_index=True, use_container_width=True)

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
            st.dataframe(df_flags, hide_index=True, use_container_width=True)
    else:
        st.info("No network scan has been performed yet. Start the real-time scanner in the Radar tab to populate the statistical moments.")

# -------------------------------------------------------------
# TAB 3: Model Benchmark Lab
# -------------------------------------------------------------
with tab_benchmark:
    st.subheader("Model Performance & Architecture Benchmark")
    st.markdown("Comparative performance metrics across candidate anomaly detection architectures on identical flow telemetry:")

    col_bench_ctrl, _ = st.columns([1, 2])
    with col_bench_ctrl:
        run_bench = st.button("🔬 Execute Benchmark Run", type="primary", use_container_width=True)

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
            st.markdown("### 🌲 Isolation Forest (Active Model)")
            st.markdown(f"- **Avg Inference Latency:** `{if_res['avg_inference_latency_ms']:.4f} ms`")
            st.markdown(f"- **P95 Latency:** `{if_res['p95_inference_latency_ms']:.4f} ms`")
            st.markdown(f"- **Precision:** `{if_res['precision'] * 100:.1f}%`")
            st.markdown(f"- **Recall:** `{if_res['recall'] * 100:.1f}%`")
            st.markdown(f"- **F1-Score:** `{if_res['f1_score']:.4f}`")
            st.markdown(f"- **False Positive Rate (FPR):** `{if_res['false_positive_rate'] * 100:.2f}%`")
            st.markdown(f"- **Memory Overhead:** `{if_res['memory_delta_mb']} MB`")

        with col_ae_card:
            st.markdown("### 🧠 Deep Autoencoder (Baseline Model)")
            st.markdown(f"- **Avg Inference Latency:** `{ae_res['avg_inference_latency_ms']:.4f} ms`")
            st.markdown(f"- **P95 Latency:** `{ae_res['p95_inference_latency_ms']:.4f} ms`")
            st.markdown(f"- **Precision:** `{ae_res['precision'] * 100:.1f}%`")
            st.markdown(f"- **Recall:** `{ae_res['recall'] * 100:.1f}%`")
            st.markdown(f"- **F1-Score:** `{ae_res['f1_score']:.4f}`")
            st.markdown(f"- **False Positive Rate (FPR):** `{ae_res['false_positive_rate'] * 100:.2f}%`")
            st.markdown(f"- **Memory Overhead:** `{ae_res['memory_delta_mb']} MB`")

# -------------------------------------------------------------
# TAB 4: Security Incident Dispatch Queue
# -------------------------------------------------------------
with tab_queue:
    st.subheader("Security Incident Dispatch Queue")
    st.markdown("Staged security incident records flagged by the detection engine, containing complete flow telemetry for forensic triage:")

    alerts = alert_mgr.get_all_alerts()
    if alerts:
        records = [a.to_dict() for a in alerts]
        df_alerts = pd.DataFrame(records)
        st.dataframe(df_alerts[["alert_id", "flow_id", "anomaly_score", "inference_time_ms", "status"]], use_container_width=True)

        col_dl, col_clr = st.columns([1, 1])
        with col_dl:
            json_blob = json.dumps(records, indent=2)
            st.download_button(
                "📥 Export Incident Queue (JSON)",
                data=json_blob,
                file_name="security_incident_queue.json",
                mime="application/json",
                use_container_width=True
            )
        with col_clr:
            if st.button("🗑️ Clear Incident Queue", use_container_width=True):
                alert_mgr.clear()
                st.rerun()
    else:
        st.info("The incident queue is currently empty. Detected anomalies will be staged here automatically.")
