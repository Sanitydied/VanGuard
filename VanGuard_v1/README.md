# VanGuard: Low-Latency Statistical Flow Anomaly Detection and Forensic Telemetry

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B.svg)](https://streamlit.io/)
[![Architecture](https://img.shields.io/badge/System-Dual--View%20NDR-slate.svg)]()

> **The Bombay Salesian Society’s Don Bosco Institute of Technology, Mumbai**  
> **Department of Computer Engineering (Academic Year 2026-27 ODD Semester)**  
> **Course:** 25IL5ELC01 - Research Methodology  
> **Mentor Assigned Activity Project Synopsis:**  
> *"VanGuard: Autonomous Network Threat Detection and Agentic Response using ReAct and RAG-Grounded Threat Mapping"*  
> 
> **Submitted by:**
> | Roll No | Student Name |
> |---|---|
> | 68 | Kenneth Ornello |
> | 69 | Kingsshen Rabert |
> | 70 | Manuel Ferreira |
> | 71 | Shaun D'souza |

---

## Project Overview

**VanGuard** is a lightweight, line-rate network detection system engineered to identify anomalies in transport-layer traffic without payload inspection. Designed for both enterprise network visibility and forensic diagnostics, VanGuard separates operational metrics from deep packet telemetry through a dual-interface architecture:

1. **Simple Overview:** A restrained, operational status console designed for rapid triage, presenting real-time system health, an active threat counter, tripwire sensitivity controls, and trusted network policy management.
2. **Advanced Forensic Mode:** A technical diagnostics dashboard providing real-time sliding-window traffic timelines, 15-moment statistical flow inspection, empirical model benchmarking, and an exportable incident queue.

---

## System Architecture and Implementation Highlights

### 1. Transport-Layer Feature Extraction
Following the standard feature representation outlined by Sarhan et al. (2022), the engine computes **15 statistical moments** per sliding window across encrypted TLS/HTTPS and raw transport-layer flows:

* **Volumetric Metrics:** `packet_count`, `byte_count`, `packet_rate`, `byte_rate`.
* **Temporal Moments:** `duration`, `mean_iat`, `std_iat` (jitter).
* **Length Distributions:** `mean_packet_size`, `std_packet_size`, `var_packet_size`.
* **State and Flag Counts:** `syn_flag_count`, `fin_flag_count`, `rst_flag_count`, `psh_flag_count`, `ack_flag_count`.

To prevent mathematical rate divergence on single-packet flows (where Δt ≈ 0), the feature extractor normalizes durations to discrete observation windows, ensuring rate attributes do not saturate into artificial anomalies.

### 2. Trusted Network Whitelist and Heuristic Pre-Filtering
To minimize false positive rates in typical local area network (LAN) environments, benign local discovery protocols and edge routing chatter are resolved through a deterministic pre-filter prior to model evaluation:
* **Multicast and Discovery Protocols:** SSDP (`239.255.255.250:1900`), mDNS (`224.0.0.251:5353`, `ff02::fb:5353`), and NetBIOS-NS (`137`).
* **Infrastructure Services:** Local gateway DNS queries (`192.168.x.x:53`) and link-local IPv6 gateway announcements (`fe80::/10`).

### 3. Decoupled, Low-Jitter Streamlit UI
* **Non-Blocking Packet Ingestion:** Raw packet capture runs continuously on an asynchronous background daemon thread (`threading.Thread`) populating a thread-safe sliding window buffer.
* **Partial DOM Re-rendering:** Dynamic telemetry cards and time-series charts refresh via `@st.fragment`, isolating metric updates from static navigation controls and preventing UI stutter.
* **Custom Display Pipeline:** Overrides Streamlit full-page reload dimming to maintain constant 100% canvas opacity and enforces explicit PyArrow string casts on tabular diagnostic values.

---

## Model Benchmark and Empirical Evaluation

VanGuard implements an unsupervised **Isolation Forest** (Smolen & Benova, 2023) to partition multivariate statistical moments into isolated tree structures. Path length distributions determine anomaly scores:

$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

Where $E(h(x))$ represents the average path depth for flow $x$, and $c(n)$ is the average path depth of unsuccessful searches in a binary search tree.

### Comparative Performance (Evaluation Dataset: 160 Flows)
Evaluated across 120 benign flows and 40 simulated attack flows (including Port Scanning, SYN Flood DoS, and Data Exfiltration bursts aligned with CICIDS2017 distributions):

| Evaluation Metric | Isolation Forest (Active Engine) | Deep Autoencoder (Baseline) | Operational Significance |
|---|:---:|:---:|---|
| **Average Latency ($T_{\text{inf}}$)** | **27.20 ms** | 0.21 ms | Bounded sub-frame processing per flow window |
| **P95 Latency** | **53.07 ms** | 0.39 ms | Consistent throughput without unbounded delays |
| **Precision** | **95.2%** | 75.0% | Minimizes erroneous alerts on irregular web traffic |
| **Recall** | **100.0%** | 45.0% | Comprehensive threat capture across stealth vectors |
| **F1-Score** | **0.9756** | 0.5625 | Optimal harmonic balance for operational triage |
| **False Positive Rate (FPR)** | **1.67%** | 5.00% | Low alert fatigue during baseline continuous inspection |
| **Memory Overhead** | **2.15 MB** | 0.45 MB | Minimal footprint suitable for edge deployment |

---

## Repository Structure

```
Major_Project/
├── agentndr/                        # Core Engine Package
│   ├── __init__.py                  # Package exports
│   ├── config.py                    # Schema definitions and threshold settings
│   ├── flow_extractor.py            # Sliding-window statistical moment extraction
│   ├── isolation_forest.py          # Isolation Forest model and scoring math
│   ├── benchmark_suite.py           # Autoencoder vs. iForest comparative benchmark
│   ├── traffic_generator.py         # Synthetic traffic and attack flow generator
│   ├── alert_queue.py               # Incident queue persistence manager
│   └── pcap_reader.py               # PCAP packet capture interface (Scapy)
├── alerts/                          # Queued incident storage
│   └── vanguard_incident_queue.json # Flagged anomalies pending triage
├── docs/
│   └── phase2_roadmap.md            # Architecture specification for Phase 2 handoff
├── tests/                           # Verification test suite
│   ├── test_flow_extractor.py       # Moment extraction validation
│   ├── test_isolation_forest.py     # Inference accuracy and latency assertions
│   ├── test_traffic_generator.py    # Synthetic generator validation
│   ├── test_alert_queue.py          # Queue serialization validation
│   └── test_benchmark_suite.py      # Benchmark suite tests
├── app.py                           # Dual-View Streamlit Dashboard
├── run_cli.py                       # Headless CLI Runner
├── run_phase1.bat                   # Environment launcher
├── requirements.txt                 # Project dependencies
└── README.md                        # Project documentation
```

---

## Installation and Execution

### 1. Environment Setup
Clone the repository and install the verified dependencies:
```bash
git clone [https://github.com/YourUsername/AgentNDR.git](https://github.com/YourUsername/AgentNDR.git)
cd AgentNDR
pip install -r requirements.txt
```

### 2. Run Test Suite
Validate the statistical extraction engine and model scoring math:
```bash
python -m unittest discover tests
```

### 3. Launch the Web Dashboard
Start the dashboard through Streamlit:
```bash
python -m streamlit run app.py
```
Open `http://localhost:8501` to access:
* **System Status:** View active defense metrics and toggle inspection states.
* **Sensitivity Controls:** Adjust tripwire scoring thresholds and toggle the trusted network whitelist.
* **Forensic Telemetry:** Inspect individual flow moments, timeline graphs, and logged alerts.

### 4. Headless CLI Monitoring
Run VanGuard in terminal-only environments:
```bash
# Continuous real-time monitor (5-second evaluation interval)
python run_cli.py --live --interval 5

# Single-shot evaluation across traffic categories
python run_cli.py

# Execute empirical model benchmark
python run_cli.py --benchmark

# Display active incident queue
python run_cli.py --show-alerts
```

---

## References

1. **Sarhan, M., Layeghy, S., & Portmann, M. (2022).** Towards a Standard Feature Set for Network Intrusion Detection System Datasets. *IEEE Transactions on Network and Service Management*, 19(1), 352–367.
2. **Smolen, M., & Benova, E. (2023).** Comparing Autoencoder and Isolation Forest in Network Anomaly Detection. *Proceedings of the 33rd Conference of Open Innovations Association FRUCT*, 238–244.
