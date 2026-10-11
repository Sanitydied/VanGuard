# AgentNDR: Phase 2 Architecture & Implementation Roadmap

> **Academic Context:** Don Bosco Institute of Technology, Mumbai  
> **Course:** 25IL5ELC01 - Research Methodology (Session 2026-27)  
> **Authors:** Kenneth Ornello, Kingsshen Rabert, Manuel Ferreira, Shaun D'souza  

---

## 📌 Phase 1 Completion Status (Prerequisite)
Phase 1 implements the **Perception and Low-Latency Statistical Flow Anomaly Scoring Layer (Tier 1)**:
- Sliding-window flow extractor capturing 15 standardized moments (Sarhan et al., 2022) across encrypted TLS/HTTPS streams.
- Unsupervised Isolation Forest anomaly scoring model (Smolen & Benova, 2023) operating at line rate ($T_{\\text{inf}} < 1$ ms) to eliminate alert fatigue.
- Staging queue: Anomalies scoring above threshold ($s \\ge 0.65 - 0.75$) are serialized and persisted into `alerts/phase1_anomaly_queue.json`.

---

## 🚀 Phase 2 Objectives (To Be Developed After Academic Gap)

Phase 2 will consume the output of Phase 1 to execute autonomous root-cause investigation, threat intelligence grounding, and automated operating system process containment.

### 1. Tier 2: Cognitive Reasoning & ReAct SOC Multi-Agent Orchestration
*Foundational Papers:* **Yao et al. (2023)** (*ReAct Paradigm*), **Wu & Johnson (2025)** (*ReAct-Driven SOC Agent*)
- **Threat Analyst Agent:**
  - Ingests `PH1-ALT-*` alerts from `alerts/phase1_anomaly_queue.json`.
  - Executes interleaved **Thought $\\rightarrow$ Action $\\rightarrow$ Observation** trajectory.
  - Queries OS host diagnostic interfaces (`inspect_socket_table`, `get_process_details`).
- **SOC Supervisor Agent:**
  - Evaluates analyst hypothesis, verifies false positive likelihood, and assesses operating system stability (checks against protected binary whitelist).
  - Issues authorization for automated host containment (`APPROVED`, `REJECTED_PROTECTED_BINARY`, `MONITOR`).

### 2. Cross-Layer Host Diagnostics & Containment Bridge
*Addressing Literature Gap 1:* Disconnection between raw network telemetry and host PID containment.
- Uses `psutil.net_connections` to inspect local socket tables and match network endpoints `(src_port, dst_ip, dst_port)` to the local **Process ID (PID)**.
- Gathers host forensic telemetry: executable binary name, command-line arguments, CPU/memory usage, parent-child process tree.
- Executes automated process containment (`taskkill /PID <pid> /F` on Windows or `proc.terminate()` via `psutil`).

### 3. Tier 3: Knowledge Grounding Layer (MITRE ATT&CK Vector RAG)
*Foundational Paper:* **Schuurman (2025)** (*RAG-ATT&CK: Exploring RAG-Assisted Mapping*)
- Indexes the **MITRE ATT&CK Enterprise Matrix v14** into a local vector store (e.g., ChromaDB / TF-IDF semantic embeddings).
- Formulates dense search vectors from network flow indicators and process command lines.
- Computes cosine similarity:
  $$\\text{Cosine Similarity}(u, v) = \\frac{u \\cdot v}{\\|u\\|_2 \\|v\\|_2}$$
- Yields deterministic technique IDs (e.g., `T1046`, `T1498`, `T1041`, `T1071`, `T1059`) and authorized mitigation actions without LLM hallucination.

---

## 🔌 Data Contract / Interface (Phase 1 $\\rightarrow$ Phase 2)

Phase 2 agents will read the alert queue JSON schema produced by Phase 1:

```json
{
  "alert_id": "PH1-ALT-A2640696",
  "timestamp": 1790620752.41,
  "flow_id": "TCP:192.168.1.105:63126<->203.0.113.50:870",
  "src_ip": "192.168.1.105",
  "src_port": 63126,
  "dst_ip": "203.0.113.50",
  "dst_port": 870,
  "protocol": "TCP",
  "anomaly_score": 0.8226,
  "estimated_path_length": 3.26,
  "inference_time_ms": 5.837,
  "flow_features": {
    "packet_count": 164,
    "byte_count": 10496,
    "duration": 0.2541,
    "mean_packet_size": 64.0,
    "mean_iat": 0.001554,
    "syn_flag_count": 164,
    "ack_flag_count": 0,
    "rst_flag_count": 34,
    "packet_rate": 645.41,
    "byte_rate": 41306.57
  },
  "status": "PENDING_PHASE2_TRIAGE"
}
```
