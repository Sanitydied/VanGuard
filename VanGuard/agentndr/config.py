"""
Phase 1 Configuration for AgentNDR.
Defines parameters for Perception, Statistical Flow Feature Extraction,
and Unsupervised Isolation Forest Anomaly Scoring.
"""

import os
from dataclasses import dataclass, field
from typing import List

@dataclass
class FlowExtractionConfig:
    """Parameters for Sliding-Window Statistical Flow Extraction (Sarhan et al., 2022)."""
    window_duration_sec: float = 5.0  # Sliding time window delta_t
    max_packets_per_flow: int = 500
    idle_timeout_sec: float = 2.0     # Time to flush inactive flows
    # 15 Standard Flow Features derived from Sarhan et al. (2022)
    feature_names: List[str] = field(default_factory=lambda: [
        "packet_count",       # Total packets in window
        "byte_count",         # Total bytes in window
        "duration",           # Flow duration (seconds)
        "mean_packet_size",   # First moment of packet length
        "std_packet_size",    # Second moment of packet length
        "var_packet_size",    # Variance of packet length
        "mean_iat",           # Packet Inter-Arrival Time (mean)
        "std_iat",            # Packet Inter-Arrival Time (std dev)
        "syn_flag_count",     # TCP SYN flags
        "fin_flag_count",     # TCP FIN flags
        "rst_flag_count",     # TCP RST flags
        "psh_flag_count",     # TCP PSH flags
        "ack_flag_count",     # TCP ACK flags
        "packet_rate",        # Packets per second
        "byte_rate"           # Bytes per second
    ])

@dataclass
class IsolationForestConfig:
    """Parameters for Unsupervised Isolation Forest Anomaly Detection (Smolen & Benova, 2023)."""
    n_estimators: int = 150
    contamination: float = 0.05
    max_samples: str = "auto"
    random_state: int = 42
    n_jobs: int = 1  # 1 for sub-millisecond streaming single-sample inference without thread overhead
    # Empirical anomaly score threshold to trigger Phase 2 alert dispatch (0.0 to 1.0)
    anomaly_threshold: float = 0.65

@dataclass
class Phase1Config:
    """Global configuration wrapper for Phase 1."""
    flow: FlowExtractionConfig = field(default_factory=FlowExtractionConfig)
    model: IsolationForestConfig = field(default_factory=IsolationForestConfig)
    project_root: str = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    alert_queue_path: str = os.path.join(
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        "alerts",
        "phase1_anomaly_queue.json"
    )
    model_save_path: str = os.path.join(
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        "models",
        "isolation_forest_phase1.joblib"
    )

DEFAULT_CONFIG = Phase1Config()
