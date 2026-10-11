"""
AgentNDR (Phase 1): Perception, Sliding-Window Flow Feature Engineering,
and Low-Latency Unsupervised Anomaly Scoring.

Department of Computer Engineering, Don Bosco Institute of Technology, Mumbai.
"""

from .config import DEFAULT_CONFIG, Phase1Config
from .flow_extractor import FlowExtractor, NetworkFlow, PacketRecord
from .isolation_forest import IsolationForestDetector
from .traffic_generator import TrafficGenerator, AttackCategory
from .alert_queue import AlertQueueManager, AnomalyAlert
from .benchmark_suite import Phase1BenchmarkSuite

__version__ = "1.0.0-phase1"
__all__ = [
    "DEFAULT_CONFIG",
    "Phase1Config",
    "FlowExtractor",
    "NetworkFlow",
    "PacketRecord",
    "IsolationForestDetector",
    "TrafficGenerator",
    "AttackCategory",
    "AlertQueueManager",
    "AnomalyAlert",
    "Phase1BenchmarkSuite"
]
