"""
Phase 1 Anomaly Alert Queue & Phase 2 Handoff Interface.
Persists flagged statistical anomalies exceeding the empirical threshold (s >= 0.65)
to provide a deterministic staging queue for the future Phase 2 ReAct SOC Agents.
"""

import os
import json
import uuid
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from .flow_extractor import NetworkFlow
from .config import DEFAULT_CONFIG
from .service_resolver import GLOBAL_RESOLVER

@dataclass
class AnomalyAlert:
    """Standardized Alert format representing the Phase 1 -> Phase 2 interface."""
    alert_id: str
    timestamp: float
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    anomaly_score: float
    estimated_path_length: float
    inference_time_ms: float
    flow_features: Dict[str, Any]
    destination_service: Optional[str] = None
    status: str = "PENDING_PHASE2_TRIAGE"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class AlertQueueManager:
    """Manages recording, queueing, and exporting of Phase 1 anomaly alerts."""

    def __init__(self, queue_filepath: Optional[str] = None):
        self.queue_filepath = queue_filepath or DEFAULT_CONFIG.alert_queue_path
        os.makedirs(os.path.dirname(self.queue_filepath), exist_ok=True)
        self.in_memory_alerts: List[AnomalyAlert] = []
        self._load_from_disk()

    def enqueue_alert(
        self,
        flow: NetworkFlow,
        anomaly_score: float,
        path_length: float,
        inference_time_ms: float,
        destination_service: Optional[str] = None
    ) -> AnomalyAlert:
        """Creates a standardized AnomalyAlert and appends it to the queue."""
        resolved_service = destination_service or GLOBAL_RESOLVER.resolve_ip(flow.dst_ip) or None
        alert = AnomalyAlert(
            alert_id=f"PH1-ALT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=time.time(),
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            anomaly_score=round(anomaly_score, 4),
            estimated_path_length=round(path_length, 2),
            inference_time_ms=round(inference_time_ms, 3),
            flow_features=flow.to_dict(),
            destination_service=resolved_service
        )
        self.in_memory_alerts.append(alert)
        self._save_to_disk()
        return alert

    def get_all_alerts(self) -> List[AnomalyAlert]:
        """Returns all queued alerts."""
        return list(self.in_memory_alerts)

    def clear(self) -> None:
        """Clears the alert queue."""
        self.in_memory_alerts = []
        self._save_to_disk()

    def _save_to_disk(self) -> None:
        """Serializes alert queue to JSON file."""
        try:
            data = [a.to_dict() for a in self.in_memory_alerts]
            with open(self.queue_filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _load_from_disk(self) -> None:
        """Loads existing alerts from JSON file if available."""
        if not os.path.exists(self.queue_filepath):
            return
        try:
            with open(self.queue_filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.in_memory_alerts = [
                    AnomalyAlert(**item) for item in data
                ]
        except Exception:
            self.in_memory_alerts = []
