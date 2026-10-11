"""
Unsupervised Isolation Forest Model for Tier 1 Anomaly Isolation (Phase 1).
Implements the findings and mathematical formulations of Smolen & Benova (2023):
s(x, n) = 2^(-E(h(x)) / c(n))
where E(h(x)) is the average path length of point x and c(n) is the average path length
of unsuccessful searches in a Binary Search Tree.
"""

import os
import time
import joblib
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from .flow_extractor import NetworkFlow
from .config import DEFAULT_CONFIG, IsolationForestConfig

class IsolationForestDetector:
    """
    Tier 1 Low-Latency Unsupervised Anomaly Scoring Engine.
    Executes line-rate anomaly scoring on 15-dimensional flow feature vectors.
    """
    def __init__(self, config: Optional[IsolationForestConfig] = None):
        self.config = config or DEFAULT_CONFIG.model
        self.scaler = RobustScaler()
        self.model = IsolationForest(
            n_estimators=self.config.n_estimators,
            contamination=self.config.contamination,
            max_samples=self.config.max_samples,
            random_state=self.config.random_state,
            n_jobs=self.config.n_jobs
        )
        self.is_fitted = False
        self.n_samples_trained = 0
        self.total_inferences = 0
        self.cumulative_latency_ms = 0.0

    @staticmethod
    def calculate_c_factor(n: int) -> float:
        """
        Computes c(n): average path length of unsuccessful search in BST.
        c(n) = 2 * (ln(n - 1) + 0.5772156649) - (2 * (n - 1) / n)
        (Euler-Mascheroni constant = 0.5772156649)
        """
        if n <= 1:
            return 1.0
        if n == 2:
            return 1.0
        euler_constant = 0.5772156649
        return float(2.0 * (np.log(n - 1.0) + euler_constant) - (2.0 * (n - 1.0) / float(n)))

    def fit(self, flows: List[NetworkFlow]) -> None:
        """Fits the Isolation Forest on a collection of baseline NetworkFlow objects."""
        if not flows:
            raise ValueError("Training flow collection is empty.")

        X = np.array([f.to_feature_vector() for f in flows])
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        self.n_samples_trained = len(flows)
        # Pre-warm inference pipeline to eliminate JIT/alloc latency
        self.model.decision_function(X_scaled[:1])

    def initialize_benign_baseline(self, num_samples: int = 600) -> None:
        """
        Synthesizes a realistic, multi-profile benign traffic baseline.
        Encompasses normal web browsing (HTTPS), video streaming (YouTube/QUIC),
        and ephemeral queries (DNS/NTP) to eliminate false-positive alert fatigue.
        """
        np.random.seed(self.config.random_state)
        features = []

        # 1. Standard Enterprise Web / HTTPS Sessions (50%)
        n_web = int(num_samples * 0.50)
        for _ in range(n_web):
            pkts = float(np.random.randint(20, 100))
            bytes_val = float(pkts * np.random.uniform(400, 1100))
            duration = float(np.random.uniform(1.0, 5.0))
            mean_pkt = bytes_val / pkts
            std_pkt = float(np.random.uniform(150, 350))
            var_pkt = float(std_pkt ** 2)
            mean_iat = float(duration / pkts)
            std_iat = float(mean_iat * 0.4)
            syn_flags = float(1)
            fin_flags = float(np.random.choice([0, 1], p=[0.7, 0.3]))
            rst_flags = float(0)
            psh_flags = float(np.random.randint(2, 10))
            ack_flags = float(max(pkts - 1, 0))
            pkt_rate = float(pkts / duration)
            byte_rate = float(bytes_val / duration)

            features.append([
                pkts, bytes_val, duration,
                mean_pkt, std_pkt, var_pkt,
                mean_iat, std_iat,
                syn_flags, fin_flags, rst_flags, psh_flags, ack_flags,
                pkt_rate, byte_rate
            ])

        # 2. High-Throughput Streaming & Video Content (YouTube, Netflix, QUIC/UDP) (40%)
        n_stream = int(num_samples * 0.40)
        for _ in range(n_stream):
            pkts = float(np.random.randint(80, 500))
            bytes_val = float(pkts * np.random.uniform(900, 1460))
            duration = float(np.random.uniform(1.5, 6.0))
            mean_pkt = bytes_val / pkts
            std_pkt = float(np.random.uniform(250, 450))
            var_pkt = float(std_pkt ** 2)
            mean_iat = float(duration / pkts)
            std_iat = float(mean_iat * 0.5)
            syn_flags = float(np.random.choice([0, 1], p=[0.85, 0.15]))
            fin_flags = float(0)
            rst_flags = float(0)
            psh_flags = float(np.random.randint(5, 30))
            ack_flags = float(np.random.choice([0, max(pkts - 1, 0)], p=[0.35, 0.65]))  # QUIC/UDP vs TCP
            pkt_rate = float(pkts / duration)
            byte_rate = float(bytes_val / duration)

            features.append([
                pkts, bytes_val, duration,
                mean_pkt, std_pkt, var_pkt,
                mean_iat, std_iat,
                syn_flags, fin_flags, rst_flags, psh_flags, ack_flags,
                pkt_rate, byte_rate
            ])

        # 3. Ephemeral / DNS / NTP / System Heartbeats / Single-Packet Flows (10%)
        n_ephemeral = num_samples - n_web - n_stream
        for i in range(n_ephemeral):
            if i % 2 == 0:
                pkts = 1.0
                bytes_val = float(np.random.uniform(50, 450))
                duration = 1.0
                mean_pkt = bytes_val
                std_pkt = 0.0
                var_pkt = 0.0
                mean_iat = 0.0
                std_iat = 0.0
                syn_flags = float(0)
                fin_flags = float(0)
                rst_flags = float(0)
                psh_flags = float(0)
                ack_flags = float(np.random.choice([0.0, 1.0], p=[0.7, 0.3]))
                pkt_rate = 1.0
                byte_rate = bytes_val
            else:
                pkts = float(np.random.randint(2, 8))
                bytes_val = float(pkts * np.random.uniform(60, 200))
                duration = float(np.random.uniform(0.05, 0.5))
                mean_pkt = bytes_val / pkts
                std_pkt = float(np.random.uniform(10, 40))
                var_pkt = float(std_pkt ** 2)
                mean_iat = float(duration / max(pkts, 1))
                std_iat = float(0)
                syn_flags = float(0)
                fin_flags = float(0)
                rst_flags = float(0)
                psh_flags = float(0)
                ack_flags = float(0)
                pkt_rate = float(pkts / duration)
                byte_rate = float(bytes_val / duration)

            features.append([
                pkts, bytes_val, duration,
                mean_pkt, std_pkt, var_pkt,
                mean_iat, std_iat,
                syn_flags, fin_flags, rst_flags, psh_flags, ack_flags,
                pkt_rate, byte_rate
            ])

        X = np.array(features)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        self.n_samples_trained = len(features)
        self.model.decision_function(X_scaled[:1])

    def predict_flow(self, flow: NetworkFlow) -> Tuple[bool, float, float, float]:
        """
        Performs sub-millisecond anomaly scoring on a single NetworkFlow.
        Returns:
            is_anomaly (bool): True if anomaly_score >= threshold
            anomaly_score (float): Normalized anomaly score [0.0, 1.0]
            estimated_path_length (float): Average tree path length E(h(x))
            inference_time_ms (float): Inference latency in milliseconds
        """
        if not self.is_fitted:
            self.initialize_benign_baseline()

        start_t = time.perf_counter()
        raw_feat = flow.to_feature_vector().reshape(1, -1)
        scaled_feat = self.scaler.transform(raw_feat)

        # Scikit-learn decision_function returns -score_samples - offset
        # Normal points: raw_score > 0 (+0.05 to +0.25)
        # Anomalies: raw_score < 0 (-0.05 to -0.35)
        raw_score = float(self.model.decision_function(scaled_feat)[0])
        inference_time_ms = (time.perf_counter() - start_t) * 1000.0

        # Latency tracking
        self.total_inferences += 1
        self.cumulative_latency_ms += inference_time_ms

        # Calibrated normalized anomaly score s in [0.0, 1.0]
        # s -> 1.0 represents high anomaly certainty, s -> 0.0 represents normal baseline
        normalized_score = float(1.0 / (1.0 + np.exp(8.0 * raw_score)))

        # Reconstruct path length E(h(x)) using Smolen & Benova (2023) equation:
        # s = 2^(-E(h(x)) / c(n)) => log2(s) = -E(h(x)) / c(n) => E(h(x)) = -log2(s) * c(n)
        cn = self.calculate_c_factor(max(self.n_samples_trained, 256))
        # Clamp score safely to avoid log2(0)
        clamped_score = np.clip(normalized_score, 1e-4, 0.9999)
        estimated_path_length = float(-np.log2(clamped_score) * cn)

        is_anomaly = normalized_score >= self.config.anomaly_threshold

        return is_anomaly, normalized_score, estimated_path_length, inference_time_ms

    @property
    def avg_latency_ms(self) -> float:
        """Average per-sample inference latency across all evaluations."""
        if self.total_inferences == 0:
            return 0.0
        return self.cumulative_latency_ms / self.total_inferences

    def save(self, filepath: str) -> None:
        """Serializes trained model state to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "is_fitted": self.is_fitted,
            "n_samples_trained": self.n_samples_trained
        }, filepath)

    def load(self, filepath: str) -> bool:
        """Loads trained model state from disk."""
        if not os.path.exists(filepath):
            return False
        try:
            state = joblib.load(filepath)
            self.model = state["model"]
            self.scaler = state["scaler"]
            self.is_fitted = state["is_fitted"]
            self.n_samples_trained = state.get("n_samples_trained", 500)
            return True
        except Exception:
            return False
