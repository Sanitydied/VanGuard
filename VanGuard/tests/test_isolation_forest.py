"""
Unit tests for Phase 1 Isolation Forest Anomaly Scoring (Smolen & Benova, 2023).
"""

import os
import unittest
from agentndr.isolation_forest import IsolationForestDetector
from agentndr.traffic_generator import TrafficGenerator, AttackCategory

class TestIsolationForest(unittest.TestCase):
    def setUp(self):
        self.detector = IsolationForestDetector()
        self.detector.initialize_benign_baseline(num_samples=250)

    def test_c_factor_math(self):
        c256 = self.detector.calculate_c_factor(256)
        self.assertGreater(c256, 8.0)
        self.assertLess(c256, 12.0)

    def test_benign_flow_prediction(self):
        flow = TrafficGenerator.generate_flow(AttackCategory.BENIGN)
        self.detector.predict_flow(flow)
        is_ano, score, path_len, lat_ms = self.detector.predict_flow(flow)

        self.assertLess(score, 0.65)
        self.assertLess(lat_ms, 100.0)
        self.assertGreater(path_len, 0.0)

    def test_attack_flow_prediction(self):
        attacks = [
            AttackCategory.PORT_SCAN,
            AttackCategory.SYN_FLOOD,
            AttackCategory.EXFILTRATION
        ]
        for att in attacks:
            flow = TrafficGenerator.generate_flow(att)
            is_ano, score, path_len, lat_ms = self.detector.predict_flow(flow)
            self.assertGreaterEqual(score, 0.60, f"Attack {att.value} score was {score}")

    def test_model_save_and_load(self):
        tmp_path = os.path.join(os.path.dirname(__file__), "test_iforest.joblib")
        try:
            self.detector.save(tmp_path)
            self.assertTrue(os.path.exists(tmp_path))

            new_detector = IsolationForestDetector()
            loaded = new_detector.load(tmp_path)
            self.assertTrue(loaded)
            self.assertTrue(new_detector.is_fitted)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
