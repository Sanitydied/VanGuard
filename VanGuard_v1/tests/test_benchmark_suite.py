"""
Unit tests for Phase 1 Benchmark Suite (Smolen & Benova, 2023).
"""

import unittest
from agentndr.isolation_forest import IsolationForestDetector
from agentndr.benchmark_suite import Phase1BenchmarkSuite

class TestBenchmarkSuite(unittest.TestCase):
    def setUp(self):
        self.detector = IsolationForestDetector()
        self.suite = Phase1BenchmarkSuite(self.detector)

    def test_comparative_benchmark(self):
        results = self.suite.run_comparative_benchmark(n_benign=40, n_attack=15)
        self.assertIn("isolation_forest", results)
        self.assertIn("autoencoder", results)

        if_res = results["isolation_forest"]
        self.assertIn("avg_inference_latency_ms", if_res)
        self.assertIn("precision", if_res)
        self.assertIn("recall", if_res)
        self.assertIn("f1_score", if_res)
        self.assertIn("false_positive_rate", if_res)
        self.assertLess(if_res["avg_inference_latency_ms"], 15.0)

if __name__ == "__main__":
    unittest.main()
