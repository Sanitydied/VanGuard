"""
Unit tests for Phase 1 Traffic Generator.
"""

import unittest
from agentndr.traffic_generator import TrafficGenerator, AttackCategory

class TestTrafficGenerator(unittest.TestCase):
    def test_generate_all_categories(self):
        for cat in AttackCategory:
            flow = TrafficGenerator.generate_flow(cat)
            self.assertEqual(len(flow.to_feature_vector()), 15)
            self.assertGreater(flow.packet_count, 0)
            self.assertGreater(flow.byte_count, 0)
            self.assertGreater(flow.duration, 0)

    def test_batch_generation(self):
        flows, labels = TrafficGenerator.generate_batch(n_benign=20, n_attack=10)
        self.assertEqual(len(flows), 30)
        self.assertEqual(len(labels), 30)
        self.assertEqual(labels.count(0), 20)
        self.assertEqual(labels.count(1), 10)

    def test_generate_live_sample(self):
        flow_benign, cat_benign = TrafficGenerator.generate_live_sample(attack_probability=0.0)
        self.assertEqual(cat_benign, AttackCategory.BENIGN)
        self.assertEqual(len(flow_benign.to_feature_vector()), 15)

        flow_forced, cat_forced = TrafficGenerator.generate_live_sample(specific_category=AttackCategory.PORT_SCAN)
        self.assertEqual(cat_forced, AttackCategory.PORT_SCAN)
        self.assertEqual(len(flow_forced.to_feature_vector()), 15)

if __name__ == "__main__":
    unittest.main()
