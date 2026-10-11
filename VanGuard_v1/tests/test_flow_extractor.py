"""
Unit tests for Phase 1 Flow Extractor (Sarhan et al., 2022).
"""

import unittest
import time
from agentndr.flow_extractor import FlowExtractor, PacketRecord

class TestFlowExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FlowExtractor()

    def test_canonical_flow_key_bidirectional(self):
        k1 = FlowExtractor.get_canonical_flow_key("192.168.1.1", 5000, "10.0.0.1", 80, "TCP")
        k2 = FlowExtractor.get_canonical_flow_key("10.0.0.1", 80, "192.168.1.1", 5000, "TCP")
        self.assertEqual(k1, k2, "Canonical flow keys must match bidirectionally")

    def test_statistical_moments_calculation(self):
        t0 = time.time()
        for i in range(10):
            p = PacketRecord(
                timestamp=t0 + (i * 0.1),
                length=100 + (i * 10),
                src_ip="192.168.1.10",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                tcp_flags={"SYN": (i == 0), "ACK": (i > 0)}
            )
            self.extractor.ingest_packet(p)

        flows = self.extractor.flush_flows(force_all=True)
        self.assertEqual(len(flows), 1)
        f = flows[0]
        self.assertEqual(f.packet_count, 10)
        self.assertEqual(f.syn_flag_count, 1)
        self.assertEqual(f.ack_flag_count, 9)
        self.assertAlmostEqual(f.mean_iat, 0.1, places=2)
        self.assertGreater(f.byte_count, 1000)

        vec = f.to_feature_vector()
        self.assertEqual(len(vec), 15)

if __name__ == "__main__":
    unittest.main()
