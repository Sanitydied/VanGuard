"""
Unit tests for PCAPLoader and LivePacketSniffer (Phase 1 Real Traffic Ingestion).
"""

import os
import unittest
import tempfile
from agentndr.flow_extractor import FlowExtractor, NetworkFlow
from agentndr.pcap_loader import PCAPLoader
from agentndr.live_sniffer import LivePacketSniffer

class TestRealTrafficIngestion(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.pcap_path = os.path.join(self.tmp_dir, "test_capture.pcap")

    def tearDown(self):
        if os.path.exists(self.pcap_path):
            os.remove(self.pcap_path)
        if os.path.exists(self.tmp_dir):
            os.rmdir(self.tmp_dir)

    def test_pcap_generation_and_loading(self):
        # 1. Generate valid sample PCAP
        PCAPLoader.generate_sample_pcap(self.pcap_path)
        self.assertTrue(os.path.exists(self.pcap_path))
        self.assertGreater(os.path.getsize(self.pcap_path), 0)

        # 2. Load and extract flows
        loader = PCAPLoader()
        flows = loader.load_pcap_file(self.pcap_path)
        self.assertIsInstance(flows, list)
        self.assertGreater(len(flows), 0)

        # 3. Verify statistical moments on real flow
        first_flow = flows[0]
        self.assertIsInstance(first_flow, NetworkFlow)
        self.assertGreater(first_flow.packet_count, 0)
        self.assertGreater(first_flow.byte_count, 0)
        vec = first_flow.to_feature_vector()
        self.assertEqual(len(vec), 15)

    def test_pcap_bytes_loading(self):
        PCAPLoader.generate_sample_pcap(self.pcap_path)
        with open(self.pcap_path, "rb") as f:
            data = f.read()

        loader = PCAPLoader()
        flows = loader.load_packets_from_bytes(data)
        self.assertIsInstance(flows, list)
        self.assertGreater(len(flows), 0)

    def test_live_sniffer_interface_discovery(self):
        ifaces = LivePacketSniffer.get_network_interfaces()
        self.assertIsInstance(ifaces, list)
        # Check structure
        if len(ifaces) > 0:
            self.assertIn("name", ifaces[0])
            self.assertIn("description", ifaces[0])

    def test_live_sniffer_pcap_check(self):
        available = LivePacketSniffer.is_pcap_available()
        self.assertIsInstance(available, bool)

if __name__ == "__main__":
    unittest.main()

