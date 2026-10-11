"""
PCAP File Ingestion & Real Network Capture Processor (Phase 1).
Parses real-world Wireshark (.pcap / .pcapng) capture files,
reconstructs 5-tuple conversations, and extracts the 15 statistical flow moments.
"""

import io
import os
import tempfile
from typing import List, Union, Optional
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from .flow_extractor import FlowExtractor, NetworkFlow

class PCAPLoader:
    """Processes real PCAP/PCAPNG network capture files into statistical NetworkFlow objects."""

    def __init__(self, extractor: Optional[FlowExtractor] = None):
        self.extractor = extractor or FlowExtractor()

    def load_packets_from_bytes(self, pcap_bytes: bytes) -> List[NetworkFlow]:
        """Loads and processes packets directly from in-memory byte buffer (e.g. Streamlit uploader)."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(pcap_bytes)
            tmp_path = tmp.name

        try:
            return self.load_pcap_file(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def load_pcap_file(self, file_path: str) -> List[NetworkFlow]:
        """Reads a .pcap file on disk and extracts completed network flows."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        packets = scapy.rdpcap(file_path)
        for pkt in packets:
            self.extractor.ingest_scapy_packet(pkt)

        # Flush all extracted flows
        flows = self.extractor.flush_flows(force_all=True)
        return flows

    @staticmethod
    def generate_sample_pcap(output_path: str) -> str:
        """
        Synthesizes a real, valid .pcap file with actual Layer 3/4 headers
        demonstrating real-world benign browsing and a simulated port scan probe.
        """
        pkts = []
        base_time = 1700000000.0

        # Benign HTTPS session (Client 192.168.1.50 -> Server 142.250.190.46)
        # 1. SYN
        pkts.append(IP(src="192.168.1.50", dst="142.250.190.46")/TCP(sport=51234, dport=443, flags="S", seq=100))
        pkts[-1].time = base_time

        # 2. SYN-ACK
        pkts.append(IP(src="142.250.190.46", dst="192.168.1.50")/TCP(sport=443, dport=51234, flags="SA", seq=500, ack=101))
        pkts[-1].time = base_time + 0.02

        # 3. ACK
        pkts.append(IP(src="192.168.1.50", dst="142.250.190.46")/TCP(sport=51234, dport=443, flags="A", seq=101, ack=501))
        pkts[-1].time = base_time + 0.03

        # 4. TLS Client Hello (Push data)
        pkts.append(IP(src="192.168.1.50", dst="142.250.190.46")/TCP(sport=51234, dport=443, flags="PA", seq=101, ack=501)/(b"\x16\x03\x01\x00" + b"\x00" * 450))
        pkts[-1].time = base_time + 0.05

        # 5. Server Response
        pkts.append(IP(src="142.250.190.46", dst="192.168.1.50")/TCP(sport=443, dport=51234, flags="PA", seq=501, ack=555)/(b"\x16\x03\x03\x00" + b"\x00" * 980))
        pkts[-1].time = base_time + 0.10

        # Port Scan probes (Attacker 10.0.0.99 -> Target 192.168.1.10)
        target_ports = [21, 22, 23, 25, 80, 443, 8080, 8443, 3389, 445]
        for idx, port in enumerate(target_ports):
            scan_pkt = IP(src="10.0.0.99", dst="192.168.1.10")/TCP(sport=60000 + idx, dport=port, flags="S", seq=1000 + idx)
            scan_pkt.time = base_time + 0.5 + (idx * 0.01)
            pkts.append(scan_pkt)

        scapy.wrpcap(output_path, pkts)
        return output_path

