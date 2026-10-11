"""
PCAP Capture File Reader (Phase 1).
Parses standard .pcap / .pcapng network packet traces using Scapy
and streams packets into the sliding-window FlowExtractor.
"""

import os
from typing import List, Optional, Callable
from .flow_extractor import FlowExtractor, NetworkFlow

class PCAPReader:
    """Ingests raw packet capture files and yields completed NetworkFlow objects."""

    @staticmethod
    def process_pcap(
        pcap_filepath: str,
        extractor: Optional[FlowExtractor] = None,
        callback: Optional[Callable[[NetworkFlow], None]] = None
    ) -> List[NetworkFlow]:
        """
        Reads a PCAP file and returns extracted NetworkFlow instances.
        If callback is provided, invokes callback for every completed flow.
        """
        if not os.path.exists(pcap_filepath):
            raise FileNotFoundError(f"PCAP file not found: {pcap_filepath}")

        # Lazy import Scapy's rdpcap
        try:
            from scapy.utils import PcapReader
        except ImportError:
            raise ImportError("Scapy is required to read PCAP files. Install via pip install scapy.")

        ext = extractor or FlowExtractor()
        completed_flows: List[NetworkFlow] = []

        with PcapReader(pcap_filepath) as pcap_reader:
            for pkt in pcap_reader:
                ext.ingest_scapy_packet(pkt)
                new_flows = ext.flush_flows(force_all=False)
                for f in new_flows:
                    completed_flows.append(f)
                    if callback:
                        callback(f)

        # Flush any remaining packets
        final_flows = ext.flush_flows(force_all=True)
        for f in final_flows:
            completed_flows.append(f)
            if callback:
                callback(f)

        return completed_flows
