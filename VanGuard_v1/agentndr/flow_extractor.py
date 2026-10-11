"""
Sliding-Window Statistical Flow Feature Extractor (Phase 1).
Implements the 15 standardized statistical flow features from Sarhan et al. (2022)
to capture volumetric and stealth attacks across encrypted (TLS/HTTPS) channels.
"""

import time
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from .config import DEFAULT_CONFIG, FlowExtractionConfig
from .service_resolver import GLOBAL_RESOLVER

@dataclass
class PacketRecord:
    """Represents a captured transport-layer packet header without payload inspection."""
    timestamp: float
    length: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    tcp_flags: Dict[str, bool] = field(default_factory=dict)

@dataclass
class NetworkFlow:
    """
    Standardized 5-Tuple Network Flow representation.
    Maintains statistical moments calculated over sliding window delta_t.
    """
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    start_time: float
    end_time: float
    packet_count: int
    byte_count: int
    duration: float
    mean_packet_size: float
    std_packet_size: float
    var_packet_size: float
    mean_iat: float  # Packet Inter-Arrival Time (seconds)
    std_iat: float
    syn_flag_count: int
    fin_flag_count: int
    rst_flag_count: int
    psh_flag_count: int
    ack_flag_count: int
    packet_rate: float
    byte_rate: float
    raw_packets: List[PacketRecord] = field(default_factory=list, repr=False)

    def to_feature_vector(self, feature_names: Optional[List[str]] = None) -> np.ndarray:
        """Converts flow statistical moments into a 1D numerical NumPy vector for Isolation Forest."""
        if feature_names is None:
            feature_names = DEFAULT_CONFIG.flow.feature_names
        
        values = [getattr(self, name, 0.0) for name in feature_names]
        return np.array(values, dtype=np.float64)

    def to_dict(self) -> Dict[str, Any]:
        """Dictionary serialization for JSON export and Streamlit display."""
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration": round(self.duration, 4),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "mean_packet_size": round(self.mean_packet_size, 2),
            "std_packet_size": round(self.std_packet_size, 2),
            "var_packet_size": round(self.var_packet_size, 2),
            "mean_iat": round(self.mean_iat, 6),
            "std_iat": round(self.std_iat, 6),
            "syn_flag_count": self.syn_flag_count,
            "fin_flag_count": self.fin_flag_count,
            "rst_flag_count": self.rst_flag_count,
            "psh_flag_count": self.psh_flag_count,
            "ack_flag_count": self.ack_flag_count,
            "packet_rate": round(self.packet_rate, 2),
            "byte_rate": round(self.byte_rate, 2)
        }

class FlowExtractor:
    """
    Maintains sliding-window time buckets and extracts standardized statistical flow features.
    """
    def __init__(self, config: Optional[FlowExtractionConfig] = None):
        self.config = config or DEFAULT_CONFIG.flow
        self.active_flow_buckets: Dict[str, List[PacketRecord]] = {}
        self.last_sweep_time = time.time()

    @staticmethod
    def get_canonical_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> str:
        """Constructs bidirectional canonical 5-tuple key."""
        ep_a = (src_ip, src_port)
        ep_b = (dst_ip, dst_port)
        if ep_a <= ep_b:
            return f"{protocol}:{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
        return f"{protocol}:{dst_ip}:{dst_port}<->{src_ip}:{src_port}"

    def ingest_packet(self, packet: PacketRecord) -> None:
        """Ingests a transport packet record into the sliding window bucket."""
        key = self.get_canonical_flow_key(
            packet.src_ip, packet.src_port,
            packet.dst_ip, packet.dst_port,
            packet.protocol
        )
        if key not in self.active_flow_buckets:
            self.active_flow_buckets[key] = []
        
        self.active_flow_buckets[key].append(packet)

    def ingest_scapy_packet(self, scapy_pkt: Any) -> Optional[PacketRecord]:
        """Extracts PacketRecord from a Scapy packet object without payload inspection."""
        try:
            # Passive DNS learning without payload inspection overhead
            if scapy_pkt.haslayer("DNS"):
                GLOBAL_RESOLVER.process_scapy_dns_packet(scapy_pkt)

            if scapy_pkt.haslayer("IP"):
                ip_layer = scapy_pkt.getlayer("IP")
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
            elif scapy_pkt.haslayer("IPv6"):
                ip_layer = scapy_pkt.getlayer("IPv6")
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
            else:
                return None
            
            pkt_len = len(scapy_pkt)
            pkt_time = float(scapy_pkt.time) if hasattr(scapy_pkt, "time") else time.time()

            src_port = 0
            dst_port = 0
            protocol = "IP"
            flags = {}

            if scapy_pkt.haslayer("TCP"):
                protocol = "TCP"
                tcp_layer = scapy_pkt.getlayer("TCP")
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                f = str(tcp_layer.flags)
                flags = {
                    "SYN": "S" in f,
                    "FIN": "F" in f,
                    "RST": "R" in f,
                    "PSH": "P" in f,
                    "ACK": "A" in f,
                    "URG": "U" in f
                }
            elif scapy_pkt.haslayer("UDP"):
                protocol = "UDP"
                udp_layer = scapy_pkt.getlayer("UDP")
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
            elif scapy_pkt.haslayer("ICMP"):
                protocol = "ICMP"

            record = PacketRecord(
                timestamp=pkt_time,
                length=pkt_len,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                tcp_flags=flags
            )
            self.ingest_packet(record)
            return record
        except Exception:
            return None

    def flush_flows(self, force_all: bool = False) -> List[NetworkFlow]:
        """
        Calculates statistical moments across flow buckets.
        Flushes buckets exceeding window_duration_sec or idle_timeout.
        """
        now = time.time()
        completed_flows: List[NetworkFlow] = []
        keys_to_remove = []

        for key, packets in self.active_flow_buckets.items():
            if not packets:
                keys_to_remove.append(key)
                continue

            duration = packets[-1].timestamp - packets[0].timestamp
            idle_time = now - packets[-1].timestamp

            if force_all or duration >= self.config.window_duration_sec or idle_time >= self.config.idle_timeout_sec:
                flow = self._compute_moments(key, packets)
                completed_flows.append(flow)
                keys_to_remove.append(key)

        for k in keys_to_remove:
            del self.active_flow_buckets[k]

        return completed_flows

    def _compute_moments(self, flow_key: str, packets: List[PacketRecord]) -> NetworkFlow:
        """
        Computes the 15 statistical flow moments as formalized in Sarhan et al. (2022).
        """
        first = packets[0]
        last = packets[-1]
        start_time = first.timestamp
        end_time = last.timestamp
        raw_duration = max(end_time - start_time, 0.0)

        packet_count = len(packets)
        lengths = np.array([p.length for p in packets], dtype=np.float64)
        byte_count = int(np.sum(lengths))
        mean_packet_size = float(np.mean(lengths))
        std_packet_size = float(np.std(lengths))
        var_packet_size = float(np.var(lengths))

        # Inter-Arrival Time (IAT)
        if packet_count > 1:
            timestamps = np.array([p.timestamp for p in packets], dtype=np.float64)
            iats = np.diff(timestamps)
            iats = np.maximum(iats, 0.0)  # eliminate negative clock skew
            mean_iat = float(np.mean(iats))
            std_iat = float(np.std(iats))
        else:
            mean_iat = 0.0
            std_iat = 0.0

        # TCP Flag distributions
        syn_count = sum(1 for p in packets if p.tcp_flags.get("SYN", False))
        fin_count = sum(1 for p in packets if p.tcp_flags.get("FIN", False))
        rst_count = sum(1 for p in packets if p.tcp_flags.get("RST", False))
        psh_count = sum(1 for p in packets if p.tcp_flags.get("PSH", False))
        ack_count = sum(1 for p in packets if p.tcp_flags.get("ACK", False))

        # Realistic rate & duration calculations (preventing false-positive rate surges)
        if packet_count <= 1 or raw_duration <= 0.0001:
            if packet_count <= 1:
                duration = 1.0
                packet_rate = 1.0
                byte_rate = float(byte_count)
            else:
                # packet_count > 1 and duration is near-zero (clamp to 1 ms instead of infinitesimal epsilon)
                duration = 0.001
                packet_rate = float(packet_count / duration)
                byte_rate = float(byte_count / duration)
        else:
            duration = raw_duration
            packet_rate = float(packet_count / duration)
            byte_rate = float(byte_count / duration)

        return NetworkFlow(
            flow_id=flow_key,
            src_ip=first.src_ip,
            src_port=first.src_port,
            dst_ip=first.dst_ip,
            dst_port=first.dst_port,
            protocol=first.protocol,
            start_time=start_time,
            end_time=end_time,
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            mean_packet_size=mean_packet_size,
            std_packet_size=std_packet_size,
            var_packet_size=var_packet_size,
            mean_iat=mean_iat,
            std_iat=std_iat,
            syn_flag_count=syn_count,
            fin_flag_count=fin_count,
            rst_flag_count=rst_count,
            psh_flag_count=psh_count,
            ack_flag_count=ack_count,
            packet_rate=packet_rate,
            byte_rate=byte_rate,
            raw_packets=packets
        )
