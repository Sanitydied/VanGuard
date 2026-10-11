"""
Network Traffic & Attack Flow Generator (Phase 1).
Synthesizes benchmark traffic distributions aligned with CICIDS2017 and UNSW-NB15
to validate the statistical feature extractor and Isolation Forest.
"""

import time
import enum
import random
import numpy as np
from typing import List, Optional, Tuple
from .flow_extractor import NetworkFlow, PacketRecord

class AttackCategory(enum.Enum):
    BENIGN = "Benign HTTPS Enterprise Traffic"
    PORT_SCAN = "Port Scan / Service Discovery (T1046)"
    SYN_FLOOD = "Volumetric SYN Flood DoS (T1498)"
    EXFILTRATION = "Data Exfiltration Burst (T1041)"
    STEALTH_C2 = "Stealthy Low-Rate Beaconing (T1071)"

class TrafficGenerator:
    """Generates synthetic network flows with realistic statistical signatures."""

    @staticmethod
    def generate_flow(
        category: AttackCategory,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None
    ) -> NetworkFlow:
        """Constructs a NetworkFlow object matching the statistical profile of the selected category."""
        now = time.time()

        if category == AttackCategory.BENIGN:
            src_ip = src_ip or "192.168.1.105"
            # High-volume benign destination: YouTube/Google, WhatsApp/Meta, or Cloudflare CDN
            dst_ip = dst_ip or random.choice(["142.250.190.46", "157.240.22.53", "104.16.132.229"])
            src_port = src_port or random.randint(49152, 65535)
            dst_port = dst_port or 443
            packet_count = random.randint(25, 90)
            duration = random.uniform(1.2, 5.0)
            byte_count = int(packet_count * random.uniform(450, 1100))
            lengths = np.random.normal(byte_count / packet_count, 220, packet_count).clip(64, 1500)
            mean_packet_size = float(np.mean(lengths))
            std_packet_size = float(np.std(lengths))
            var_packet_size = float(std_packet_size ** 2)
            mean_iat = float(duration / packet_count)
            std_iat = float(mean_iat * 0.4)
            syn_flags = 1
            ack_flags = packet_count - 1
            rst_flags = 0
            fin_flags = 1
            psh_flags = random.randint(2, 8)

        elif category == AttackCategory.PORT_SCAN:
            src_ip = src_ip or "192.168.1.45"
            dst_ip = dst_ip or "192.168.1.1"
            src_port = src_port or random.randint(49152, 65535)
            dst_port = dst_port or random.randint(20, 1024)
            packet_count = random.randint(80, 250)
            duration = random.uniform(0.1, 0.5)  # Extremely rapid probes
            byte_count = packet_count * 64      # Small probe headers
            lengths = np.full(packet_count, 64.0)
            mean_packet_size = 64.0
            std_packet_size = 0.0
            var_packet_size = 0.0
            mean_iat = float(duration / packet_count)
            std_iat = float(mean_iat * 0.05)
            syn_flags = packet_count
            ack_flags = 0                       # Unanswered SYNs
            rst_flags = random.randint(10, 40)
            fin_flags = 0
            psh_flags = 0

        elif category == AttackCategory.SYN_FLOOD:
            src_ip = src_ip or "198.51.100.22"
            dst_ip = dst_ip or "192.168.1.100"
            src_port = src_port or random.randint(49152, 65535)
            dst_port = dst_port or 80
            packet_count = random.randint(500, 2000)
            duration = random.uniform(0.3, 1.0)
            byte_count = packet_count * 54
            lengths = np.full(packet_count, 54.0)
            mean_packet_size = 54.0
            std_packet_size = 0.0
            var_packet_size = 0.0
            mean_iat = float(duration / packet_count)
            std_iat = float(mean_iat * 0.01)
            syn_flags = packet_count
            ack_flags = 0
            rst_flags = 0
            fin_flags = 0
            psh_flags = 0

        elif category == AttackCategory.EXFILTRATION:
            src_ip = src_ip or "192.168.1.105"
            dst_ip = dst_ip or "185.220.101.5"
            src_port = src_port or random.randint(49152, 65535)
            dst_port = dst_port or 8443
            packet_count = random.randint(600, 1500)
            duration = random.uniform(1.5, 4.0)
            # Massive burst of large MTU frames (megabytes)
            lengths = np.random.normal(1460, 20, packet_count).clip(1350, 1514)
            byte_count = int(np.sum(lengths))
            mean_packet_size = float(np.mean(lengths))
            std_packet_size = float(np.std(lengths))
            var_packet_size = float(std_packet_size ** 2)
            mean_iat = float(duration / packet_count)
            std_iat = float(mean_iat * 0.9)
            syn_flags = 1
            ack_flags = packet_count - 1
            rst_flags = 0
            fin_flags = 0
            psh_flags = int(packet_count * 0.9)

        else: # STEALTH_C2
            src_ip = src_ip or "192.168.1.105"
            dst_ip = dst_ip or "91.108.4.1"
            src_port = src_port or random.randint(49152, 65535)
            dst_port = dst_port or 4444
            packet_count = random.randint(10, 20)
            duration = random.uniform(30.0, 60.0)
            lengths = np.random.uniform(90, 180, packet_count)
            byte_count = int(np.sum(lengths))
            mean_packet_size = float(np.mean(lengths))
            std_packet_size = float(np.std(lengths))
            var_packet_size = float(std_packet_size ** 2)
            mean_iat = float(duration / packet_count)
            std_iat = 0.0005  # Near zero jitter: periodic beaconing
            syn_flags = 1
            ack_flags = packet_count - 1
            rst_flags = 0
            fin_flags = 0
            psh_flags = int(packet_count * 0.8)

        packet_rate = float(packet_count / duration)
        byte_rate = float(byte_count / duration)

        flow_key = f"TCP:{src_ip}:{src_port}<->{dst_ip}:{dst_port}"

        return NetworkFlow(
            flow_id=flow_key,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="TCP",
            start_time=now - duration,
            end_time=now,
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            mean_packet_size=mean_packet_size,
            std_packet_size=std_packet_size,
            var_packet_size=var_packet_size,
            mean_iat=mean_iat,
            std_iat=std_iat,
            syn_flag_count=syn_flags,
            fin_flag_count=fin_flags,
            rst_flag_count=rst_flags,
            psh_flag_count=psh_flags,
            ack_flag_count=ack_flags,
            packet_rate=packet_rate,
            byte_rate=byte_rate
        )

    @classmethod
    def generate_batch(cls, n_benign: int = 100, n_attack: int = 25) -> Tuple[List[NetworkFlow], List[int]]:
        """
        Generates a balanced evaluation batch.
        Returns:
            flows: list of NetworkFlow
            labels: 0 for benign, 1 for attack
        """
        flows = []
        labels = []

        for _ in range(n_benign):
            flows.append(cls.generate_flow(AttackCategory.BENIGN))
            labels.append(0)

        attack_types = [
            AttackCategory.PORT_SCAN,
            AttackCategory.SYN_FLOOD,
            AttackCategory.EXFILTRATION,
            AttackCategory.STEALTH_C2
        ]
        for i in range(n_attack):
            att = attack_types[i % len(attack_types)]
            flows.append(cls.generate_flow(att))
            labels.append(1)

        return flows, labels

    @classmethod
    def generate_live_sample(
        cls,
        attack_probability: float = 0.3,
        specific_category: Optional[AttackCategory] = None
    ) -> Tuple[NetworkFlow, AttackCategory]:
        """
        Generates a single flow for real-time live network monitoring.
        Simulates enterprise background traffic with probabilistic threat events.
        """
        if specific_category is not None:
            cat = specific_category
        elif random.random() < attack_probability:
            cat = random.choice([
                AttackCategory.PORT_SCAN,
                AttackCategory.SYN_FLOOD,
                AttackCategory.EXFILTRATION,
                AttackCategory.STEALTH_C2
            ])
        else:
            cat = AttackCategory.BENIGN

        return cls.generate_flow(cat), cat
