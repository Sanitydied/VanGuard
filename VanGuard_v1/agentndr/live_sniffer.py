"""
Live Network Packet Sniffer (Phase 1).
Captures real-time packets from physical network adapters (Wi-Fi / Ethernet),
feeds them into FlowExtractor, and provides live 5-tuple flow statistical moments.
"""

import os
import sys
import time
import threading
from typing import List, Dict, Any, Optional
import scapy.all as scapy
from .flow_extractor import FlowExtractor, NetworkFlow

class LivePacketSniffer:
    """Manages background real-time packet sniffing from active host network adapters."""

    def __init__(self, extractor: Optional[FlowExtractor] = None):
        self.extractor = extractor or FlowExtractor()
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.selected_iface: Optional[str] = None
        self.last_error: Optional[str] = None
        self.packets_captured: int = 0
        self._flow_cache: List[NetworkFlow] = []
        self._lock = threading.Lock()

    @staticmethod
    def is_pcap_available() -> bool:
        """Checks if Npcap or WinPcap driver is installed on the host system."""
        if hasattr(scapy.conf, "use_pcap") and scapy.conf.use_pcap:
            return True
        # Check standard Windows Npcap / WinPcap installation locations
        npcap_paths = [
            r"C:\Windows\System32\wpcap.dll",
            r"C:\Windows\System32\Npcap\wpcap.dll",
            r"C:\Windows\SysWOW64\wpcap.dll",
            r"C:\Windows\SysWOW64\Npcap\wpcap.dll"
        ]
        return any(os.path.exists(p) for p in npcap_paths)

    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        """Returns clean list strictly containing physical Wi-Fi and Ethernet adapters."""
        interfaces = []
        try:
            from scapy.all import conf
            for iface in conf.ifaces.values():
                name = str(getattr(iface, "name", "")).strip()
                desc = str(getattr(iface, "description", "")).strip()
                combined = (name + " " + desc).lower()

                # Filter out virtual, tunnel, bluetooth, loopback, miniport, and sharing devices
                skip_keywords = [
                    "virtual", "direct", "wan", "miniport", "bluetooth",
                    "loopback", "pseudo", "ndis", "sharing", "teredo",
                    "filter", "scheduler", "kernel", "https", "6to4", "debug"
                ]
                if any(k in combined for k in skip_keywords):
                    continue

                # Strictly match physical Wi-Fi or Ethernet
                is_wifi = any(k in combined for k in ["wi-fi", "wifi", "wireless", "wlan", "802.11"])
                is_ethernet = any(k in combined for k in ["ethernet", "gbe", "lan", "pcie"])

                if not (is_wifi or is_ethernet):
                    continue

                ip = str(getattr(iface, "ip", "")).strip()
                dev_name = getattr(iface, "network_name", name)

                prefix = "Wi-Fi" if is_wifi else "Ethernet"
                clean_desc = desc if desc and desc != name else name
                if ip and not ip.startswith("169.254.") and ip != "127.0.0.1":
                    display_label = f"[{prefix}] {clean_desc} ({ip}) [Connected]"
                    has_ip = True
                else:
                    display_label = f"[{prefix}] {clean_desc} [Disconnected - No Cable]"
                    has_ip = False

                interfaces.append({
                    "name": name,
                    "description": clean_desc,
                    "display": display_label,
                    "dev_name": dev_name,
                    "iface_obj": iface,
                    "ip": ip,
                    "is_wifi": is_wifi,
                    "has_ip": has_ip
                })

            # Sort active interface with IP first, prioritizing active Wi-Fi
            interfaces.sort(key=lambda x: (not x["has_ip"], not x["is_wifi"]))

        except Exception:
            pass

        return interfaces

    def start_capture(self, iface_name: Optional[str] = None) -> bool:
        """Starts real-time background packet sniffing on the chosen adapter."""
        if self.is_running:
            return True

        if not self.is_pcap_available():
            self.last_error = (
                "Npcap packet capture driver is not installed on this Windows system. "
                "Download and install Npcap from https://npcap.com/#download to enable live wire sniffing."
            )
            return False

        # Resolve chosen adapter to Scapy interface device
        resolved_iface = None
        if iface_name:
            try:
                from scapy.all import conf
                for iface in conf.ifaces.values():
                    if (
                        getattr(iface, "network_name", "") == iface_name or
                        getattr(iface, "name", "") == iface_name or
                        getattr(iface, "description", "") == iface_name
                    ):
                        resolved_iface = getattr(iface, "network_name", iface)
                        break
                if not resolved_iface:
                    resolved_iface = iface_name
            except Exception:
                resolved_iface = iface_name

        self.selected_iface = resolved_iface
        self.is_running = True
        self.last_error = None
        self.clear_buffers()

        self._thread = threading.Thread(target=self._capture_worker, daemon=True)
        self._thread.start()
        return True

    def clear_buffers(self) -> None:
        """Clears all accumulated packets, flow buckets, and cached flows."""
        with self._lock:
            self.extractor.active_flow_buckets.clear()
            self._flow_cache.clear()
            self.packets_captured = 0

    def stop_capture(self) -> None:
        """Stops background packet sniffing cleanly without blocking the UI thread."""
        self.is_running = False
        # Do not block the Streamlit UI thread on join; daemon thread terminates cleanly
        self._thread = None
        self.clear_buffers()

    def _capture_worker(self) -> None:
        """Background daemon thread executing asynchronous Scapy sniffing and writing to thread-safe cache."""
        try:
            while self.is_running:
                scapy.sniff(
                    iface=self.selected_iface,
                    prn=self._process_packet,
                    stop_filter=lambda p: not self.is_running,
                    store=False,
                    timeout=0.5
                )
                # Background thread periodically aggregates completed flow windows into thread-safe cache
                with self._lock:
                    ready = self.extractor.flush_flows(force_all=False)
                    if ready:
                        self._flow_cache.extend(ready)
                        if len(self._flow_cache) > 500:
                            self._flow_cache = self._flow_cache[-500:]
        except Exception as e:
            self.last_error = str(e)
            self.is_running = False

    def _process_packet(self, pkt: Any) -> None:
        with self._lock:
            self.packets_captured += 1
            self.extractor.ingest_scapy_packet(pkt)

    def flush_real_flows(self, force_all: bool = False) -> List[NetworkFlow]:
        """
        Thread-safe instantaneous flow retrieval without blocking UI thread on socket I/O.
        Drains cached flows prepared asynchronously by the background daemon thread.
        """
        with self._lock:
            ready = list(self._flow_cache)
            self._flow_cache.clear()
            extra = self.extractor.flush_flows(force_all=force_all)
            if extra:
                ready.extend(extra)
            return ready

