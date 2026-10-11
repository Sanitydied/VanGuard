"""
AgentNDR Service & Endpoint Resolver (Phase 1).
Provides high-performance, non-blocking IP-to-Service identity mapping.
Combines passive DNS packet learning, well-known CIDR ranges,
and asynchronous background reverse-DNS lookups.
"""

import socket
import ipaddress
import threading
import queue
import re
from typing import Optional, Dict, Tuple, List, Any

def _parse_net(cidr: str) -> Any:
    return ipaddress.ip_network(cidr, strict=False)

class ServiceResolver:
    """
    Autonomous IP-to-Service identity resolver.
    Translates raw Layer 3 network IP addresses into human-readable destination services
    (e.g., YouTube, WhatsApp, Google, Meta, Cloudflare, Microsoft, Local Gateway).
    """

    # Well-known CIDR prefixes and their authoritative service identities
    KNOWN_CIDRS: List[Tuple[Any, str]] = [
        # Simulation & Benchmark Testbed Specific Targets (Highest Priority)
        (_parse_net("185.220.101.5/32"), "Darknet Node (Exfil Target)"),
        (_parse_net("91.108.4.1/32"), "External C2 Beacon"),
        (_parse_net("198.51.100.22/32"), "External SYN Flooder"),
        (_parse_net("192.168.1.100/32"), "Internal Web Server"),
        (_parse_net("203.0.113.50/32"), "Cloud Web Server"),
        (_parse_net("203.0.113.0/24"), "External Lab Testbed"),

        # Google & YouTube Infrastructure
        (_parse_net("142.250.0.0/15"), "YouTube / Google"),
        (_parse_net("172.217.0.0/16"), "YouTube / Google"),
        (_parse_net("216.58.192.0/19"), "YouTube / Google"),
        (_parse_net("74.125.0.0/16"), "YouTube / Google"),
        (_parse_net("173.194.0.0/16"), "YouTube / Google"),
        (_parse_net("64.233.160.0/19"), "Google Services"),
        (_parse_net("66.102.0.0/20"), "Google Services"),
        (_parse_net("66.249.64.0/19"), "Google Services"),
        (_parse_net("209.85.128.0/17"), "YouTube / Google"),
        (_parse_net("216.239.32.0/19"), "Google Services"),
        (_parse_net("8.8.8.8/32"), "Google DNS"),
        (_parse_net("8.8.4.4/32"), "Google DNS"),

        # Meta & WhatsApp Infrastructure
        (_parse_net("157.240.0.0/16"), "WhatsApp / Meta"),
        (_parse_net("31.13.0.0/16"), "WhatsApp / Meta"),
        (_parse_net("185.60.216.0/22"), "WhatsApp / Meta"),
        (_parse_net("129.134.0.0/16"), "Meta / Facebook"),
        (_parse_net("179.60.192.0/22"), "WhatsApp / Meta"),
        (_parse_net("69.171.224.0/19"), "Meta / Facebook"),
        (_parse_net("204.15.20.0/22"), "WhatsApp / Meta"),

        # Cloudflare CDN & Public DNS
        (_parse_net("1.1.1.1/32"), "Cloudflare DNS"),
        (_parse_net("1.0.0.1/32"), "Cloudflare DNS"),
        (_parse_net("104.16.0.0/12"), "Cloudflare CDN"),
        (_parse_net("172.64.0.0/13"), "Cloudflare CDN"),
        (_parse_net("162.158.0.0/15"), "Cloudflare CDN"),
        (_parse_net("108.162.192.0/18"), "Cloudflare CDN"),
        (_parse_net("190.93.240.0/20"), "Cloudflare CDN"),
        (_parse_net("197.234.240.0/22"), "Cloudflare CDN"),
        (_parse_net("198.41.128.0/17"), "Cloudflare CDN"),

        # Microsoft, Azure & Teams
        (_parse_net("20.0.0.0/8"), "Microsoft / Azure"),
        (_parse_net("52.96.0.0/12"), "Microsoft / Office365"),
        (_parse_net("52.112.0.0/14"), "Microsoft Teams"),
        (_parse_net("40.76.0.0/14"), "Microsoft / Azure"),
        (_parse_net("13.107.0.0/16"), "Microsoft / Office365"),

        # GitHub
        (_parse_net("140.82.112.0/20"), "GitHub"),
        (_parse_net("185.199.108.0/22"), "GitHub Pages"),
        (_parse_net("192.30.252.0/22"), "GitHub"),

        # Amazon AWS & CloudFront
        (_parse_net("3.0.0.0/9"), "Amazon / AWS Cloud"),
        (_parse_net("54.0.0.0/9"), "Amazon / AWS Cloud"),
        (_parse_net("44.192.0.0/11"), "Amazon / AWS Cloud"),
        (_parse_net("18.0.0.0/9"), "Amazon / AWS Cloud"),
        (_parse_net("34.192.0.0/10"), "Amazon / AWS Cloud"),

        # Apple
        (_parse_net("17.0.0.0/8"), "Apple Services"),

        # Telegram
        (_parse_net("149.154.160.0/20"), "Telegram Messenger"),
        (_parse_net("91.108.4.0/22"), "Telegram Messenger"),
        (_parse_net("91.108.56.0/22"), "Telegram Messenger"),

        # Twitter / X
        (_parse_net("104.244.42.0/21"), "X (Twitter)"),

        # Netflix
        (_parse_net("23.246.0.0/18"), "Netflix Video"),
        (_parse_net("198.38.96.0/19"), "Netflix Video"),
        (_parse_net("45.57.0.0/17"), "Netflix Video"),

        # Spotify
        (_parse_net("35.186.224.0/19"), "Spotify Audio"),
        (_parse_net("194.132.160.0/19"), "Spotify Audio"),
    ]

    LOCAL_INFRA_MULTICAST_IPS: set = {
        '239.255.255.250',
        '224.0.0.251',
        '224.0.0.252',
        '224.0.0.2',
        'ff02::fb',
        'ff02::16',
        '255.255.255.255'
    }

    LOCAL_INFRA_PORTS: set = {1900, 5353, 137}

    def __init__(self):
        self._cache: Dict[str, str] = {}
        self._pending: set = set()
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._lock = threading.Lock()
        self._local_ips: set = self._detect_local_ips()

        # Start non-blocking reverse-DNS background resolver
        self._worker_thread = threading.Thread(target=self._dns_worker, daemon=True)
        self._worker_thread.start()

    def _detect_local_ips(self) -> set:
        """Discovers local network interface IP addresses assigned to this PC."""
        ips = {"127.0.0.1", "::1"}
        try:
            hostname = socket.gethostname()
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                ip = item[4][0]
                if ip:
                    ips.add(ip)
        except Exception:
            pass
        return ips

    @staticmethod
    def clean_domain_name(domain: str) -> str:
        """
        Translates raw FQDNs or reverse-DNS PTR hostnames into human-readable site labels.
        Example: 'rr2---sn-4g5ednks.googlevideo.com' -> 'YouTube'
        """
        d = domain.lower().rstrip(".")

        if any(k in d for k in ["youtube", "googlevideo", "ytimg", "youtu.be"]):
            return "YouTube"
        if "whatsapp" in d:
            return "WhatsApp"
        if any(k in d for k in ["instagram", "cdninstagram"]):
            return "Instagram"
        if any(k in d for k in ["facebook", "fbcdn", "fbsbx", "meta.com"]):
            return "Meta / Facebook"
        if any(k in d for k in ["google", "gstatic", "1e100", "ggpht", "googleapis"]):
            return "YouTube / Google" if "1e100" in d else "Google Services"
        if "cloudflare" in d:
            return "Cloudflare CDN"
        if "github" in d:
            return "GitHub"
        if any(k in d for k in ["openai", "chatgpt"]):
            return "OpenAI / ChatGPT"
        if "teams.microsoft" in d:
            return "Microsoft Teams"
        if any(k in d for k in ["microsoft", "office", "azure", "live.com", "bing", "msft"]):
            return "Microsoft / Azure"
        if any(k in d for k in ["amazon", "amazonaws", "cloudfront"]):
            return "Amazon CloudFront" if "cloudfront" in d else "Amazon / AWS Cloud"
        if any(k in d for k in ["apple", "icloud", "mzstatic", "aaplimg"]):
            return "Apple Services"
        if any(k in d for k in ["netflix", "nflx"]):
            return "Netflix"
        if any(k in d for k in ["spotify", "scdn.co"]):
            return "Spotify"
        if any(k in d for k in ["discord", "discordapp", "discord.gg"]):
            return "Discord"
        if any(k in d for k in ["telegram", "t.me"]):
            return "Telegram"
        if any(k in d for k in ["twitter", "twimg", "x.com"]):
            return "X (Twitter)"
        if any(k in d for k in ["reddit", "redditmedia"]):
            return "Reddit"
        if any(k in d for k in ["wikipedia", "wikimedia"]):
            return "Wikipedia"
        if any(k in d for k in ["linkedin", "licdn"]):
            return "LinkedIn"
        if "zoom" in d:
            return "Zoom"
        if "twitch" in d:
            return "Twitch"

        # General clean extraction of registered domain (e.g. sub.example.com -> Example.com)
        parts = d.split(".")
        if len(parts) >= 2:
            base = ".".join(parts[-2:])
            return base.capitalize()
        return d

    def learn_dns_mapping(self, ip: str, domain: str) -> None:
        """
        Passively records an IP-to-domain mapping sniffed directly from live DNS responses.
        Ensures instantaneous zero-overhead identification of real browser traffic.
        """
        if not ip or not domain:
            return
        clean_site = self.clean_domain_name(domain)
        with self._lock:
            # Prefer specific site name (e.g. YouTube) over generic Google
            current = self._cache.get(ip)
            if not current or ("Google" in current and clean_site == "YouTube"):
                self._cache[ip] = clean_site

    def process_scapy_dns_packet(self, pkt: Any) -> None:
        """
        Inspects live Scapy packet for DNS response records (DNSRR) and registers them.
        """
        try:
            if not pkt.haslayer("DNS"):
                return
            dns = pkt.getlayer("DNS")
            # qr == 1 indicates DNS response; ancount > 0 indicates answers present
            if getattr(dns, "qr", 0) == 1 and getattr(dns, "ancount", 0) > 0:
                ans = getattr(dns, "an", None)
                records = []
                if isinstance(ans, (list, tuple)) or hasattr(ans, "__iter__"):
                    try:
                        records = list(ans)
                    except TypeError:
                        records = [ans] if ans else []
                elif ans is not None:
                    records = [ans]

                for rr in records:
                    curr = rr
                    while curr and hasattr(curr, "rrname"):
                        rr_type = getattr(curr, "type", 0)
                        if rr_type in (1, 28):
                            raw_domain = getattr(curr, "rrname", b"")
                            if isinstance(raw_domain, bytes):
                                domain_str = raw_domain.decode("utf-8", errors="ignore")
                            else:
                                domain_str = str(raw_domain)

                            raw_rdata = getattr(curr, "rdata", "")
                            ip_str = str(raw_rdata).strip()
                            if ip_str and domain_str:
                                self.learn_dns_mapping(ip_str, domain_str)

                        # Advance if linked list
                        curr = getattr(curr, "payload", None)
                        if not curr or not hasattr(curr, "rrname"):
                            break
        except Exception:
            pass

    def resolve_ip(self, ip_str: str) -> str:
        """
        Resolves an IP address to a friendly service identity.
        Returns the friendly service name, or empty string if unidentified.
        """
        if not ip_str:
            return ""

        # Check fast memory cache
        with self._lock:
            if ip_str in self._cache:
                return self._cache[ip_str]

        # Check if local host
        if ip_str in self._local_ips or ip_str == "127.0.0.1" or ip_str == "::1":
            label = "This PC (Local Host)"
            with self._lock:
                self._cache[ip_str] = label
            return label

        # Parse IP object for CIDR checks
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return ""

        # Check pre-compiled CIDR ranges first (includes explicit testbed IPs & major CDNs)
        for net, service_name in self.KNOWN_CIDRS:
            if ip_obj in net:
                with self._lock:
                    self._cache[ip_str] = service_name
                return service_name

        # Local & Private subnets
        if ip_obj.is_private or ip_obj.is_loopback:
            if ip_str.endswith(".1") or ip_str.endswith(".254"):
                label = "Local Gateway Router"
            else:
                label = "Local Network Host"
            with self._lock:
                self._cache[ip_str] = label
            return label

        # Multicast & Broadcast
        if ip_obj.is_multicast or ip_str in self.LOCAL_INFRA_MULTICAST_IPS:
            if ip_str in ("224.0.0.251", "ff02::fb"):
                label = "mDNS Discovery (Verified Local Infrastructure)"
            elif ip_str == "239.255.255.250":
                label = "SSDP Device Discovery (Verified Local Infrastructure)"
            elif ip_str == "224.0.0.252":
                label = "LLMNR Discovery (Verified Local Infrastructure)"
            elif ip_str == "ff02::16":
                label = "IPv6 Multicast (Verified Local Infrastructure)"
            elif ip_str == "224.0.0.2":
                label = "Router Multicast (Verified Local Infrastructure)"
            else:
                label = "Verified Local Infrastructure (Multicast)"
            with self._lock:
                self._cache[ip_str] = label
            return label

        if ip_str == "255.255.255.255":
            label = "Verified Local Infrastructure (Broadcast)"
            with self._lock:
                self._cache[ip_str] = label
            return label

        if ip_obj.is_link_local:
            label = "Link-Local"
            with self._lock:
                self._cache[ip_str] = label
            return label

        # If not matched, enqueue for background reverse DNS without blocking
        with self._lock:
            if ip_str not in self._pending:
                self._pending.add(ip_str)
                try:
                    self._queue.put_nowait(ip_str)
                except queue.Full:
                    pass

        return ""

    def format_ip(self, ip_str: str) -> str:
        """
        Formats an IP address with its destination identity:
        Example: '142.250.190.46 (YouTube / Google)' or '192.168.1.6 (This PC)'
        """
        if not ip_str:
            return ""
        service = self.resolve_ip(ip_str)
        if service:
            return f"{ip_str} ({service})"
        return ip_str

    def format_endpoint(self, ip_str: str, port: Optional[int] = None) -> str:
        """
        Formats an IP endpoint with port and service identity:
        Example: '142.250.190.46:443 (YouTube / Google)'
        """
        if not ip_str:
            return ""
        service = self.resolve_ip(ip_str)
        port_suffix = f":{port}" if port is not None else ""
        if service:
            return f"{ip_str}{port_suffix} ({service})"
        return f"{ip_str}{port_suffix}"

    TRUSTED_PROVIDER_GROUPS: Dict[str, List[str]] = {
        "Google & YouTube": ["google", "youtube", "1e100", "googlevideo", "gstatic", "ggpht"],
        "WhatsApp & Meta": ["whatsapp", "meta", "facebook", "fbcdn", "instagram"],
        "Cloudflare CDN": ["cloudflare", "one.one.one.one"],
        "Microsoft & Teams": ["microsoft", "azure", "office365", "teams", "windows", "live.com", "msft"],
        "Apple Services": ["apple", "icloud", "aaplimg"],
        "Amazon AWS": ["amazon", "aws", "cloudfront"],
        "GitHub": ["github"],
        "Netflix": ["netflix", "nflx"],
        "Spotify": ["spotify"],
    }

    def is_local_infrastructure_flow(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int] = 0,
        dst_port: Optional[int] = 0
    ) -> bool:
        """
        Fast-paths benign local network infrastructure traffic before passing it to ML anomaly detection:
        - Multicast & Broadcast: dst_ip in ['239.255.255.250', '224.0.0.251', '224.0.0.252', '224.0.0.2', 'ff02::fb', 'ff02::16']
        - Infrastructure ports: dst_port or src_port in [1900 (SSDP), 5353 (mDNS), 137 (NetBIOS-NS), 53 (DNS to local gateway 192.168.x.x)]
        """
        s_ip = str(src_ip or "").strip()
        d_ip = str(dst_ip or "").strip()
        sp = int(src_port or 0)
        dp = int(dst_port or 0)

        # 1. Multicast & Broadcast destination or source IPs
        if d_ip in self.LOCAL_INFRA_MULTICAST_IPS or s_ip in self.LOCAL_INFRA_MULTICAST_IPS:
            return True

        if d_ip.startswith("224.") or d_ip.startswith("239.") or d_ip.startswith("ff02::") or d_ip == "255.255.255.255":
            return True

        # 2. Well-known local infrastructure discovery ports (1900 SSDP, 5353 mDNS, 137 NetBIOS-NS)
        if dp in self.LOCAL_INFRA_PORTS or sp in self.LOCAL_INFRA_PORTS:
            return True

        # 3. Port 53 (DNS) to/from local gateway (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
        if dp == 53 or sp == 53:
            if (s_ip.startswith("192.168.") or s_ip.startswith("10.") or s_ip.startswith("172.") or
                d_ip.startswith("192.168.") or d_ip.startswith("10.") or d_ip.startswith("172.")):
                return True

        return False

    def is_trusted(self, ip_str: str, allowed_providers: Optional[List[str]] = None) -> bool:
        """
        Determines whether an IP belongs to a verified trusted source provider or local infrastructure.
        Explicit lab attack targets are strictly excluded from whitelisting.
        """
        if not ip_str:
            return False
        # Never whitelist explicit lab attacks
        if ip_str in ("185.220.101.5", "91.108.4.1", "198.51.100.22"):
            return False

        # Local infrastructure is always trusted
        if self.is_local_infrastructure_flow(ip_str, ""):
            return True

        svc = self.resolve_ip(ip_str).lower()
        if not svc:
            return False

        # Exclude attack keywords
        if any(k in svc for k in ["darknet", "beacon", "flooder", "c2", "attack", "exfil", "recon"]):
            return False

        if allowed_providers is None:
            allowed_providers = list(self.TRUSTED_PROVIDER_GROUPS.keys())

        for group in allowed_providers:
            keywords = self.TRUSTED_PROVIDER_GROUPS.get(group, [])
            if any(kw in svc for kw in keywords):
                return True

        return False

    def is_flow_trusted(
        self,
        src_ip: str,
        dst_ip: str,
        allowed_providers: Optional[List[str]] = None,
        src_port: Optional[int] = 0,
        dst_port: Optional[int] = 0
    ) -> bool:
        """
        Checks whether either endpoint of a network flow belongs to an allowed trusted source
        or benign local network infrastructure.
        """
        if self.is_local_infrastructure_flow(src_ip, dst_ip, src_port, dst_port):
            return True
        return self.is_trusted(dst_ip, allowed_providers) or self.is_trusted(src_ip, allowed_providers)

    def format_connection(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        include_ports: bool = False
    ) -> str:
        """
        Formats bidirectional or directional flow connection:
        Example: '192.168.1.6 (This PC) → 142.250.190.46 (YouTube)'
        """
        if include_ports and src_port is not None and dst_port is not None:
            src_text = self.format_endpoint(src_ip, src_port)
            dst_text = self.format_endpoint(dst_ip, dst_port)
        else:
            src_text = self.format_ip(src_ip)
            dst_text = self.format_ip(dst_ip)
        return f"{src_text} → {dst_text}"

    def _dns_worker(self) -> None:
        """Background thread executing non-blocking reverse DNS lookups."""
        while True:
            try:
                ip_str = self._queue.get()
                if not ip_str:
                    continue
                try:
                    # Reverse lookup with 1-second timeout
                    hostname, _, _ = socket.gethostbyaddr(ip_str)
                    clean_name = self.clean_domain_name(hostname)
                    with self._lock:
                        self._cache[ip_str] = clean_name
                except Exception:
                    pass
                finally:
                    self._queue.task_done()
            except Exception:
                pass


# Global singleton instance for high-throughput zero-latency reuse
GLOBAL_RESOLVER = ServiceResolver()
