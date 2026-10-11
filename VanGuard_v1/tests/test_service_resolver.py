"""
Unit tests for ServiceResolver (Phase 1 Destination & Service Identification).
"""

import unittest
import scapy.all as scapy
from agentndr.service_resolver import ServiceResolver, GLOBAL_RESOLVER

class TestServiceResolver(unittest.TestCase):

    def setUp(self):
        self.resolver = ServiceResolver()

    def test_known_cidrs_resolution(self):
        # YouTube / Google
        res_yt = self.resolver.resolve_ip("142.250.190.46")
        self.assertIn("YouTube", res_yt)

        # WhatsApp / Meta
        res_wa = self.resolver.resolve_ip("157.240.22.53")
        self.assertIn("WhatsApp", res_wa)

        # Cloudflare DNS
        res_cf = self.resolver.resolve_ip("1.1.1.1")
        self.assertEqual(res_cf, "Cloudflare DNS")

        # Local Gateway
        res_gw = self.resolver.resolve_ip("192.168.1.1")
        self.assertEqual(res_gw, "Local Gateway Router")

        # Localhost
        res_lh = self.resolver.resolve_ip("127.0.0.1")
        self.assertIn("This PC", res_lh)

    def test_clean_domain_name(self):
        self.assertEqual(self.resolver.clean_domain_name("rr2---sn-4g5ednks.googlevideo.com"), "YouTube")
        self.assertEqual(self.resolver.clean_domain_name("web.whatsapp.com"), "WhatsApp")
        self.assertEqual(self.resolver.clean_domain_name("whatsapp-cdn-shv-01-sjc3.fbcdn.net"), "WhatsApp")
        self.assertEqual(self.resolver.clean_domain_name("api.github.com"), "GitHub")
        self.assertEqual(self.resolver.clean_domain_name("teams.microsoft.com"), "Microsoft Teams")

    def test_passive_dns_packet_learning(self):
        # Create synthetic DNS answer packet
        pkt = (
            scapy.IP(src="192.168.1.1", dst="192.168.1.105") /
            scapy.UDP(sport=53, dport=54321) /
            scapy.DNS(
                qr=1,
                ancount=1,
                an=scapy.DNSRR(rrname="rr1---sn-video.googlevideo.com.", type=1, rdata="199.232.40.50")
            )
        )
        self.resolver.process_scapy_dns_packet(pkt)
        resolved = self.resolver.resolve_ip("199.232.40.50")
        self.assertEqual(resolved, "YouTube")

    def test_formatting_functions(self):
        formatted = self.resolver.format_ip("142.250.190.46")
        self.assertIn("142.250.190.46", formatted)
        self.assertIn("YouTube", formatted)

        conn = self.resolver.format_connection("192.168.1.105", "142.250.190.46")
        self.assertIn("→", conn)
        self.assertIn("YouTube", conn)

    def test_trusted_source_whitelisting(self):
        # Trusted sources
        self.assertTrue(self.resolver.is_trusted("142.250.190.46"))  # YouTube / Google
        self.assertTrue(self.resolver.is_trusted("157.240.22.53"))   # WhatsApp / Meta
        self.assertTrue(self.resolver.is_trusted("1.1.1.1"))          # Cloudflare

        # Untrusted / Attack targets
        self.assertFalse(self.resolver.is_trusted("185.220.101.5"))  # Darknet
        self.assertFalse(self.resolver.is_trusted("91.108.4.1"))     # External C2
        self.assertFalse(self.resolver.is_trusted("198.51.100.22"))  # SYN Flooder

        # Flow whitelisting check
        self.assertTrue(self.resolver.is_flow_trusted("192.168.1.6", "142.250.190.46"))
        self.assertFalse(self.resolver.is_flow_trusted("192.168.1.6", "185.220.101.5"))

if __name__ == "__main__":
    unittest.main()

