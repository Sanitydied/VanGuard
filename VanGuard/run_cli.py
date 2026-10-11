"""
AgentNDR (Phase 1) Command Line Interface.
Runs CLI flow ingestion, benchmark evaluations, and alert inspection.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
import argparse
from agentndr.flow_extractor import FlowExtractor
from agentndr.isolation_forest import IsolationForestDetector
from agentndr.traffic_generator import TrafficGenerator, AttackCategory
from agentndr.alert_queue import AlertQueueManager
from agentndr.benchmark_suite import Phase1BenchmarkSuite

def print_banner():
    print("=" * 70)
    print("  AgentNDR: Autonomous Network Threat Detection Engine")
    print("=" * 70)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="AgentNDR Phase 1 CLI")
    parser.add_argument(
        "--traffic",
        choices=["all", "benign", "scan", "flood", "exfil", "stealth"],
        default="all",
        help="Traffic vectors to simulate and evaluate (defaults to 'all' vectors simultaneously)"
    )
    parser.add_argument("--benchmark", action="store_true", help="Run empirical Autoencoder vs iForest benchmark")
    parser.add_argument("--show-alerts", action="store_true", help="Display Phase 1 alert queue for Phase 2 handoff")
    parser.add_argument("--live", action="store_true", help="Start continuous real-time network monitoring (every N seconds)")
    parser.add_argument("--interval", type=float, default=5.0, help="Scan interval in seconds for live monitoring (default: 5.0)")

    args = parser.parse_args()
    detector = IsolationForestDetector()
    detector.initialize_benign_baseline()
    alert_mgr = AlertQueueManager()

    cat_map = {
        "benign": AttackCategory.BENIGN,
        "scan": AttackCategory.PORT_SCAN,
        "flood": AttackCategory.SYN_FLOOD,
        "exfil": AttackCategory.EXFILTRATION,
        "stealth": AttackCategory.STEALTH_C2
    }

    if args.show_alerts:
        alerts = alert_mgr.get_all_alerts()
        print(f"\n[Phase 1 Alert Dispatch Queue: {len(alerts)} items pending Phase 2 triage]:")
        for a in alerts:
            print(f"  Alert ID: {a.alert_id} | Flow: {a.flow_id} | Score: {a.anomaly_score} | Latency: {a.inference_time_ms} ms")
        return

    if args.benchmark:
        print("\n[*] Executing Empirical Benchmark: Isolation Forest vs Autoencoder (Smolen & Benova, 2023)...")
        suite = Phase1BenchmarkSuite(detector)
        results = suite.run_comparative_benchmark(n_benign=150, n_attack=50)

        print("\n--- [Benchmark Results] ---")
        for model_name, metrics in [("Isolation Forest", results["isolation_forest"]), ("Deep Autoencoder", results["autoencoder"])]:
            print(f"\nModel: {model_name}")
            for k, v in metrics.items():
                print(f"  {k:28s}: {v}")
        return

    if args.live:
        import time
        from datetime import datetime
        print(f"\n[*] Starting Real-Time Autonomous Network Monitor (Interval: {args.interval}s)")
        print(f"[*] Scanning All 5 Network Vectors Simultaneously Every {args.interval} Seconds")
        print(f"[*] Decision Threshold: {detector.config.anomaly_threshold:.2f} | Target Latency: < 1.0 ms")
        print("[*] Press Ctrl+C at any time to terminate real-time monitoring.\n")
        tick = 0
        try:
            while True:
                tick += 1
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n=== [Cycle #{tick:03d} | {now_str}] Scanning All Vectors Simultaneously ===")
                print(f"{'PROFILE':24s} | {'SCORE':7s} | {'PATH':5s} | {'LATENCY':8s} | {'VERDICT'}")
                print("-" * 75)
                for cat in AttackCategory:
                    flow = TrafficGenerator.generate_flow(cat)
                    is_ano, score, path_len, lat = detector.predict_flow(flow)
                    verdict = "🚨 ALERT QUEUED" if is_ano else "✅ NORMAL PASS"
                    print(f"{cat.name:24s} | {score:.4f}  | {path_len:5.2f} | {lat:6.3f}ms | {verdict}")

                    if is_ano:
                        alert = alert_mgr.enqueue_alert(flow, score, path_len, lat)
                        print(f"   └──> Queued: {alert.alert_id} ({flow.flow_id})")

                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n" + "=" * 70)
            print(f"  Live monitor stopped. Total Scans: {detector.total_inferences} | Avg Latency: {detector.avg_latency_ms:.3f} ms")
            print("=" * 70)
            return

    selected = [cat_map[args.traffic]] if args.traffic != "all" else list(cat_map.values())

    for cat in selected:
        print(f"\n--- [Ingesting: {cat.value}] ---")
        flow = TrafficGenerator.generate_flow(cat)
        is_ano, score, path_len, lat = detector.predict_flow(flow)

        print(f"  Flow ID:               {flow.flow_id}")
        print(f"  Duration / Pkts / Vol: {flow.duration:.2f}s | {flow.packet_count} packets | {flow.byte_count} bytes")
        print(f"  SYN / ACK / RST Flags: SYN={flow.syn_flag_count} | ACK={flow.ack_flag_count} | RST={flow.rst_flag_count}")
        print(f"  Mean Packet IAT:       {flow.mean_iat:.6f} s")
        print(f"  Anomaly Score s(x, n): {score:.4f} (Threshold = {detector.config.anomaly_threshold:.2f})")
        print(f"  Estimated Path E(h(x)): {path_len:.2f}")
        print(f"  Inference Latency:     {lat:.3f} ms (Target < 1.0 ms)")

        if is_ano:
            alert = alert_mgr.enqueue_alert(flow, score, path_len, lat)
            print(f"  Status:                [ALERT] ANOMALY QUEUED -> Alert ID: {alert.alert_id}")
        else:
            print(f"  Status:                [NORMAL] BENIGN TRAFFIC (Fast-Path Dropped)")

    print("\n" + "=" * 70)
    print(f"  Total Inferences: {detector.total_inferences} | Avg Latency: {detector.avg_latency_ms:.3f} ms")
    print("=" * 70)

if __name__ == "__main__":
    main()
