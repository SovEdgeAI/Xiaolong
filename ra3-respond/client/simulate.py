#!/usr/bin/env python3
"""5G-NIDD threat report simulator for the RA3 system.

Sends threat reports to the RA3 server's POST /report endpoint. Two modes:

  Single:  python simulate.py --once --attack SYN_Flood
  Loop:    python simulate.py --loop --interval 5

Each attack type carries realistic metadata reflecting its typical signature.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

import httpx

SERVER_URL = os.getenv("RA3_SERVER_URL", "http://localhost:8000")

# ---------------------------------------------------------------------------
# Sample scenarios: >= 2 per attack type, with signature-accurate metadata.
# Each entry: (client_id, severity, confidence, metadata)
# ---------------------------------------------------------------------------
SCENARIOS: dict[str, list[dict]] = {
    "SYN_Flood": [
        {
            "client_id": "bs_node_01",
            "severity": "critical",
            "confidence": 0.98,
            "metadata": {"half_open_connections": 48000, "syn_rate": 15000, "source_ips": 3400},
        },
        {
            "client_id": "bs_node_04",
            "severity": "high",
            "confidence": 0.91,
            "metadata": {"half_open_connections": 22000, "syn_rate": 8200, "source_ips": 1500},
        },
    ],
    "UDP_Flood": [
        {
            "client_id": "bs_node_02",
            "severity": "critical",
            "confidence": 0.96,
            "metadata": {"packet_rate": 850000, "bandwidth_mbps": 420, "target_port": 53},
        },
        {
            "client_id": "bs_node_07",
            "severity": "high",
            "confidence": 0.88,
            "metadata": {"packet_rate": 410000, "bandwidth_mbps": 210, "target_port": 123},
        },
    ],
    "ICMP_Flood": [
        {
            "client_id": "bs_node_03",
            "severity": "high",
            "confidence": 0.93,
            "metadata": {"echo_request_rate": 120000, "bandwidth_mbps": 89},
        },
        {
            "client_id": "bs_node_05",
            "severity": "medium",
            "confidence": 0.8,
            "metadata": {"echo_request_rate": 40000, "bandwidth_mbps": 31},
        },
    ],
    "HTTP_Flood": [
        {
            "client_id": "bs_node_01",
            "severity": "high",
            "confidence": 0.9,
            "metadata": {"request_rate": 50000, "unique_source_ips": 2, "top_endpoint": "/api/login"},
        },
        {
            "client_id": "bs_node_06",
            "severity": "critical",
            "confidence": 0.95,
            "metadata": {"request_rate": 120000, "unique_source_ips": 15, "top_endpoint": "/search"},
        },
    ],
    "Slowrate_DoS": [
        {
            "client_id": "bs_node_02",
            "severity": "medium",
            "confidence": 0.85,
            "metadata": {"active_connections": 4900, "avg_request_duration_s": 280, "variant": "slowloris"},
        },
        {
            "client_id": "bs_node_08",
            "severity": "high",
            "confidence": 0.89,
            "metadata": {"active_connections": 7800, "avg_request_duration_s": 340, "variant": "torshammer"},
        },
    ],
    "SYN_Scan": [
        {
            "client_id": "bs_node_03",
            "severity": "low",
            "confidence": 0.82,
            "metadata": {"ports_probed": 65535, "scan_rate": 1000, "source_ips": 1, "scanner_ip": "203.0.113.7"},
        },
        {
            "client_id": "bs_node_09",
            "severity": "medium",
            "confidence": 0.87,
            "metadata": {"ports_probed": 30000, "scan_rate": 2500, "source_ips": 4, "scanner_ip": "198.51.100.22"},
        },
    ],
    "TCP_Connect_Scan": [
        {
            "client_id": "bs_node_04",
            "severity": "low",
            "confidence": 0.8,
            "metadata": {"ports_probed": 1024, "completed_handshakes": 980, "scanner_ip": "203.0.113.44"},
        },
        {
            "client_id": "bs_node_05",
            "severity": "medium",
            "confidence": 0.84,
            "metadata": {"ports_probed": 4096, "completed_handshakes": 3900, "scanner_ip": "198.51.100.9"},
        },
    ],
    "UDP_Scan": [
        {
            "client_id": "bs_node_06",
            "severity": "low",
            "confidence": 0.78,
            "metadata": {"ports_probed": 500, "icmp_unreachable_received": 312, "scanner_ip": "192.0.2.55"},
        },
        {
            "client_id": "bs_node_07",
            "severity": "medium",
            "confidence": 0.83,
            "metadata": {"ports_probed": 2000, "icmp_unreachable_received": 1450, "scanner_ip": "192.0.2.88"},
        },
    ],
}

ATTACK_TYPES = list(SCENARIOS.keys())


def build_report(attack_type: str) -> dict:
    """Pick a scenario for the given attack type and shape it as a /report body."""
    scenario = random.choice(SCENARIOS[attack_type])
    return {
        "client_id": scenario["client_id"],
        "attack_type": attack_type,
        "severity": scenario["severity"],
        "confidence": scenario["confidence"],
        "metadata": scenario["metadata"],
    }


def send_report(client: httpx.Client, report: dict) -> None:
    """POST a single report and pretty-print the RA3 decision."""
    print(f"\n→ Reporting {report['attack_type']} "
          f"from {report['client_id']} (severity={report['severity']})")
    try:
        resp = client.post(f"{SERVER_URL}/report", json=report, timeout=60.0)
    except httpx.HTTPError as exc:
        print(f"  ✗ request failed: {exc}")
        return

    if resp.status_code >= 400:
        print(f"  ✗ server returned {resp.status_code}: {resp.text}")
        return

    data = resp.json()
    print(f"  ✓ incident_id: {data['incident_id']}")
    actions = data.get("selected_actions", [])
    print(f"  ✓ {len(actions)} action(s) selected:")
    for a in sorted(actions, key=lambda x: x.get("order", 0)):
        args = a.get("arguments", {})
        print(f"      {a['order']}. {a['name']}  args={args}")

    executions = data.get("execution_results", [])
    if executions:
        print(f"  ✓ execution results (ran in ephemeral containers):")
        for e in sorted(executions, key=lambda x: x.get("order") or 0):
            ex = e.get("execution", {})
            status = ex.get("status", "?")
            detail = ex.get("result", {}).get("effect") or ex.get("error") or ""
            print(f"      • {e['name']}: {status}  {detail}")

    reasoning = (data.get("llm_reasoning") or "").strip()
    if reasoning:
        snippet = reasoning if len(reasoning) < 500 else reasoning[:500] + "…"
        print(f"  ↳ reasoning: {snippet}")


def run_once(attack_type: str | None) -> None:
    at = attack_type or random.choice(ATTACK_TYPES)
    if at not in SCENARIOS:
        print(f"Unknown attack type '{at}'. Valid: {', '.join(ATTACK_TYPES)}")
        sys.exit(2)
    with httpx.Client() as client:
        send_report(client, build_report(at))


def run_loop(interval: float) -> None:
    print(f"Looping every {interval}s against {SERVER_URL}. Ctrl-C to stop.")
    with httpx.Client() as client:
        try:
            while True:
                send_report(client, build_report(random.choice(ATTACK_TYPES)))
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="RA3 5G-NIDD threat report simulator")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="send a single report")
    mode.add_argument("--loop", action="store_true", help="continuously report random threats")
    parser.add_argument("--attack", help=f"attack type for --once ({', '.join(ATTACK_TYPES)})")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between reports in --loop")
    args = parser.parse_args()

    if args.once:
        run_once(args.attack)
    else:
        run_loop(args.interval)


if __name__ == "__main__":
    main()
