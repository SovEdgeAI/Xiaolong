#!/usr/bin/env python3
"""Offline end-to-end demo of the RA3 decision + execution logic.

Runs WITHOUT Docker, Postgres, HTTP, or any external LLM. It exercises the two
pieces of real business logic directly:

  * server/llm.py    — the decision engine (forced into mock mode)
  * executor/handlers.py — the code that runs inside each ephemeral container

so you can see, for one alert, exactly what RA3 decides and "executes", and
whether it satisfies the mandatory rules.

Usage:  LLM_MODEL=mock python3 scripts/demo_offline.py [ATTACK_TYPE]
The full networked pipeline (containers/DB/API) still requires `docker compose up`.
"""

from __future__ import annotations

import json
import os
import sys

os.environ.setdefault("LLM_MODEL", "mock")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "server"))
sys.path.insert(0, os.path.join(ROOT, "executor"))

import llm  # noqa: E402
from handlers import HANDLERS  # noqa: E402

# A representative alert per attack type (mirrors the client simulator).
SAMPLES = {
    "SYN_Flood": ("bs_node_01", "critical", 0.98,
                  {"half_open_connections": 48000, "syn_rate": 15000, "source_ips": 3400}),
    "UDP_Flood": ("bs_node_02", "critical", 0.96,
                  {"packet_rate": 850000, "bandwidth_mbps": 420}),
    "HTTP_Flood": ("bs_node_01", "high", 0.90,
                   {"request_rate": 50000, "unique_source_ips": 2}),
    "SYN_Scan": ("bs_node_03", "low", 0.82,
                 {"ports_probed": 65535, "scan_rate": 1000, "scanner_ip": "203.0.113.7"}),
}


def run(attack_type: str) -> bool:
    client_id, severity, confidence, metadata = SAMPLES[attack_type]
    incident_id = "11111111-2222-3333-4444-555555555555"

    print("=" * 72)
    print(f"ALERT  {attack_type}  (severity={severity})")
    print("=" * 72)

    print("\n[STEP 1] Incoming report (RA1 -> POST /report):")
    print(json.dumps({"client_id": client_id, "attack_type": attack_type,
                      "severity": severity, "confidence": confidence,
                      "metadata": metadata}, indent=2))

    print("\n[STEP 2] Decision engine (llm.decide_actions, mock mode):")
    decision = llm.decide_actions(incident_id, client_id, attack_type,
                                  severity, confidence, metadata)
    for a in decision["selected_actions"]:
        print(f"  #{a['order']} {a['name']}")
        print(f"      args   : {json.dumps(a['arguments'])}")
        print(f"      reason : {a['reason']}")
    print(f"\n  reasoning: {decision['llm_reasoning']}")

    print("\n[STEP 3] Execution (executor/handlers.py — runs inside each container):")
    exec_results = []
    for a in decision["selected_actions"]:
        result = HANDLERS[a["name"]](**a["arguments"])
        exec_results.append({"name": a["name"], "order": a["order"],
                             "execution": {"status": "success", "result": result}})
        print(f"  ok  {a['name']:<24} -> {result.get('effect')}")

    print("\n[STEP 4] Verdict:")
    names = [a["name"] for a in decision["selected_actions"]]
    checks = {
        "always logs (log_incident present)": "log_incident" in names,
        "high/critical alerts operator": (severity not in ("high", "critical"))
                                          or ("alert_operator" in names),
        "picks a threat-specific mitigation": any(
            n not in ("log_incident", "alert_operator") for n in names),
        "all actions executed successfully": all(
            r["execution"]["status"] == "success" for r in exec_results),
    }
    for label, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    overall = all(checks.values())
    print(f"\n  => {'SUCCESS' if overall else 'FAILED'}\n")
    return overall


def main() -> int:
    which = sys.argv[1] if len(sys.argv) > 1 else None
    targets = [which] if which else list(SAMPLES)
    ok = all(run(t) for t in targets)
    print("ALL SCENARIOS:", "SUCCESS" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
