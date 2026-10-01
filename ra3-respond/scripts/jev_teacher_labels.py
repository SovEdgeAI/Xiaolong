#!/usr/bin/env python3
"""Label synthetic alerts with Claude teachers for AnyJev L1/L2 fitting.

For every alert, each teacher model answers — for each candidate action the
local decider would be asked about — whether the action is *necessary* under
docs/response_policy.md. A label is kept only where the teachers agree; the
policy's own rule voter is recorded next to it for auditing, not used as a label.

  1. Alerts: stratified by attack type (equal counts), metrics drawn
     log-uniformly across each rule's threshold, severity and detector
     confidence uniform, so both Yes and No cases occur.
  2. Teachers: `claude -p` in headless mode with a minimal context (no tools,
     no MCP, no local settings), one call per (alert, teacher).
  3. Split: 20% of alerts (fixed by id) are `test` and never used for fitting.

Output: JSONL, one alert per line, appended as results arrive (re-running the
same command resumes). `labels[action]` is "yes" / "no" when the teachers agree,
null when they disagree.

Usage:
  python scripts/jev_teacher_labels.py -n 320 --max-cost 30 --out artifacts/teacher_labels.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "server"))

import jev_decider  # noqa: E402  (candidate_actions; torch is only imported on model load)
from actions import ACTION_DEFINITIONS  # noqa: E402

POLICY_PATH = os.path.join(ROOT, "docs", "response_policy.md")
ATTACKS = ["SYN_Flood", "UDP_Flood", "ICMP_Flood", "HTTP_Flood", "Slowrate_DoS",
           "SYN_Scan", "TCP_Connect_Scan", "UDP_Scan"]
SEVERITIES = ["low", "medium", "high", "critical"]
DESCRIPTIONS = {a["name"]: a["description"] for a in ACTION_DEFINITIONS}
TEACHER_SYSTEM = ("You are a careful data labeler for a network security response system. "
                  "Apply the given policy literally and answer exactly in the requested JSON format.")


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
def _logu(rng: random.Random, lo: float, hi: float) -> int:
    return int(round(math.exp(rng.uniform(math.log(lo), math.log(hi)))))


def _ip(rng: random.Random) -> str:
    net = rng.choice(["192.0.2", "198.51.100", "203.0.113"])  # documentation ranges
    return f"{net}.{rng.randint(1, 254)}"


def synth_alert(rng: random.Random, attack: str, i: int) -> dict:
    m: dict = {}
    if attack == "SYN_Flood":
        m["half_open_connections"] = _logu(rng, 50, 80000)
        m["syn_rate"] = max(1, int(m["half_open_connections"] * rng.uniform(0.1, 0.6)))
        m["source_ips"] = _logu(rng, 1, 10000)
    elif attack == "UDP_Flood":
        m["packet_rate"] = _logu(rng, 1000, 1500000)
        m["bandwidth_mbps"] = max(1, int(m["packet_rate"] * rng.uniform(0.0002, 0.0006)))
        m["target_port"] = rng.choice([53, 123, 161, 1900, 443, rng.randint(1024, 65535)])
    elif attack == "ICMP_Flood":
        m["echo_request_rate"] = _logu(rng, 100, 200000)
        m["bandwidth_mbps"] = max(1, int(m["echo_request_rate"] * rng.uniform(0.0004, 0.0009)))
    elif attack == "HTTP_Flood":
        m["request_rate"] = _logu(rng, 200, 200000)
        m["unique_source_ips"] = _logu(rng, 1, 5000)
        m["top_endpoint"] = rng.choice(["/api/login", "/search", "/", "/api/fl/upload", "/metrics"])
    elif attack == "Slowrate_DoS":
        m["active_connections"] = _logu(rng, 50, 12000)
        m["avg_request_duration_s"] = _logu(rng, 5, 600)
        m["variant"] = rng.choice(["slowloris", "torshammer", "rudy"])
    else:  # scans
        m["ports_probed"] = _logu(rng, 20, 65535)
        if attack == "SYN_Scan":
            m["scan_rate"] = _logu(rng, 10, 5000)
        if attack == "TCP_Connect_Scan":
            m["completed_handshakes"] = 0 if rng.random() < 0.4 else rng.randint(1, min(m["ports_probed"], 50))
        if attack == "UDP_Scan":
            closed = m["ports_probed"] if rng.random() < 0.4 else int(m["ports_probed"] * rng.uniform(0.5, 0.99))
            m["icmp_unreachable_received"] = closed
        m["source_ips"] = 1 if rng.random() < 0.6 else _logu(rng, 2, 50)
        if rng.random() < 0.8:
            m["scanner_ip"] = _ip(rng)
    return {"id": f"tl-{i:05d}", "client_id": f"bs_node_{rng.randint(1, 12):02d}",
            "attack_type": attack, "severity": rng.choice(SEVERITIES),
            "confidence": round(rng.uniform(0.5, 0.99), 2), "metadata": m}


def split_of(alert_id: str) -> str:
    return "test" if int(hashlib.sha256(alert_id.encode()).hexdigest(), 16) % 5 == 0 else "train"


# ---------------------------------------------------------------------------
# Rule voter: docs/response_policy.md as code (audit only, not a label source)
# ---------------------------------------------------------------------------
def rule_vote(alert: dict, action: str) -> bool:
    m, conf, sev, at = alert["metadata"], alert["confidence"], alert["severity"], alert["attack_type"]
    weak = conf < 0.6
    if action == "enable_syn_cookie":
        return not (m.get("half_open_connections", 0) < 1000 and m.get("syn_rate", 0) < 1000 and weak)
    if action == "rate_limit":
        if at == "ICMP_Flood":
            strong = m.get("echo_request_rate", 0) >= 1000
        else:
            strong = m.get("packet_rate", 0) >= 10000 or m.get("bandwidth_mbps", 0) >= 50
        return strong or not weak
    if action == "enable_http_rate_limit":
        return m.get("request_rate", 0) >= 1000 or not weak
    if action == "set_connection_timeout":
        return m.get("avg_request_duration_s", 0) >= 30 and m.get("active_connections", 0) >= 500
    if action == "block_ip":
        if at == "HTTP_Flood":
            return m.get("unique_source_ips", 10 ** 9) <= 20
        return bool(m.get("scanner_ip")) and m.get("source_ips", 1) <= 5
    if action == "close_unnecessary_ports":
        if m.get("ports_probed", 0) >= 1000:
            return True
        if at == "TCP_Connect_Scan":
            return m.get("completed_handshakes", 0) > 0
        if at == "UDP_Scan":
            return m.get("ports_probed", 0) - m.get("icmp_unreachable_received", 0) > 0
        return False
    if action == "share_threat_intel":
        return (bool(m.get("scanner_ip")) and conf >= 0.8) or (sev == "critical" and conf >= 0.9)
    if action == "alert_operator":
        return sev == "medium" and conf >= 0.85
    raise KeyError(action)


# ---------------------------------------------------------------------------
# Teachers
# ---------------------------------------------------------------------------
def teacher_prompt(policy: str, alert: dict, candidates: list[str]) -> str:
    state = {k: alert[k] for k in ("client_id", "attack_type", "severity")}
    state["detector_confidence"] = alert["confidence"]
    state["metadata"] = alert["metadata"]
    acts = "\n".join(f"- {a}: {DESCRIPTIONS[a]}" for a in candidates)
    shape = json.dumps({a: {"necessary": "true|false", "reason": "<= 20 words"} for a in candidates}, indent=1)
    return (f"POLICY:\n{policy}\n\nALERT:\n{json.dumps(state, indent=1)}\n\n"
            f"CANDIDATE ACTIONS:\n{acts}\n\n"
            "For each candidate action, decide whether it is necessary for this alert under the "
            "POLICY. Reply with ONLY a JSON object of exactly this shape, no other text:\n" + shape)


def ask_claude(model: str, prompt: str, timeout: int = 300) -> tuple[dict, float]:
    cmd = ["claude", "-p", prompt, "--output-format", "json", "--model", model,
           "--system-prompt", TEACHER_SYSTEM, "--tools", "", "--strict-mcp-config",
           "--mcp-config", '{"mcpServers":{}}', "--setting-sources", ""]
    last = None
    for _ in range(2):  # one retry on a malformed answer
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              cwd="/tmp")  # no project CLAUDE.md in context
        env = json.loads(proc.stdout)
        cost = float(env.get("total_cost_usd") or 0.0)
        text = env.get("result") or ""
        try:
            obj = json.loads(text[text.index("{"): text.rindex("}") + 1])
            return obj, cost
        except (ValueError, json.JSONDecodeError) as exc:
            last = exc
    raise RuntimeError(f"{model}: unparseable teacher answer ({last})")


def _as_bool(v) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "yes"):
        return True
    if isinstance(v, str) and v.strip().lower() in ("false", "no"):
        return False
    return None


def label_alert(alert: dict, policy: str, teachers: list[str]) -> dict:
    candidates = jev_decider.candidate_actions(alert["attack_type"], alert["severity"])
    prompt = teacher_prompt(policy, alert, candidates)
    answers, cost = {}, 0.0
    for t in teachers:
        obj, c = ask_claude(t, prompt)
        cost += c
        answers[t] = {a: {"necessary": _as_bool((obj.get(a) or {}).get("necessary")),
                          "reason": str((obj.get(a) or {}).get("reason", ""))} for a in candidates}
    labels = {}
    for a in candidates:
        votes = {answers[t][a]["necessary"] for t in teachers}
        labels[a] = None if len(votes) != 1 or None in votes else ("yes" if votes.pop() else "no")
    return {**alert, "split": split_of(alert["id"]), "candidates": candidates,
            "rule": {a: rule_vote(alert, a) for a in candidates},
            "teachers": answers, "labels": labels, "cost_usd": round(cost, 5)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", type=int, default=320, help="alerts, spread evenly over the 8 attack types")
    ap.add_argument("--teachers", default="opus,sonnet", help="claude --model aliases, comma-separated")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--max-cost", type=float, default=30.0, help="stop submitting once spend exceeds this (USD)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default=os.path.join(ROOT, "artifacts", "teacher_labels.jsonl"))
    args = ap.parse_args()

    policy = open(POLICY_PATH).read()
    teachers = [t.strip() for t in args.teachers.split(",") if t.strip()]
    rng = random.Random(args.seed)
    # round-robin over attack types: counts differ by at most one
    alerts = [synth_alert(rng, ATTACKS[i % len(ATTACKS)], i) for i in range(args.n)]

    done = set()
    if os.path.exists(args.out):
        with open(args.out) as f:
            done = {json.loads(line)["id"] for line in f if line.strip()}
    todo = [a for a in alerts if a["id"] not in done]
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    print(f"{len(alerts)} alerts, {len(done)} already labeled, {len(todo)} to go; teachers={teachers}")

    spent, n_ok, n_fail = 0.0, 0, 0
    lock = threading.Lock()
    with open(args.out, "a") as f, ThreadPoolExecutor(args.workers) as pool:
        futures = {}
        it = iter(todo)

        def submit_next() -> None:
            if spent >= args.max_cost:
                return
            a = next(it, None)
            if a is not None:
                futures[pool.submit(label_alert, a, policy, teachers)] = a

        for _ in range(args.workers):
            submit_next()
        while futures:
            fut = next(as_completed(list(futures)))
            a = futures.pop(fut)
            try:
                rec = fut.result()
            except Exception as exc:  # noqa: BLE001
                n_fail += 1
                print(f"  {a['id']} FAILED: {exc}", file=sys.stderr)
            else:
                with lock:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    f.flush()
                    spent += rec["cost_usd"]
                    n_ok += 1
                agree = sum(v is not None for v in rec["labels"].values())
                print(f"  {rec['id']} {rec['attack_type']:<17} {rec['severity']:<8} "
                      f"agree {agree}/{len(rec['labels'])}  ${rec['cost_usd']:.3f}  total ${spent:.2f}")
            submit_next()
    stop = " (stopped at --max-cost)" if spent >= args.max_cost and n_ok + n_fail < len(todo) else ""
    print(f"labeled {n_ok}, failed {n_fail}, spent ${spent:.2f}{stop} -> {args.out}")
    return 0 if n_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
