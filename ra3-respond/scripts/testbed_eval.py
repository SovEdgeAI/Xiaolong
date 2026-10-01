#!/usr/bin/env python3
"""Stage 4: does RA3 actually resolve the alert, on the live 5G testbed?

For each 5G-NIDD attack class this harness runs the full loop end to end:

  1. reset      clear blocks, restore the victim to baseline, settle
  2. baseline   read the victim's metrics with no attack running
  3. attack     launch the bounded attack from the compromised UE (ue-2)
  4. under      read the victim's metrics again -> the symptom of the attack
  5. alert      build an RA3 alert from the *measured* metrics (type is known;
                severity/confidence are set) and POST it to RA3 /report
  6. enforce    RA3 decides + executes on the testbed via the agent (real)
  7. after      stop the attack, wait, read the victim's metrics once more
  8. verdict    resolved if the attack's symptom cleared after RA3 acted

The testbed's own detector must be off (tools/testbed_autonomy.sh off) so RA3
is the sole decider. Reads metrics from the testbed-agent; drives attacks by
docker exec into the UE; talks to RA3 over HTTP.

  python3 scripts/testbed_eval.py                 # all types
  python3 scripts/testbed_eval.py SYN_Flood UDP_Flood
  python3 scripts/testbed_eval.py --duration 45 --out results.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

RA3 = os.environ.get("RA3_URL", "http://localhost:8000")
AGENT = os.environ.get("AGENT_URL", "http://localhost:8090")
UE = os.environ.get("UE_CONTAINER", "ue-2")
UE_IP = os.environ.get("TESTBED_UE_IP", "10.45.0.3")
TESTBED = os.environ.get("TESTBED_DIR", "/home/xiaolong/5G-SDN-DDoS-Detection-Mitigation")
A2_HOST = os.environ.get("A2_HOST_CONTAINER", "a2-host")

# attack class -> (severity, how to build metadata from a metrics snapshot,
#                  how to read the "symptom" scalar that mitigation should lower)
def _syn_meta(m):   return {"half_open_connections": m["half_open_connections"],
                            "syn_rate": int(m["rates"].get("tcp_passive_opens_per_s") or 0),
                            "source_ips": 1}
def _udp_meta(m):   return {"packet_rate": int(m["rates"].get("udp_sink_per_s") or 0),
                            "bandwidth_mbps": 0, "target_port": 53, "source_ips": 1}
def _icmp_meta(m):  return {"echo_request_rate": int(m["rates"].get("icmp_in_msgs_per_s") or 0),
                            "bandwidth_mbps": 0, "source_ips": 1}
def _http_meta(m):  return {"request_rate": int((m["rates"].get("http_requests_per_s") or 0) * 60),
                            "unique_source_ips": 1, "top_endpoint": "/"}
def _slow_meta(m):  return {"active_connections": m["active_connections"],
                            "avg_request_duration_s": 60, "variant": "slowloris"}
def _scan_meta(m):  return {"ports_probed": 1024, "scan_rate": 500, "source_ips": 1, "scanner_ip": UE_IP}

def _syn_sym(m):    return m["half_open_connections"]
def _udp_sym(m):    return float(m["rates"].get("udp_sink_per_s") or 0)
def _icmp_sym(m):   return float(m["rates"].get("icmp_in_msgs_per_s") or 0)
def _http_sym(m):   return float(m["rates"].get("http_requests_per_s") or 0)
def _slow_sym(m):   return m["active_connections"]
def _scan_sym(m):   return float(m["rates"].get("tcp_passive_opens_per_s") or 0)

ATTACKS = {
    "SYN_Flood":        ("critical", _syn_meta,  _syn_sym,  "half_open_connections"),
    "UDP_Flood":        ("critical", _udp_meta,  _udp_sym,  "udp_in/s"),
    "ICMP_Flood":       ("high",     _icmp_meta, _icmp_sym, "icmp_in/s"),
    "HTTP_Flood":       ("high",     _http_meta, _http_sym, "http_req/s"),
    "Slowrate_DoS":     ("high",     _slow_meta, _slow_sym, "active_connections"),
    "SYN_Scan":         ("medium",   _scan_meta, _scan_sym, "tcp_opens/s"),
    "TCP_Connect_Scan": ("medium",   _scan_meta, _scan_sym, "tcp_opens/s"),
    "UDP_Scan":         ("medium",   _scan_meta, _udp_sym,  "udp_in/s"),
}


def sh(*cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def http(url, payload=None, timeout=600):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read() or b"null")


def metrics():
    _, m = http(f"{AGENT}/metrics", timeout=10)
    return m


GOOD_UE_SCRIPT = os.path.join(TESTBED, "victim", "start_good_ue.sh")
GOOD_MIN_RATE = float(os.environ.get("GOOD_MIN_RATE", "0.8"))   # legit success >= 80% = OK
_good_prev = {"ok": 0, "fail": 0}


def good_sample():
    """Success rate of the legitimate UE's HTTP client SINCE the last call, or
    None if the good UE is not running. Measures collateral damage: a good
    mitigation leaves this high."""
    global _good_prev
    r = sh(GOOD_UE_SCRIPT, "probe")
    try:
        cur = json.loads(r.stdout.strip() or "{}")
        ok, fail = int(cur.get("ok", 0)), int(cur.get("fail", 0))
    except (ValueError, KeyError):
        return None
    if ok == 0 and fail == 0:
        return None
    dok, dfail = ok - _good_prev["ok"], fail - _good_prev["fail"]
    _good_prev = {"ok": ok, "fail": fail}
    total = dok + dfail
    return {"rate": (dok / total) if total > 0 else 1.0, "ok": dok, "fail": dfail}


def _syncookies_sent():
    """TcpExtSyncookiesSent on the victim: proof syn cookies are active."""
    r = sh("docker", "exec", "victim", "sh", "-c",
           "awk 'NR==1{for(i=1;i<=NF;i++)h[$i]=i} NR==2{print $h[\"SyncookiesSent\"]}' "
           "/proc/net/netstat 2>/dev/null | tail -1")
    try:
        return int(r.stdout.strip() or 0)
    except ValueError:
        return 0


def _ports_dropped_on_victim():
    """Ports the victim now DROPs (proof close_unnecessary_ports took effect)."""
    r = sh("docker", "exec", "victim", "sh", "-c", "iptables -S INPUT 2>/dev/null")
    return sorted({int(p) for p in re.findall(r"--dport (\d+) -j DROP", r.stdout)})


def settle_rates(n=2, gap=3):
    """Prime the agent's per-second rate counters (they need two reads)."""
    for _ in range(n):
        metrics(); time.sleep(gap)
    return metrics()


def victim_ip():
    r = sh(f"{TESTBED}/victim/start_victim.sh", "ip")
    return r.stdout.strip()


def repin_route():
    sh(f"{TESTBED}/victim/start_victim.sh", "route")


def datapath_ok(vip, count=4):
    # Parse the actual loss % ("100% packet loss" contains "0% packet loss" as a
    # substring, so string matching must not be used here). OK if any reply came.
    r = sh("docker", "exec", UE, "ping", "-I", "uesimtun0", "-c", str(count), "-W", "2", vip, timeout=20)
    m = re.search(r"(\d+)% packet loss", r.stdout)
    return m is not None and int(m.group(1)) < 100


def ensure_datapath(vip):
    """Recover the UE if the user plane wedged (CM-IDLE / silent stall)."""
    repin_route()
    if datapath_ok(vip):
        return True
    print("  [reset] UE data path down; restarting RAN...")
    sh(f"{TESTBED}/approach2/docker_scripts/wsl_run.sh",
       f"{TESTBED}/approach2/docker_scripts/08_start_ran.sh", timeout=180)
    time.sleep(5); repin_route()
    return datapath_ok(vip)


def reset():
    sh("docker", "exec", "-w", TESTBED, A2_HOST, "python3", "tools/enforce.py", "clear", "--ue", UE_IP)
    sh("docker", "exec", UE, "sh", "-c", "iptables -F INPUT 2>/dev/null; true")
    sh("docker", "exec", "victim", "sh", "-c",
       "sysctl -w net.ipv4.tcp_syncookies=0 >/dev/null 2>&1; iptables -F INPUT 2>/dev/null; "
       "sed -i -E '/limit_req_zone .* zone=perip:/d; /limit_req zone=perip/d; "
       "s|(client_body_timeout)[[:space:]]+[0-9]+s;|\\1 60s;|; "
       "s|(keepalive_timeout)[[:space:]]+[0-9]+s;|\\1 65s;|' /etc/nginx/nginx.conf; nginx -s reload 2>/dev/null")


def launch_attack(kind, duration, pps):
    sh(f"{TESTBED}/attack-harness/run_attack.sh", kind, "--duration", str(duration),
       "--pps", str(pps), "--detached")


def stop_attack():
    sh("docker", "exec", UE, "sh", "-c",
       "pkill -f '[a]ttack.sh' 2>/dev/null; pkill -x hping3 2>/dev/null; "
       "pkill -x ping 2>/dev/null; pkill -x nmap 2>/dev/null; pkill -x curl 2>/dev/null; "
       "pkill -f '[s]lowrate.py' 2>/dev/null; true")


def run_one(kind, duration, settle):
    severity, mk_meta, sym, sym_name = ATTACKS[kind]
    print(f"\n=== {kind} ({severity}) ===")
    reset(); time.sleep(settle)
    vip = victim_ip()
    if not ensure_datapath(vip):
        print("  SKIP: UE data path could not be recovered")
        return {"attack": kind, "error": "datapath down"}

    base = settle_rates()
    b_sym = sym(base)
    print(f"  baseline   {sym_name}={b_sym}")

    launch_attack(kind, duration, 1500)
    # Wait until the attack is actually manifesting (poll the symptom) rather
    # than measuring at a fixed time that may be before it ramps.
    u_sym = 0.0
    for _ in range(6):
        time.sleep(4)
        u_sym = sym(settle_rates(n=1, gap=2))
        if u_sym > (10 if "conn" in sym_name or "half" in sym_name else 50):
            break
    under = settle_rates(n=1, gap=2)
    u_sym = max(u_sym, sym(under))
    print(f"  under      {sym_name}={u_sym}")

    meta = mk_meta(under)
    alert = {"client_id": "bs_node_01", "attack_type": kind, "severity": severity,
             "confidence": 0.95, "metadata": meta}
    print(f"  alert      metadata={json.dumps(meta)}")
    t0 = time.time()
    code, r = http(f"{RA3}/report", alert)
    decide_s = time.time() - t0
    actions = [a["name"] for a in r["selected_actions"]] if code == 201 else []
    tb_ok = all((e["execution"].get("result", {}).get("testbed", {}) or {"ok": True}).get("ok", True)
                for e in r.get("execution_results", [])) if code == 201 else False
    print(f"  RA3        {code} in {decide_s:.0f}s -> {actions}  (testbed_ok={tb_ok})")

    good_sample()  # prime the legit-user counter at the moment mitigation starts
    cookies_before = _syncookies_sent()
    # Enforcement propagates over a few seconds (MitigationModule reconciles the
    # switch every ~5 s). Poll until the symptom settles, up to ~30 s.
    m_sym = u_sym
    for _ in range(6):
        time.sleep(4)
        m_sym = sym(settle_rates(n=1, gap=2))
        if u_sym > 0 and m_sym <= 0.3 * u_sym:
            break
    cookies_after = _syncookies_sent()
    stop_attack(); time.sleep(settle)
    after = settle_rates()
    a_sym = sym(after)
    print(f"  after      {sym_name}={m_sym} (attack on) -> {a_sym} (attack stopped)")

    # Verdict is mechanism-aware: what "resolved" means depends on the action
    # RA3 took, not on one universal number. block_ip is checked first because
    # it is the decisive action when present (it cuts the source off entirely).
    net = any(x in actions for x in ("block_ip", "quarantine_ue", "rate_limit",
                                     "throttle_ue_bandwidth", "enable_http_rate_limit"))
    cutoff = [c for c in ("quarantine_ue", "block_ip") if c in actions]
    reason = ""
    if cutoff:
        # The definitive proof the UE is cut off: it can no longer reach the
        # victim. (Rate/stock symptoms drain at different speeds; connectivity
        # is unambiguous.) quarantine_ue and block_ip both sever the data path.
        ue_blocked = not datapath_ok(vip)
        traffic_stopped = u_sym > 0 and m_sym <= max(1.0, 0.3 * u_sym)
        resolved = ue_blocked or traffic_stopped
        reason = (f"UE cut off ({cutoff[0]}, ping loss 100%); "
                  f"attack {sym_name} {u_sym}->{m_sym}") if ue_blocked else \
                 f"attack {sym_name} {u_sym}->{m_sym} at the victim"
    elif "enable_syn_cookie" in actions:
        # syn cookies keep the server serving without a SYN queue; the proof is
        # that it is actively issuing cookies under the flood.
        dc = cookies_after - cookies_before
        resolved = dc > 0
        reason = f"SYN cookies issued while under flood: +{dc}"
    elif "close_unnecessary_ports" in actions:
        # A scan has no traffic symptom to drain: the attacker keeps probing and
        # RA3 (correctly) does not cut it off. The mitigation here is attack-
        # surface reduction, so "resolved" means the closed ports are now
        # FILTERED on the victim (the DROP rules are in effect).
        closed = _ports_dropped_on_victim()
        resolved = len(closed) > 0
        reason = (f"attack surface reduced: ports {closed} now filtered on the victim"
                  if resolved else "close_unnecessary_ports did not take effect")
    elif net:
        resolved = u_sym > 0 and m_sym <= max(1.0, 0.6 * u_sym)
        reason = f"attack {sym_name} {u_sym}->{m_sym} at the victim"
    else:
        resolved = u_sym > 0 and m_sym <= max(1.0, 0.5 * u_sym)
        reason = f"{sym_name} {u_sym}->{m_sym}"
    # Collateral check: did the legitimate UE keep getting served while the
    # attack was mitigated? A good mitigation stops the attacker without harming
    # the normal user. good_before/good_after are success-rate samples.
    good = good_sample()
    good_served = good is None or good["rate"] >= GOOD_MIN_RATE
    collateral = "" if good is None else (
        f"; legit user OK ({good['rate']:.0%} success)" if good_served
        else f"; HARMED legit user ({good['rate']:.0%} success)")
    resolved_full = resolved and good_served
    print(f"  VERDICT    {'RESOLVED' if resolved_full else 'NOT RESOLVED'}  ({reason}{collateral})")
    return {"attack": kind, "severity": severity, "actions": actions, "testbed_ok": tb_ok,
            "legit_user_ok": good_served, "legit_user": good,
            "symptom": sym_name, "baseline": b_sym, "under_attack": u_sym,
            "under_mitigation": m_sym, "after_stop": a_sym, "syncookies_delta": cookies_after - cookies_before,
            "resolved": bool(resolved_full), "attack_stopped": bool(resolved), "reason": reason, "decide_seconds": round(decide_s, 1)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("attacks", nargs="*", help="subset of attack types (default: all)")
    ap.add_argument("--duration", type=int, default=90, help="attack duration (s); must outlast the loop")
    ap.add_argument("--settle", type=int, default=6, help="settle time between phases (s)")
    ap.add_argument("--out", help="write results JSON here")
    args = ap.parse_args()

    kinds = args.attacks or list(ATTACKS)
    bad = [k for k in kinds if k not in ATTACKS]
    if bad:
        print(f"unknown attack(s): {bad}; valid: {list(ATTACKS)}", file=sys.stderr)
        return 2

    # sanity: RA3 up, agent up, detector off
    try:
        http(f"{RA3}/health", timeout=5)
        http(f"{AGENT}/health", timeout=5)
    except Exception as e:  # noqa: BLE001
        print(f"RA3 or agent not reachable: {e}", file=sys.stderr)
        return 1

    results = []
    for k in kinds:
        try:
            results.append(run_one(k, args.duration, args.settle))
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR on {k}: {type(e).__name__}: {e}")
            results.append({"attack": k, "error": str(e)})
        finally:
            stop_attack()
    reset()

    print("\n================ SUMMARY ================")
    print(f"{'attack':<17}{'actions':<34}{'attack stopped':<16}{'legit user':<13}{'verdict'}")
    for r in results:
        if "error" in r:
            print(f"{r['attack']:<17}ERROR: {r['error']}"); continue
        stopped = "yes" if r.get("attack_stopped") else "no"
        lu = r.get("legit_user")
        legit = "n/a" if lu is None else (f"OK {lu['rate']:.0%}" if r.get("legit_user_ok") else f"HARMED {lu['rate']:.0%}")
        print(f"{r['attack']:<17}{','.join(a for a in r['actions'] if a not in ('alert_operator','log_incident'))[:32]:<34}"
              f"{stopped:<16}{legit:<13}{'RESOLVED' if r['resolved'] else 'NOT RESOLVED'}")
    n_ok = sum(1 for r in results if r.get("resolved"))
    print(f"\nfully resolved (attack stopped AND legit user unharmed): "
          f"{n_ok}/{len([r for r in results if 'error' not in r])}")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
