#!/usr/bin/env python3
"""End-to-end check of a running RA3 stack (decider + MCP + executor containers + DB).

Sends four alerts and three invalid requests to POST /report and checks the
decision rules, execution order, container isolation (cross-checked against
`docker events`), the structured explanation and persistence. Needs the stack
up (`docker compose up -d db mcp server`) and the docker CLI.

Usage:  python3 scripts/e2e_test.py        (RA3_SERVER_URL defaults to http://localhost:8000)
"""
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

BASE = os.getenv("RA3_SERVER_URL", "http://localhost:8000")
MANDATORY = {"log_incident", "alert_operator"}
SUPPORT = {"share_threat_intel"}

CASES = [
    ("SYN_Flood", "critical", 0.98, {"half_open_connections": 48000, "syn_rate": 15000}),
    ("UDP_Flood", "high", 0.88, {"packet_rate": 410000, "bandwidth_mbps": 210, "target_port": 123}),
    ("HTTP_Flood", "high", 0.90, {"request_rate": 50000, "unique_source_ips": 2, "top_endpoint": "/api/login"}),
    ("UDP_Scan", "low", 0.78, {"ports_probed": 500, "icmp_unreachable_received": 312, "scanner_ip": "192.0.2.55"}),
]


def call(method, path, body=None, timeout=900):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


results = []


def check(case, name, ok, detail=""):
    results.append((case, name, bool(ok), detail))


catalog = {a["name"]: a for a in call("GET", "/actions")[1]}
check("setup", "health ok + db connected", call("GET", "/health")[1] == {"status": "ok", "database": "connected"})
check("setup", "catalog has 9 actions", len(catalog) == 9, len(catalog))

events = subprocess.Popen(
    ["docker", "events", "--filter", "image=ra3-executor:latest", "--filter", "event=die",
     "--format", "{{json .}}"], stdout=subprocess.PIPE, text=True)

reports = []
for attack, sev, conf, meta in CASES:
    case = f"{attack}/{sev}"
    t0 = time.time()
    code, r = call("POST", "/report", {"client_id": "bs_node_01", "attack_type": attack,
                                       "severity": sev, "confidence": conf, "metadata": meta})
    dt = time.time() - t0
    check(case, "POST /report -> 201", code == 201, f"{code} in {dt:.0f}s")
    if code != 201:
        continue
    reports.append((case, r, dt))
    sel = r["selected_actions"]
    names = [a["name"] for a in sel]
    ex = r["explanation"]
    rec = {x["name"]: x for x in ex["selected_actions"]}

    # --- decision rules
    check(case, "log_incident present and last", names[-1] == "log_incident", names)
    if sev in ("high", "critical"):
        check(case, "alert_operator present (high/critical)", "alert_operator" in names)
        check(case, "alert_operator is mandatory_rule", rec["alert_operator"]["decision_basis"] == "mandatory_rule")
    mitig = [n for n in names if n not in MANDATORY | SUPPORT]
    check(case, ">=1 mitigation selected", len(mitig) >= 1, mitig)
    bad = [n for n in names if n not in MANDATORY and attack not in catalog[n]["applicable_threats"]]
    check(case, "every model-chosen action applicable to attack", not bad, bad)
    check(case, "1..N actions (count in [2, 9])", 2 <= len(names) <= 9, len(names))

    # --- ordering
    check(case, "order is 1..n contiguous", [a["order"] for a in sel] == list(range(1, len(sel) + 1)))
    lo = [rec[n]["log_odds"] for n in mitig]
    check(case, "mitigations sorted by log_odds desc", lo == sorted(lo, reverse=True), lo)
    tail = [n for n in names if n in MANDATORY | SUPPORT]
    want = [n for n in ("share_threat_intel", "alert_operator", "log_incident") if n in tail]
    check(case, "support -> alert -> log after mitigations", names[len(mitig):] == want, names)

    # --- execution
    er = r["execution_results"]
    check(case, "one execution per selected action, same order", [e["name"] for e in er] == names)
    check(case, "all executions success", all(e["execution"]["status"] == "success" for e in er),
          [e["execution"]["status"] for e in er])
    check(case, "executed with the decided arguments",
          all(e["execution"]["arguments"] == a["arguments"] for e, a in zip(er, sel)))
    rts = [e["execution"].get("runtime", {}) for e in er]
    hosts = [rt.get("container_hostname") for rt in rts]
    check(case, "each action in its own container", len(set(hosts)) == len(hosts) and None not in hosts, hosts)
    check(case, "containers network-isolated (only lo)", all(rt.get("network_interfaces") == ["lo"] for rt in rts))
    check(case, "containers memory-capped at 128 MiB", all(rt.get("memory_limit_bytes") == "134217728" for rt in rts))
    check(case, "executor is PID 1 in container", all(rt.get("pid") == 1 for rt in rts))

    # --- structured explanation
    for key in ("overall_assessment", "selected_actions", "rejected_actions", "explanation_source"):
        check(case, f"explanation.{key} present", key in ex)
    confs_ok = True
    for x in ex["selected_actions"]:
        c = x["confidence"]
        confs_ok &= 0 <= c <= 1
        if x["decision_basis"] == "mandatory_rule":
            confs_ok &= c == 1.0 and x["p_necessary"] is None
        else:
            confs_ok &= abs(c - x["p_necessary"]) < 1e-9
    for x in ex["rejected_actions"]:
        confs_ok &= abs(x["confidence"] - (1 - x["p_necessary"])) < 1e-3
    check(case, "confidence semantics (p / 1-p / 1.0 rule)", confs_ok)
    check(case, "selected_actions[].confidence == explanation",
          all(a["confidence"] == rec[a["name"]]["confidence"] for a in sel))
    texts = [ex["overall_assessment"]] + [x["rationale"] for x in ex["selected_actions"] + ex["rejected_actions"]]
    ascii_ratio = sum(ch.isascii() for t in texts for ch in t) / max(1, sum(len(t) for t in texts))
    check(case, "explanation in English (ASCII >= 98%)", ascii_ratio >= 0.98, f"{ascii_ratio:.3f}")
    check(case, "explanation generated by LLM", ex["explanation_source"] == "llm", ex["explanation_source"])
    check(case, "every action has a rationale", all(t.strip() for t in texts))

    # --- persistence
    code, d = call("GET", f"/incidents/{r['incident_id']}")
    check(case, "GET /incidents/{id} -> 200", code == 200, code)
    if code == 200:
        check(case, "incident status resolved", d["status"] == "resolved", d["status"])
        resp = d["responses"][0]
        check(case, "DB selected_actions == response",
              [a["name"] for a in resp["selected_actions"]] == names)
        check(case, "DB execution_results persisted", len(resp["execution_results"]) == len(names))
    code, lst = call("GET", f"/incidents?attack_type={attack}&limit=5")
    check(case, "listed in GET /incidents?attack_type", any(i["id"] == r["incident_id"] for i in lst["items"]))

# --- invalid input
code, _ = call("POST", "/report", {"client_id": "n", "attack_type": "Normal", "severity": "low", "confidence": 0.9})
check("errors", "Normal -> 400", code == 400, code)
code, _ = call("POST", "/report", {"client_id": "n", "attack_type": "Bogus", "severity": "low", "confidence": 0.9})
check("errors", "unknown attack_type -> 422", code == 422, code)
code, _ = call("POST", "/report", {"client_id": "n", "attack_type": "SYN_Flood", "severity": "low", "confidence": 1.5})
check("errors", "confidence > 1 -> 422", code == 422, code)

# --- docker events: every reported container actually ran and exited 0
time.sleep(2)
events.terminate()
died = {}
for line in events.stdout.read().splitlines():
    ev = json.loads(line)
    died[ev["Actor"]["ID"][:12]] = ev["Actor"]["Attributes"].get("exitCode")
all_hosts = [e["execution"]["runtime"]["container_hostname"] for _, r, _ in reports for e in r["execution_results"]]
check("docker", "every executor container seen by docker events", all(h in died for h in all_hosts),
      f"{sum(h in died for h in all_hosts)}/{len(all_hosts)}")
check("docker", "every executor container exited 0", all(died.get(h) == "0" for h in all_hosts))
left = subprocess.run(["docker", "ps", "-aq", "--filter", "ancestor=ra3-executor:latest", "--filter", "status=running"],
                      capture_output=True, text=True).stdout.split()
check("docker", "no executor container left running", not left, left)

# --- report
print("\n=== decisions ===")
for case, r, dt in reports:
    ex = r["explanation"]
    print(f"{case:<22} {dt:5.0f}s  " + " -> ".join(
        f"{x['name']}[{x['calibration'] or 'rule'}]({x['confidence']:.2f})" for x in ex["selected_actions"]))
    print(f"{'':<29}rejected: " + (", ".join(f"{x['name']}[{x['calibration']}](p={x['p_necessary']:.2f})"
                                            for x in ex["rejected_actions"]) or "-"))
print("\n=== checks ===")
for case, name, ok, detail in results:
    if not ok:
        print(f"FAIL [{case}] {name}  {detail}")
n_ok = sum(ok for *_, ok, _ in results)
print(f"{n_ok}/{len(results)} checks passed")
raise SystemExit(0 if n_ok == len(results) else 1)
