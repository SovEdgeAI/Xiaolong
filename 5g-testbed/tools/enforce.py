#!/usr/bin/env python3
"""enforce.py - one control point for blocking and rate-limiting on this testbed.

The testbed has five enforcement mechanisms, each with its own control surface.
This tool picks one from what you want to control and how precisely, applies it,
and says which mechanism it used and why.

  WHAT YOU TARGET         APPROACH 2 (P4 / ONOS)           APPROACH 1 (OVS / RYU)
  block  --ue IP          P4 dropped_inner_ipv4            UPF iptables (post-decap)
  limit  --flow S,D,P     P4 per-flow meter cell           (impossible: OVS can't see in GTP)
  limit  --ue IP          P4 meter, every cell of that UE  (impossible; use --imsi or --tunnel)
  limit  --tunnel         -                                OVS HTB queue via OpenFlow set_queue
  limit  --imsi IMSI      core Session-AMBR                core Session-AMBR

Why these choices (measured in experiments/bandwidth-control):
  * P4 is the only mechanism that sees inside the GTP tunnel, so it is the only
    per-UE / per-flow option that is also SDN-driven and line-rate.
  * OVS policers (meter, ingress policing) deliver ~0.5x of the setpoint against
    TCP; the HTB *queue* tracks to ~0.95x, so --tunnel always uses the queue.
  * Core AMBR tracks best (~1.1x) but is per-session and needs a re-registration.
  * Core per-flow PCC rules do NOT reach the UPF in Open5GS 2.4.0 (expD), so they
    are never chosen.
  * OVS cannot block one UE (the rule would match the whole tunnel), so approach 1
    per-UE blocking drops at the UPF after decapsulation instead - effective, but
    enforced by iptables, not by the SDN controller.

Examples:
  enforce.py block --ue 10.45.100.4
  enforce.py limit --flow 10.45.0.3,192.168.230.1,6 --rate 10000
  enforce.py limit --ue 10.45.0.3 --rate 5000
  enforce.py limit --tunnel --rate 20000                     # approach 1 aggregate
  enforce.py limit --imsi 001010000000001 --rate 100000 --approach 1 --reregister
  enforce.py clear --ue 10.45.100.4        (or --flow / --tunnel / --imsi)
  enforce.py status
Rates are kbps. Add --dry-run to print the decision without applying it.
"""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

FLOW_API = "http://127.0.0.1:23500"            # approach 2 flow / block API
UE_CONTAINERS = {1: "ue-1", 2: "ue-2"}
UPF_CONTAINER = "up-1"
OVS_BRIDGE = "br-ovs-ryu"
OVS_HELPER = "ovs-tools"                        # privileged container with the OVS CLI
CORE_DB = {1: "open5gs", 2: "open5gs_a2"}
PUNT_RULE = "table=0,cookie=0x1,priority=1000,udp,tp_dst=2152"
TAG = "enforce.py"


# ---------------------------------------------------------------- helpers
def sh(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:6])}... failed: {(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout


def dexec(container, *cmd, check=True):
    return sh(["docker", "exec", container, *cmd], check=check)


def api(method, path):
    req = urllib.request.Request(FLOW_API + path, method=method)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read().decode()
            return r.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        return e.code, None


def decide(backend, reason, dry):
    print(f"-> mechanism: {backend}")
    print(f"   why:       {reason}")
    if dry:
        print("   (dry run - nothing applied)")
        sys.exit(0)


def ue_addr(approach):
    out = dexec(UE_CONTAINERS[approach], "sh", "-c",
                "ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1", check=False)
    return out.strip()


def which_approach(ip, forced):
    """Both deployments use 10.45.0.0/16, so resolve by who actually holds the IP."""
    if forced:
        return forced, f"--approach {forced}"
    for a in (2, 1):
        if ue_addr(a) == ip:
            return a, f"{ip} is the tunnel address of {UE_CONTAINERS[a]}"
    return 2, f"{ip} is on no UE interface (spoofed/replayed source) - approach 2 tracks those as flows"


# ---------------------------------------------------------------- P4 (approach 2)
def meter_cells():
    """flow key 'src-dst-proto' -> meter cell, from the running ONOS instance's log."""
    r = subprocess.run(["docker", "logs", "onos"], capture_output=True, text=True)
    log = r.stdout + r.stderr
    cells = {}
    for m in re.finditer(r"QoS: flow (\S+) -> meter cell (\d+)", log):
        cells[m.group(1)] = int(m.group(2))
    return cells


def p4_set_cell(cell, kbps):
    dexec("onos", "sh", "-c", f"echo {cell} > /tmp/qos_meter_index; echo {kbps} > /tmp/qos_rate_kbps")
    time.sleep(2.2)   # QoSMeterModule polls once a second; each cell keeps its config once written


def p4_block(ip):
    code, _ = api("POST", f"/blocked-ip/{ip}")
    if code != 200:
        raise RuntimeError(f"flow API refused block ({code})")
    print(f"   {ip} added to /blocked-ips; MitigationModule installs dropped_inner_ipv4 within ~5 s")


ONOS_REST = "http://localhost:8181/onos/v1"


def onos(method, path):
    import base64
    req = urllib.request.Request(ONOS_REST + path, method=method)
    req.add_header("Authorization", "Basic " + base64.b64encode(b"onos:rocks").decode())
    with urllib.request.urlopen(req, timeout=8) as r:
        body = r.read().decode()
        return json.loads(body) if body else None


def p4_forget_flows(ip):
    """Deletes every gtp_flows entry involving ip, so its switch counters restart.

    The detector's features are lifetime counters (packets, bytes, duration since
    the entry was created). If the entry survives an unblock, UpdateFlowStats
    re-creates the flow record from those totals within seconds and the detector
    sees a 'new' flow already carrying the whole attack - it re-flags and re-blocks
    an idle host. Removing the entry makes the next packet a fresh packet-in.
    """
    hexip = "".join(f"{int(o):02x}" for o in ip.split("."))
    removed = 0
    for f in onos("GET", "/flows/device:s1")["flows"]:
        if "gtp_flows" not in f.get("tableId", ""):
            continue
        vals = [m.get("value", "").lower() for c in f["selector"]["criteria"] for m in c.get("matches", [])
                if m.get("field") in ("hdr.inner_ipv4.src_addr", "hdr.inner_ipv4.dst_addr")]
        if hexip in (v.zfill(8) for v in vals):
            onos("DELETE", f"/flows/device:s1/{f['id']}")
            removed += 1
    return removed


def p4_unblock(ip):
    # Order matters: reset everything that could re-flag this IP while the drop
    # rule still holds, and release the block LAST. Releasing first leaves a
    # window in which the old 5-of-5 attack votes re-flag the IP and the
    # detector re-blocks it before the reset runs - an idle host bounces back.
    api("DELETE", f"/flagged-ips/{ip}")
    n = p4_forget_flows(ip)
    api("DELETE", f"/unidirectionalFlows/{ip}")
    time.sleep(6)   # one detector cycle: anything it fetched before the reset now 404s
    api("DELETE", f"/unidirectionalFlows/{ip}")
    api("DELETE", f"/flagged-ips/{ip}")
    api("DELETE", f"/blocked-ips/{ip}")
    print(f"   {ip}: {n} gtp_flows entries and flow history reset, then block released")


# ---------------------------------------------------------------- UPF iptables (approach 1)
def upf_rules(ip):
    return [["FORWARD", "-i", "ogstun", "-s", ip], ["FORWARD", "-o", "ogstun", "-d", ip]]


def upf_block(ip):
    for r in upf_rules(ip):
        spec = r + ["-m", "comment", "--comment", TAG, "-j", "DROP"]
        exists = subprocess.run(["docker", "exec", UPF_CONTAINER, "iptables", "-C", *spec],
                                capture_output=True).returncode == 0
        if not exists:
            dexec(UPF_CONTAINER, "iptables", "-I", *spec)
    print(f"   DROP rules for {ip} (both directions) inserted in {UPF_CONTAINER} FORWARD chain")


def upf_unblock(ip):
    for r in upf_rules(ip):
        spec = r + ["-m", "comment", "--comment", TAG, "-j", "DROP"]
        while subprocess.run(["docker", "exec", UPF_CONTAINER, "iptables", "-D", *spec],
                             capture_output=True).returncode == 0:
            pass
    print(f"   DROP rules for {ip} removed from {UPF_CONTAINER}")


# ---------------------------------------------------------------- OVS HTB (approach 1)
def ovs(*cmd, check=True):
    if sh(["docker", "inspect", "-f", "{{.State.Running}}", OVS_HELPER], check=False).strip() != "true":
        raise RuntimeError(f"helper container '{OVS_HELPER}' is not running (see CLAUDE.md)")
    return dexec(OVS_HELPER, *cmd, check=check)


def upf_ovs_port():
    idx = dexec(UPF_CONTAINER, "cat", "/sys/class/net/eth1/iflink").strip()
    for line in sh(["ip", "-o", "link"]).splitlines():
        num, name = line.split(":", 2)[:2]
        if num.strip() == idx:
            return name.strip().split("@")[0]
    raise RuntimeError("could not find the OVS port facing the UPF")


def ovs_limit(kbps):
    port, bps = upf_ovs_port(), kbps * 1000
    ovs("sh", "-c",
        f"ovs-vsctl -- clear port {port} qos -- --all destroy qos -- --all destroy queue >/dev/null 2>&1; "
        f"ovs-vsctl -- set port {port} qos=@q "
        f"-- --id=@q create qos type=linux-htb other-config:max-rate=2000000000 queues:0=@q0 queues:1=@q1 "
        f"-- --id=@q0 create queue other-config:max-rate=2000000000 "
        f"-- --id=@q1 create queue other-config:min-rate={bps} other-config:max-rate={bps} >/dev/null")
    # Put GTP-U into queue 1 by rewriting the detection punt rule itself, so the
    # traffic is both shaped AND still mirrored to Ryu for detection. (A separate
    # priority-500 queue rule would be shadowed by the priority-1000 punt.)
    ovs("ovs-ofctl", "-O", "OpenFlow13", "mod-flows", "--strict", OVS_BRIDGE,
        f"{PUNT_RULE},actions=controller,set_queue:1,normal")
    print(f"   linux-htb queue 1 on {port} at {kbps} kbps; GTP-U steered into it by the punt rule")


def ovs_clear():
    port = upf_ovs_port()
    ovs("ovs-ofctl", "-O", "OpenFlow13", "mod-flows", "--strict", OVS_BRIDGE,
        f"{PUNT_RULE},actions=controller,normal")
    ovs("sh", "-c", f"ovs-vsctl -- clear port {port} qos -- --all destroy qos -- --all destroy queue >/dev/null 2>&1; true")
    print(f"   HTB queue removed from {port}; punt rule restored to controller,normal")


# ---------------------------------------------------------------- core AMBR
def core_ambr(imsi, approach, kbps, reregister):
    val, unit = (kbps, 1) if kbps else (1, 3)     # 0 -> restore 1 Gbit/s default
    js = (f"db.subscribers.updateOne({{imsi:'{imsi}'}},{{$set:{{"
          f"'ambr.downlink':{{value:{val},unit:{unit}}},'ambr.uplink':{{value:{val},unit:{unit}}},"
          f"'slice.0.session.0.ambr.downlink':{{value:{val},unit:{unit}}},"
          f"'slice.0.session.0.ambr.uplink':{{value:{val},unit:{unit}}}}}}}).matchedCount")
    n = dexec("mongo-container", "mongosh", "--quiet", f"mongodb://127.0.0.1:27017/{CORE_DB[approach]}",
              "--eval", js).strip()
    if n != "1":
        raise RuntimeError(f"IMSI {imsi} not found in {CORE_DB[approach]}")
    print(f"   Session-AMBR for {imsi} set to {'1 Gbit/s (default)' if not kbps else f'{kbps} kbps'} "
          f"in {CORE_DB[approach]}")
    if reregister:
        dexec(UE_CONTAINERS[approach], "sh", "-c",
              "pkill -x nr-ue 2>/dev/null; sleep 3; cd /ueransim && "
              "nohup ./nr-ue -c config/open5gs-ue1.yaml >/var/log/nr-ue.log 2>&1 & sleep 12")
        print(f"   {UE_CONTAINERS[approach]} re-registered; new tunnel address {ue_addr(approach)}")
    else:
        print("   takes effect at the next PDU session establishment (add --reregister to force it)")


# ---------------------------------------------------------------- status
def status():
    print("== P4 blocks (approach 2, /blocked-ips) ==")
    code, body = api("GET", "/blocked-ips")
    print("  " + (", ".join(b["ueip"] for b in body) if code == 200 and body else "(none)"))
    print("== P4 meter cells known to ONOS ==")
    cells = meter_cells()
    for k, v in sorted(cells.items(), key=lambda kv: kv[1])[:20]:
        print(f"  cell {v:>3}  {k}")
    if not cells:
        print("  (none)")
    rate = dexec("onos", "sh", "-c", "cat /tmp/qos_meter_index /tmp/qos_rate_kbps 2>/dev/null | tr '\\n' ' '",
                 check=False).split()
    print(f"  last write: cell {rate[0] if rate else '-'} rate {rate[1] if len(rate) > 1 else '-'} kbps"
          " (cells keep earlier writes)")
    print("== UPF iptables blocks (approach 1) ==")
    rules = [l for l in dexec(UPF_CONTAINER, "iptables", "-S", "FORWARD", check=False).splitlines() if TAG in l]
    print("\n".join("  " + r for r in rules) or "  (none)")
    print("== OVS tunnel shaping (approach 1) ==")
    try:
        flow = [l for l in ovs("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", OVS_BRIDGE).splitlines()
                if "cookie=0x1" in l]
        print("  punt rule: " + (flow[0].split("actions=")[-1] if flow else "MISSING - approach 1 detection is off"))
        q = ovs("sh", "-c", "ovs-vsctl list queue | grep other_config", check=False).strip()
        print("  queues: " + (q.replace("\n", " | ") if q else "(none)"))
    except RuntimeError as e:
        print(f"  unavailable: {e}")


# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["block", "limit", "clear", "status"])
    tgt = ap.add_mutually_exclusive_group()
    tgt.add_argument("--ue", metavar="IP")
    tgt.add_argument("--flow", metavar="SRC,DST,PROTO")
    tgt.add_argument("--tunnel", action="store_true", help="approach 1 aggregate gNB<->UPF tunnel")
    tgt.add_argument("--imsi")
    ap.add_argument("--rate", type=int, metavar="KBPS")
    ap.add_argument("--approach", type=int, choices=[1, 2])
    ap.add_argument("--reregister", action="store_true", help="with --imsi: re-register the UE now")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if a.action == "status":
        return status()
    if not (a.ue or a.flow or a.tunnel or a.imsi):
        ap.error("give a target: --ue, --flow, --tunnel or --imsi")
    if a.action == "limit" and not a.rate:
        ap.error("limit needs --rate KBPS")

    # ---- block
    if a.action == "block":
        if not a.ue:
            ap.error("block takes --ue IP (per-flow blocking is not implemented; see README)")
        appr, why = which_approach(a.ue, a.approach)
        if appr == 2:
            decide("P4 dropped_inner_ipv4 (approach 2)",
                   f"{why}; P4 matches the inner source inside GTP-U, dropping only this UE at line rate", a.dry_run)
            p4_block(a.ue)
        else:
            decide("UPF iptables DROP (approach 1)",
                   f"{why}; OVS cannot see inside GTP-U (a rule would drop every UE), so drop after "
                   "decapsulation at the UPF", a.dry_run)
            upf_block(a.ue)
        return

    # ---- limit / clear
    rate = 0 if a.action == "clear" else a.rate
    if a.imsi:
        appr = a.approach or 1
        decide(f"core Session-AMBR (approach {appr})",
               "per-subscriber cap enforced by the UPF shaper; tracks the setpoint best (~1.1x) "
               "but only applies at session establishment", a.dry_run)
        return core_ambr(a.imsi, appr, rate, a.reregister)

    if a.tunnel:
        decide("OVS linux-htb queue via OpenFlow set_queue (approach 1)",
               "aggregate tunnel shaping; the queue tracks ~0.95x, OVS policers only ~0.5x", a.dry_run)
        return ovs_clear() if a.action == "clear" else ovs_limit(rate)

    if a.flow:
        src, dst, proto = (x.strip() for x in a.flow.split(","))
        appr, why = which_approach(src, a.approach)
        if appr == 1:
            sys.exit("x  approach 1 cannot limit a single flow: OVS has no GTP parser, so every UE and flow "
                     "shares one outer 5-tuple. Use --imsi (core) or --tunnel (aggregate).")
        cell = meter_cells().get(f"{src}-{dst}-{proto}")
        if cell is None:
            sys.exit(f"x  no meter cell for {src}-{dst}-{proto} yet - it is allocated on the flow's first packet")
        decide("P4 per-flow meter (approach 2)",
               f"{why}; one inner (src,dst,proto) flow = one meter cell ({cell})", a.dry_run)
        p4_set_cell(cell, rate)
        print(f"   meter cell {cell} -> {'unlimited' if not rate else f'{rate} kbps'}")
        return

    if a.ue:
        if a.action == "clear" and not a.rate:
            # clear --ue lifts BOTH a block and any per-UE meter limits.
            appr, why = which_approach(a.ue, a.approach)
            if appr == 1:
                decide("UPF iptables (approach 1)", why, a.dry_run)
                return upf_unblock(a.ue)
            decide("P4 (approach 2)", f"{why}; removing block and meter limits", a.dry_run)
            p4_unblock(a.ue)
            for key, cell in meter_cells().items():
                if key.startswith(a.ue + "-") or f"-{a.ue}-" in key:
                    p4_set_cell(cell, 0)
            return
        appr, why = which_approach(a.ue, a.approach)
        if appr == 1:
            sys.exit("x  approach 1 cannot limit one UE in the switch (OVS can't see inside GTP-U). "
                     "Use --imsi for a per-subscriber cap in the core.")
        cells = {k: c for k, c in meter_cells().items() if k.startswith(a.ue + "-")}
        if not cells:
            sys.exit(f"x  no flows seen from {a.ue} yet - send some traffic first")
        decide("P4 per-flow meters, every uplink flow of this UE (approach 2)",
               f"{why}; applies the rate to each of its {len(cells)} flow cells", a.dry_run)
        for key, cell in cells.items():
            p4_set_cell(cell, rate)
            print(f"   cell {cell:>3} ({key}) -> {'unlimited' if not rate else f'{rate} kbps'}")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        sys.exit(f"x  {e}")
