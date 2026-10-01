#!/usr/bin/env python3
"""testbed-agent: the bounded control surface RA3 drives to enforce actions.

RA3's executor runs sandboxed (no network of its own). It reaches this agent
over one HTTP endpoint, and the agent translates each RA3 action into the
matching testbed operation:

  network-side (before traffic reaches the victim, at the P4 switch / core):
    POST /block        {ue_ip, duration_minutes}   -> flow API /blocked-ip + auto-unblock timer
    POST /unblock      {ue_ip}                       -> enforce.py clear --ue
    POST /rate_limit   {ue_ip, kbps}                 -> enforce.py limit --ue (P4 meter)

  server-side (on the victim itself):
    POST /syn_cookie        {enable, duration_minutes}  -> sysctl net.ipv4.tcp_syncookies
    POST /conn_timeout      {seconds}                    -> nginx client/keepalive timeouts
    POST /http_rate_limit   {requests_per_minute, per_ip} -> nginx limit_req
    POST /close_ports       {ports, duration_minutes}    -> victim iptables drop
    POST /open_ports        {ports}

  5G core-side (per-UE subscriber in Open5GS):
    POST /throttle_ue    {ue_ip, mbps, duration_minutes}  -> P4 per-UE meter + subscriber AMBR
    POST /quarantine_ue  {ue_ip, duration_minutes, reason}-> P4 drop (isolation) + subscriber barring

  read-only:
    GET  /metrics      -> victim metrics passthrough
    GET  /status       -> what is currently enforced
    GET  /health

Everything is scoped: block targets are validated as UE-pool addresses, ports
must be integers, and the agent only ever touches the fixed testbed containers.
It talks to the host Docker daemon (mounted socket) and the flow API.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import subprocess
import threading
import time
import urllib.request

FLOW_API = os.environ.get("FLOW_API", "http://172.17.0.1:23500")
VICTIM = os.environ.get("VICTIM_CONTAINER", "victim")
UE = os.environ.get("UE_CONTAINER", "ue-2")
A2_HOST = os.environ.get("A2_HOST_CONTAINER", "a2-host")
REPO = os.environ.get("REPO_DIR", "/repo")
UE_POOL = os.environ.get("UE_POOL_PREFIX", "10.45.")
PORT = int(os.environ.get("AGENT_PORT", "8090"))
# 5G core (Open5GS subscriber DB in MongoDB) -- used by the 5G-native actions
# (throttle_ue / quarantine_ue) to change a subscriber's AMBR / barring status.
MONGO = os.environ.get("MONGO_CONTAINER", "mongo-container")
OPEN5GS_DB = os.environ.get("OPEN5GS_DB", "open5gs_a2")
# 5G control plane (AMF log) + RAN (UERANSIM gNB) -- used by quarantine_ue to
# FORCE-DETACH an attached UE (barring alone only blocks re-registration, it does
# not stop control-plane procedures from a UE that is already registered).
CP = os.environ.get("CP_CONTAINER", "cp-2")
GNB = os.environ.get("GNB_CONTAINER", "gnb-2")
GNB_NODE = os.environ.get("GNB_NODE", "UERANSIM-gnb-1-1-1")
GNB_DIR = os.environ.get("GNB_DIR", "/ueransim")
AMF_LOG = os.environ.get("AMF_LOG", "/var/log/open5gs/amf.out")
# The testbed's default subscriber AMBR, restored when a throttle is released.
DEFAULT_AMBR_VALUE = int(os.environ.get("DEFAULT_AMBR_VALUE", "1"))
DEFAULT_AMBR_UNIT = int(os.environ.get("DEFAULT_AMBR_UNIT", "3"))  # 0 bps,1 Kbps,2 Mbps,3 Gbps

_state_lock = threading.Lock()
_enforced: dict[str, dict] = {}   # key -> {action, args, expires_at}
_timers: dict[str, threading.Timer] = {}


# --------------------------------------------------------------------------
def sh(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def dexec(container: str, *cmd: str, timeout: int = 30) -> tuple[int, str]:
    return sh(["docker", "exec", container, *cmd], timeout=timeout)


def mongo_eval(js: str, timeout: int = 20) -> tuple[int, str]:
    """Run a mongosh snippet against the Open5GS subscriber DB."""
    return sh(["docker", "exec", MONGO, "mongosh", "--quiet",
               f"mongodb://127.0.0.1:27017/{OPEN5GS_DB}", "--eval", js], timeout=timeout)


def flow_api(method: str, path: str) -> tuple[int, str]:
    req = urllib.request.Request(FLOW_API + path, method=method)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        return e.code, e.read().decode()
    except Exception as e:  # noqa: BLE001
        return 0, str(e)


def is_ue(ip: str) -> bool:
    return isinstance(ip, str) and ip.startswith(UE_POOL)


def _schedule_unblock(key: str, fn, minutes: float) -> None:
    old = _timers.pop(key, None)
    if old:
        old.cancel()
    if minutes and minutes > 0:
        t = threading.Timer(minutes * 60, fn)
        t.daemon = True
        t.start()
        _timers[key] = t


# ---- action implementations ----------------------------------------------
def do_block(a: dict) -> dict:
    ip = a["ue_ip"]
    if not is_ue(ip):
        return {"ok": False, "error": f"{ip} is not a UE-pool address"}
    code, body = flow_api("POST", f"/blocked-ip/{ip}")
    ok = code in (200, 400)  # 400 = already blocked
    mins = float(a.get("duration_minutes") or 0)
    key = f"block:{ip}"
    with _state_lock:
        _enforced[key] = {"action": "block", "ue_ip": ip,
                          "expires_at": (time.time() + mins * 60) if mins else None}
    _schedule_unblock(key, lambda: do_unblock({"ue_ip": ip}), mins)
    return {"ok": ok, "mechanism": "P4 dropped_inner_ipv4 (via flow API)",
            "flow_api_status": code, "auto_unblock_minutes": mins or None}


def do_unblock(a: dict) -> dict:
    ip = a["ue_ip"]
    code, body = sh(["docker", "exec", "-w", REPO, A2_HOST,
                     "python3", "tools/enforce.py", "clear", "--ue", ip])
    with _state_lock:
        _enforced.pop(f"block:{ip}", None)
        _enforced.pop(f"rate:{ip}", None)
    return {"ok": code == 0, "detail": body[-300:]}


def do_rate_limit(a: dict) -> dict:
    ip = a["ue_ip"]
    kbps = int(a.get("kbps") or 10000)
    if not is_ue(ip):
        return {"ok": False, "error": f"{ip} is not a UE-pool address"}
    code, body = sh(["docker", "exec", "-w", REPO, A2_HOST, "python3", "tools/enforce.py",
                     "limit", "--ue", ip, "--rate", str(kbps)])
    with _state_lock:
        _enforced[f"rate:{ip}"] = {"action": "rate_limit", "ue_ip": ip, "kbps": kbps, "expires_at": None}
    return {"ok": code == 0, "mechanism": "P4 per-flow meter", "kbps": kbps, "detail": body[-300:]}


def do_syn_cookie(a: dict) -> dict:
    enable = a.get("enable", True)
    val = "1" if enable else "0"
    code, body = dexec(VICTIM, "sysctl", "-w", f"net.ipv4.tcp_syncookies={val}")
    mins = float(a.get("duration_minutes") or 0)
    if enable:
        _schedule_unblock("syncookie", lambda: do_syn_cookie({"enable": False}), mins)
    with _state_lock:
        if enable:
            _enforced["syncookie"] = {"action": "syn_cookie",
                                      "expires_at": (time.time() + mins * 60) if mins else None}
        else:
            _enforced.pop("syncookie", None)
    return {"ok": code == 0, "mechanism": "victim sysctl tcp_syncookies", "value": val, "detail": body[-200:]}


def do_conn_timeout(a: dict) -> dict:
    secs = int(a.get("seconds") or 15)
    script = (
        f"sed -i -E 's/(client_body_timeout)\\s+[0-9]+s;/\\1 {secs}s;/; "
        f"s/(client_header_timeout)\\s+[0-9]+s;/\\1 {secs}s;/; "
        f"s/(keepalive_timeout)\\s+[0-9]+s;/\\1 {secs}s;/' /etc/nginx/nginx.conf "
        f"&& nginx -s reload")
    code, body = dexec(VICTIM, "sh", "-c", script)
    with _state_lock:
        _enforced["conn_timeout"] = {"action": "set_connection_timeout", "seconds": secs, "expires_at": None}
    return {"ok": code == 0, "mechanism": "victim nginx timeouts", "seconds": secs, "detail": body[-200:]}


def do_http_rate_limit(a: dict) -> dict:
    rpm = int(a.get("requests_per_minute") or 600)
    rps = max(1, rpm // 60)
    per_ip = a.get("per_ip", True)
    key = "$binary_remote_addr" if per_ip else "$server_name"
    # Fill the two markers in nginx.conf. Reset them first so repeated calls
    # re-set the rate instead of stacking directives.
    zone = f"limit_req_zone {key} zone=perip:10m rate={rps}r/s;"
    script = (
        "cfg=/etc/nginx/nginx.conf; "
        # remove any directives a previous call inserted (so calls don't stack)
        "sed -i -E '/limit_req_zone .* zone=perip:/d; /limit_req zone=perip/d' $cfg; "
        # insert fresh ones right after each marker
        f"sed -i 's|#RA3_RATE_LIMIT_ZONE|#RA3_RATE_LIMIT_ZONE\\n    {zone}|' $cfg; "
        "sed -i 's|#RA3_RATE_LIMIT_REQ|#RA3_RATE_LIMIT_REQ\\n            limit_req zone=perip burst=20 nodelay;|' $cfg; "
        "nginx -t 2>/dev/null && nginx -s reload")
    code, body = dexec(VICTIM, "sh", "-c", script)
    with _state_lock:
        _enforced["http_rate_limit"] = {"action": "enable_http_rate_limit",
                                        "requests_per_minute": rpm, "per_ip": per_ip, "expires_at": None}
    return {"ok": code == 0, "mechanism": "victim nginx limit_req", "requests_per_minute": rpm,
            "rate_rps": rps, "detail": body[-200:]}


def do_close_ports(a: dict) -> dict:
    ports = [int(p) for p in a.get("ports", [])]
    mins = float(a.get("duration_minutes") or 0)
    done = []
    for p in ports:
        for proto in ("tcp", "udp"):
            dexec(VICTIM, "sh", "-c",
                  f"iptables -C INPUT -p {proto} --dport {p} -j DROP 2>/dev/null || "
                  f"iptables -A INPUT -p {proto} --dport {p} -j DROP")
        done.append(p)
    if mins > 0:
        _schedule_unblock("ports", lambda: do_open_ports({"ports": ports}), mins)
    with _state_lock:
        _enforced["close_ports"] = {"action": "close_unnecessary_ports", "ports": done,
                                    "expires_at": (time.time() + mins * 60) if mins else None}
    return {"ok": True, "mechanism": "victim iptables DROP", "closed_ports": done}


def do_open_ports(a: dict) -> dict:
    ports = [int(p) for p in a.get("ports", [])]
    for p in ports:
        for proto in ("tcp", "udp"):
            dexec(VICTIM, "sh", "-c", f"iptables -D INPUT -p {proto} --dport {p} -j DROP 2>/dev/null || true")
    with _state_lock:
        _enforced.pop("close_ports", None)
    return {"ok": True, "reopened_ports": ports}


def do_throttle_ue(a: dict) -> dict:
    """5G-native bandwidth cap: a per-UE P4 meter (immediate) + the subscriber's
    AMBR in the core (applies to future PDU sessions). Softer than block."""
    ip = a["ue_ip"]
    if not is_ue(ip):
        return {"ok": False, "error": f"{ip} is not a UE-pool address"}
    mbps = int(a.get("mbps") or 5)
    kbps = max(1, mbps * 1000)
    mins = float(a.get("duration_minutes") or 0)
    # 1) data-plane: meter the UE's flows now
    code, body = sh(["docker", "exec", "-w", REPO, A2_HOST, "python3", "tools/enforce.py",
                     "limit", "--ue", ip, "--rate", str(kbps)])
    meter_ok = code == 0
    # 2) core: write the subscriber AMBR (down/up) to mbps
    ambr = f'{{value:{mbps},unit:2}}'
    mcode, mbody = mongo_eval(
        f'var r=db.subscribers.updateOne({{"slice.session.ue.addr":"{ip}"}},'
        f'{{$set:{{"ambr.downlink":{ambr},"ambr.uplink":{ambr},'
        f'"slice.$[].session.$[].ambr.downlink":{ambr},"slice.$[].session.$[].ambr.uplink":{ambr}}}}});'
        f'print(r.matchedCount);')
    core_ok = mcode == 0 and (mbody.strip().endswith("1"))

    def _restore():
        do_unblock({"ue_ip": ip})
        da = f'{{value:{DEFAULT_AMBR_VALUE},unit:{DEFAULT_AMBR_UNIT}}}'
        mongo_eval(f'db.subscribers.updateOne({{"slice.session.ue.addr":"{ip}"}},'
                   f'{{$set:{{"ambr.downlink":{da},"ambr.uplink":{da},'
                   f'"slice.$[].session.$[].ambr.downlink":{da},"slice.$[].session.$[].ambr.uplink":{da}}}}});')

    _schedule_unblock(f"throttle:{ip}", _restore, mins)
    with _state_lock:
        _enforced[f"throttle:{ip}"] = {"action": "throttle_ue_bandwidth", "ue_ip": ip,
                                       "mbps": mbps, "expires_at": (time.time() + mins * 60) if mins else None}
    return {"ok": meter_ok, "mechanism": "P4 per-UE meter + core AMBR", "mbps": mbps,
            "kbps": kbps, "core_ambr_updated": core_ok, "detail": body[-200:]}


def _imsi_for_ip(ip: str) -> str | None:
    code, out = mongo_eval(f'var d=db.subscribers.findOne({{"slice.session.ue.addr":"{ip}"}},'
                           f'{{imsi:1}}); if(d) print(d.imsi);')
    m = re.search(r"(\d{15})", out)
    return m.group(1) if m else None


def _amf_ngap_for_imsi(imsi: str) -> str | None:
    """The AMF_UE_NGAP_ID tied to this IMSI's most recent registration (amf.out)."""
    code, log = dexec(CP, "sh", "-c", f"tail -n 600 {AMF_LOG}")
    last_y, reg_y = None, None
    for ln in log.splitlines():
        # Only the InitialContextSetup line carries the ACTIVE context id; it is
        # the one that also prints CellID. Release lines (…ngap-handler.c:1399)
        # also print AMF_UE_NGAP_ID but refer to a context being torn down.
        m = re.search(r"AMF_UE_NGAP_ID\[(\d+)\]", ln)
        if m and "CellID" in ln:
            last_y = m.group(1)
        if ("imsi-" + imsi) in ln and "Registration complete" in ln:
            reg_y = last_y
    return reg_y


def _gnb_ueid_for_amfngap(y: str) -> str | None:
    code, lst = dexec(GNB, "sh", "-c", f"cd {GNB_DIR} && ./nr-cli {GNB_NODE} -e 'ue-list'")
    cur, found = None, None
    for ln in lst.splitlines():
        m = re.search(r"ue-id:\s*(\d+)", ln)
        if m:
            cur = m.group(1)
        m2 = re.search(r"amf-ngap-id:\s*(\d+)", ln)
        if m2 and m2.group(1) == str(y):
            found = cur
    return found


def force_detach_ue(ip: str) -> dict:
    """Release the UE's context at the gNB (true detach). Barring then stops it
    from re-registering. Returns what was released."""
    imsi = _imsi_for_ip(ip)
    if not imsi:
        return {"detached": False, "why": f"no IMSI for {ip}"}
    y = _amf_ngap_for_imsi(imsi)
    ueid = _gnb_ueid_for_amfngap(y) if y else None
    if not ueid:
        return {"detached": False, "imsi": imsi, "amf_ngap_id": y, "why": "no gNB ue-id match"}
    code, out = dexec(GNB, "sh", "-c", f"cd {GNB_DIR} && ./nr-cli {GNB_NODE} -e 'ue-release {ueid}'")
    return {"detached": code == 0, "imsi": imsi, "amf_ngap_id": y, "gnb_ue_id": ueid,
            "detail": out[-120:]}


def do_quarantine_ue(a: dict) -> dict:
    """5G-native cut-off: isolate the UE in the data plane (drop its inner IP at
    the switch) AND bar the subscriber in the core (subscriber_status=1) so it
    cannot re-register. Targets the one subscriber, not just an IP."""
    ip = a["ue_ip"]
    if not is_ue(ip):
        return {"ok": False, "error": f"{ip} is not a UE-pool address"}
    mins = float(a.get("duration_minutes") or 0)
    # 1) data-plane: drop all of the UE's traffic at the switch
    code, body = flow_api("POST", f"/blocked-ip/{ip}")
    iso_ok = code in (200, 400)  # 400 = already blocked
    # 2) core: bar the subscriber (operator-determined barring)
    mcode, mbody = mongo_eval(
        f'var r=db.subscribers.updateOne({{"slice.session.ue.addr":"{ip}"}},'
        f'{{$set:{{subscriber_status:1}}}});print(r.matchedCount);')
    bar_ok = mcode == 0 and mbody.strip().endswith("1")
    # 3) RAN: force-detach the UE at the gNB. Barring alone only blocks a FUTURE
    # registration; a UE already attached keeps running control-plane procedures
    # until its context is released. ue-release + barring = a real cut-off.
    detach = force_detach_ue(ip)

    def _release():
        do_unblock({"ue_ip": ip})
        mongo_eval(f'db.subscribers.updateOne({{"slice.session.ue.addr":"{ip}"}},'
                   f'{{$set:{{subscriber_status:0}}}});')

    _schedule_unblock(f"quarantine:{ip}", _release, mins)
    with _state_lock:
        _enforced[f"quarantine:{ip}"] = {"action": "quarantine_ue", "ue_ip": ip,
                                         "reason": a.get("reason", ""),
                                         "expires_at": (time.time() + mins * 60) if mins else None}
    return {"ok": iso_ok, "mechanism": "P4 drop (isolation) + core barring + gNB force-detach",
            "flow_api_status": code, "subscriber_barred": bar_ok, "force_detach": detach,
            "auto_release_minutes": mins or None}


def get_metrics() -> dict:
    code, body = dexec(VICTIM, "python3", "-c",
                       "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:9100/metrics').read().decode())")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"error": "victim metrics unavailable", "detail": body[-200:]}


ACTIONS = {
    "/block": do_block, "/unblock": do_unblock, "/rate_limit": do_rate_limit,
    "/syn_cookie": do_syn_cookie, "/conn_timeout": do_conn_timeout,
    "/http_rate_limit": do_http_rate_limit, "/close_ports": do_close_ports,
    "/open_ports": do_open_ports,
    "/throttle_ue": do_throttle_ue, "/quarantine_ue": do_quarantine_ue,
}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.rstrip("/") or "/"
        if path == "/health":
            self._send(200, {"status": "ok"})
        elif path == "/metrics":
            self._send(200, get_metrics())
        elif path == "/status":
            with _state_lock:
                self._send(200, {"enforced": _enforced})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.rstrip("/") or "/"
        fn = ACTIONS.get(path)
        if fn is None:
            self._send(404, {"error": f"unknown action {path}"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            args = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid JSON"})
            return
        try:
            self._send(200, fn(args))
        except Exception as e:  # noqa: BLE001
            self._send(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})

    def log_message(self, fmt, *args) -> None:
        print("agent " + (fmt % args), flush=True)


def main() -> None:
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"testbed-agent on :{PORT}  flow_api={FLOW_API} victim={VICTIM}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
