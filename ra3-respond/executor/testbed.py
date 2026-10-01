"""Testbed execution: map each RA3 action onto a testbed-agent call.

When EXECUTOR_MODE=testbed, the executor stops simulating and actually enforces
the action on the 5G SDN DDoS testbed, by POSTing to the testbed-agent
(AGENT_URL). The agent performs the real operation (P4 drop/meter, or a change
on the victim) and returns what it did.

  network-side (before traffic reaches the victim):
    block_ip        -> /block      (P4 dropped_inner_ipv4)
    rate_limit      -> /rate_limit  (P4 per-flow meter)
  server-side (on the victim):
    enable_syn_cookie      -> /syn_cookie
    set_connection_timeout -> /conn_timeout
    enable_http_rate_limit -> /http_rate_limit
    close_unnecessary_ports-> /close_ports
  local (no testbed effect): alert_operator, log_incident, share_threat_intel

The RA3 alert addresses a node by client_id; on the testbed the compromised
node is one UE. TESTBED_UE_IP (default 10.45.0.3) is the address block_ip and
rate_limit act on, regardless of the placeholder IPs in the decision.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

AGENT_URL = os.getenv("AGENT_URL", "http://172.17.0.1:8090")
UE_IP = os.getenv("TESTBED_UE_IP", "10.45.0.3")
# per-flow meter is byte-rate (kbps); RA3 rate_limit is in packets/s. Convert
# with a nominal average packet size so a pps limit becomes a kbps meter.
AVG_PKT_BYTES = int(os.getenv("TESTBED_AVG_PKT_BYTES", "800"))


def _agent(path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(AGENT_URL + path, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"agent {e.code}: {e.read().decode()[:200]}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _pps_to_kbps(pps: int) -> int:
    return max(1, int(pps * AVG_PKT_BYTES * 8 / 1000))


def block_ip(client_id: str, ip_list: list[str], duration_minutes: int = 30, **_: Any) -> dict:
    r = _agent("/block", {"ue_ip": UE_IP, "duration_minutes": duration_minutes})
    return {"effect": f"blocked UE {UE_IP} at the P4 switch", "testbed": r,
            "requested_ip_list": ip_list, "duration_minutes": duration_minutes}


def rate_limit(client_id: str, protocol: str, pps_limit: int, **_: Any) -> dict:
    kbps = _pps_to_kbps(pps_limit)
    r = _agent("/rate_limit", {"ue_ip": UE_IP, "kbps": kbps})
    return {"effect": f"metered UE {UE_IP} at ~{kbps} kbps (from {pps_limit} pps)",
            "protocol": protocol, "testbed": r}


def throttle_ue_bandwidth(client_id: str, mbps: int = 5, duration_minutes: int = 30, **_: Any) -> dict:
    r = _agent("/throttle_ue", {"ue_ip": UE_IP, "mbps": mbps, "duration_minutes": duration_minutes})
    return {"effect": f"throttled UE {UE_IP} to {mbps} Mbit/s (P4 meter + core AMBR)",
            "mbps": mbps, "duration_minutes": duration_minutes, "testbed": r}


def quarantine_ue(client_id: str, duration_minutes: int = 30, reason: str = "", **_: Any) -> dict:
    r = _agent("/quarantine_ue", {"ue_ip": UE_IP, "duration_minutes": duration_minutes, "reason": reason})
    return {"effect": f"quarantined UE {UE_IP} (switch isolation + core barring)",
            "duration_minutes": duration_minutes, "reason": reason, "testbed": r}


def enable_syn_cookie(client_id: str, duration_minutes: int = 60, **_: Any) -> dict:
    r = _agent("/syn_cookie", {"enable": True, "duration_minutes": duration_minutes})
    return {"effect": "SYN cookies enabled on the victim", "duration_minutes": duration_minutes, "testbed": r}


def set_connection_timeout(client_id: str, timeout_seconds: int, **_: Any) -> dict:
    r = _agent("/conn_timeout", {"seconds": timeout_seconds})
    return {"effect": f"victim idle timeout set to {timeout_seconds}s", "testbed": r}


def close_unnecessary_ports(client_id: str, port_list: list[int], **_: Any) -> dict:
    r = _agent("/close_ports", {"ports": port_list, "duration_minutes": 30})
    return {"effect": f"closed {len(port_list)} port(s) on the victim", "closed_ports": port_list, "testbed": r}


def enable_http_rate_limit(client_id: str, requests_per_minute: int, per_ip: bool = True, **_: Any) -> dict:
    r = _agent("/http_rate_limit", {"requests_per_minute": requests_per_minute, "per_ip": per_ip})
    return {"effect": f"victim HTTP rate limit {requests_per_minute}/min", "per_ip": per_ip, "testbed": r}


# Local actions: no testbed effect, mirror the mock result so the pipeline is unchanged.
def alert_operator(incident_id: str, severity: str, message: str, channel: str = "email", **_: Any) -> dict:
    return {"effect": f"Operator alerted via {channel}", "incident_id": incident_id,
            "severity": severity, "message": message}


def log_incident(incident_id: str, action_taken: str, notes: str = "", **_: Any) -> dict:
    return {"effect": "Incident logged for audit", "incident_id": incident_id,
            "action_taken": action_taken, "notes": notes}


def share_threat_intel(attack_type: str, source_pattern: str, affected_nodes: list[str], **_: Any) -> dict:
    return {"effect": "Threat intelligence broadcast to federation", "attack_type": attack_type,
            "source_pattern": source_pattern, "affected_nodes": affected_nodes}


HANDLERS: dict[str, Any] = {
    "enable_syn_cookie": enable_syn_cookie,
    "rate_limit": rate_limit,
    "throttle_ue_bandwidth": throttle_ue_bandwidth,
    "quarantine_ue": quarantine_ue,
    "block_ip": block_ip,
    "set_connection_timeout": set_connection_timeout,
    "close_unnecessary_ports": close_unnecessary_ports,
    "enable_http_rate_limit": enable_http_rate_limit,
    "alert_operator": alert_operator,
    "log_incident": log_incident,
    "share_threat_intel": share_threat_intel,
}
