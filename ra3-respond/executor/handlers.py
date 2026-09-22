"""Mock implementations of the 9 RA3 response actions.

Each function runs inside an ephemeral, network-isolated Docker container
(one container per action invocation). In this mock mode the functions do NOT
touch a real firewall / kernel / WAF — they *simulate* the mitigation and
return a structured description of what would have happened. Swapping in real
implementations later only requires editing these functions.

Every handler accepts **_ so that unexpected extra arguments coming from the
LLM never crash execution.
"""

from __future__ import annotations

from typing import Any


def enable_syn_cookie(client_id: str, duration_minutes: int = 60, **_: Any) -> dict:
    return {
        "effect": f"SYN cookies enabled on {client_id}",
        "duration_minutes": duration_minutes,
        "note": "Half-open connections will now be validated via cookies.",
    }


def rate_limit(client_id: str, protocol: str, pps_limit: int, **_: Any) -> dict:
    return {
        "effect": f"Inbound {protocol.upper()} rate limited on {client_id}",
        "pps_limit": pps_limit,
    }


def block_ip(client_id: str, ip_list: list[str], duration_minutes: int = 30, **_: Any) -> dict:
    return {
        "effect": f"Blocked {len(ip_list)} source IP(s) on {client_id}",
        "blocked_ips": ip_list,
        "duration_minutes": duration_minutes,
    }


def set_connection_timeout(client_id: str, timeout_seconds: int, **_: Any) -> dict:
    return {
        "effect": f"Connection idle timeout on {client_id} set to {timeout_seconds}s",
        "timeout_seconds": timeout_seconds,
    }


def close_unnecessary_ports(client_id: str, port_list: list[int], **_: Any) -> dict:
    return {
        "effect": f"Closed {len(port_list)} port(s) on {client_id}",
        "closed_ports": port_list,
    }


def enable_http_rate_limit(client_id: str, requests_per_minute: int, per_ip: bool = True, **_: Any) -> dict:
    return {
        "effect": f"HTTP rate limit applied on {client_id}",
        "requests_per_minute": requests_per_minute,
        "per_ip": per_ip,
    }


def alert_operator(incident_id: str, severity: str, message: str, channel: str = "email", **_: Any) -> dict:
    return {
        "effect": f"Operator alerted via {channel}",
        "incident_id": incident_id,
        "severity": severity,
        "message": message,
    }


def log_incident(incident_id: str, action_taken: str, notes: str = "", **_: Any) -> dict:
    return {
        "effect": "Incident logged for audit",
        "incident_id": incident_id,
        "action_taken": action_taken,
        "notes": notes,
    }


def share_threat_intel(attack_type: str, source_pattern: str, affected_nodes: list[str], **_: Any) -> dict:
    return {
        "effect": "Threat intelligence broadcast to federation",
        "attack_type": attack_type,
        "source_pattern": source_pattern,
        "affected_nodes": affected_nodes,
    }


HANDLERS: dict[str, Any] = {
    "enable_syn_cookie": enable_syn_cookie,
    "rate_limit": rate_limit,
    "block_ip": block_ip,
    "set_connection_timeout": set_connection_timeout,
    "close_unnecessary_ports": close_unnecessary_ports,
    "enable_http_rate_limit": enable_http_rate_limit,
    "alert_operator": alert_operator,
    "log_incident": log_incident,
    "share_threat_intel": share_threat_intel,
}
