"""RA3 MCP server.

Exposes the 9 response actions as MCP tools over the streamable-HTTP
transport. When a tool is called, execution is delegated to an ephemeral
Docker container (see runner.py). The tool signatures mirror the JSON schemas
in server/actions.py so that the LLM's selected actions map 1:1 onto MCP tool
calls.

NB: do NOT add `from __future__ import annotations` here — FastMCP introspects
the real annotation objects at tool-registration time, and stringized
annotations break its Context detection (get_origin/issubclass on a str).
"""

import logging
import os

from mcp.server.fastmcp import FastMCP

import training
from runner import run_in_container

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
)

mcp = FastMCP("ra3-actions", host="0.0.0.0", port=9000)


@mcp.tool()
def enable_syn_cookie(client_id: str, duration_minutes: int = 60) -> dict:
    """Enable SYN Cookie on the target node to stop half-open TCP connections."""
    return run_in_container("enable_syn_cookie", {
        "client_id": client_id, "duration_minutes": duration_minutes,
    })


@mcp.tool()
def rate_limit(client_id: str, protocol: str, pps_limit: int) -> dict:
    """Apply an inbound packet-rate limit for a given protocol (icmp/udp/tcp)."""
    return run_in_container("rate_limit", {
        "client_id": client_id, "protocol": protocol, "pps_limit": pps_limit,
    })


@mcp.tool()
def block_ip(client_id: str, ip_list: list[str], duration_minutes: int = 30) -> dict:
    """Block a batch of source IPs; auto-released after duration_minutes."""
    return run_in_container("block_ip", {
        "client_id": client_id, "ip_list": ip_list, "duration_minutes": duration_minutes,
    })


@mcp.tool()
def set_connection_timeout(client_id: str, timeout_seconds: int) -> dict:
    """Shorten the connection idle timeout to evict slow-rate connections."""
    return run_in_container("set_connection_timeout", {
        "client_id": client_id, "timeout_seconds": timeout_seconds,
    })


@mcp.tool()
def close_unnecessary_ports(client_id: str, port_list: list[int]) -> dict:
    """Close unnecessary open ports to reduce the attack surface."""
    return run_in_container("close_unnecessary_ports", {
        "client_id": client_id, "port_list": port_list,
    })


@mcp.tool()
def enable_http_rate_limit(client_id: str, requests_per_minute: int, per_ip: bool = True) -> dict:
    """Rate limit HTTP requests at the WAF / reverse-proxy layer."""
    return run_in_container("enable_http_rate_limit", {
        "client_id": client_id, "requests_per_minute": requests_per_minute, "per_ip": per_ip,
    })


@mcp.tool()
def alert_operator(incident_id: str, severity: str, message: str, channel: str = "email") -> dict:
    """Notify on-call operations staff (mandatory for high/critical severity)."""
    return run_in_container("alert_operator", {
        "incident_id": incident_id, "severity": severity, "message": message, "channel": channel,
    })


@mcp.tool()
def log_incident(incident_id: str, action_taken: str, notes: str = "") -> dict:
    """Write a complete audit log entry for the incident (mandatory every time)."""
    return run_in_container("log_incident", {
        "incident_id": incident_id, "action_taken": action_taken, "notes": notes,
    })


@mcp.tool()
def share_threat_intel(attack_type: str, source_pattern: str, affected_nodes: list[str]) -> dict:
    """Broadcast threat intelligence to peer nodes for federated early-warning."""
    return run_in_container("share_threat_intel", {
        "attack_type": attack_type, "source_pattern": source_pattern, "affected_nodes": affected_nodes,
    })


@mcp.tool()
def throttle_ue_bandwidth(client_id: str, mbps: int = 5, duration_minutes: int = 30) -> dict:
    """5G-native: cap the offending UE's bandwidth (per-UE meter + core AMBR)."""
    return run_in_container("throttle_ue_bandwidth", {
        "client_id": client_id, "mbps": mbps, "duration_minutes": duration_minutes,
    })


@mcp.tool()
def quarantine_ue(client_id: str, duration_minutes: int = 30, reason: str = "") -> dict:
    """5G-native: isolate + force-detach the UE and bar the subscriber in the core."""
    return run_in_container("quarantine_ue", {
        "client_id": client_id, "duration_minutes": duration_minutes, "reason": reason,
    })


# ---------------------------------------------------------------------------
# Model maintenance tools. NOT response actions: they are absent from the action
# catalog (server/actions.py), so the decision engine can never select them;
# only the RA3 training API calls them.
# ---------------------------------------------------------------------------
@mcp.tool()
def training_start_job(job_id: str, base_model: str, dataset: str, mode: str = "dry_run",
                       method: str = "lora", hyperparams: dict | None = None,
                       simulate_seconds: float = 0) -> dict:
    """Start a fine-tuning job in a detached trainer container; returns immediately."""
    return training.start_job(job_id, {
        "base_model": base_model, "dataset": dataset, "mode": mode, "method": method,
        "hyperparams": hyperparams or {}, "simulate_seconds": simulate_seconds,
    })


@mcp.tool()
def training_get_job(job_id: str) -> dict:
    """Report a fine-tuning job's state and the trainer's status.json."""
    return training.get_job(job_id)


if __name__ == "__main__":
    # Serves the MCP endpoint at http://0.0.0.0:9000/mcp
    mcp.run(transport="streamable-http")
