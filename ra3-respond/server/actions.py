"""Response-action catalog.

Each action is expressed as an Anthropic tool definition (`name`,
`description`, `input_schema`). The same definitions are used to:

  * build the `tools` list passed to Claude for function calling (llm.py), and
  * document the catalog via GET /actions.

The DB seed (db/init.sql) mirrors these definitions so that a fresh
deployment already has the catalog persisted.
"""

from __future__ import annotations

from typing import Any

# Every threat class that warrants an active response (Normal excluded).
ALL_THREATS: list[str] = [
    "ICMP_Flood",
    "UDP_Flood",
    "SYN_Flood",
    "HTTP_Flood",
    "Slowrate_DoS",
    "SYN_Scan",
    "TCP_Connect_Scan",
    "UDP_Scan",
]


# Each entry: the Anthropic tool schema + RA3-specific metadata under `_meta`.
ACTION_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "enable_syn_cookie",
        "description": (
            "Enable SYN Cookie on the target node to stop half-open TCP "
            "connections from exhausting the connection state table."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string", "description": "Target node ID, e.g. bs_node_01"},
                "duration_minutes": {
                    "type": "integer",
                    "description": "How long to keep SYN cookies enabled",
                    "default": 60,
                },
            },
            "required": ["client_id"],
        },
        "_meta": {"applicable_threats": ["SYN_Flood"], "severity_threshold": "medium"},
    },
    {
        "name": "rate_limit",
        "description": (
            "Apply an inbound packet-rate limit for a given protocol to blunt "
            "volumetric floods."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string", "description": "Target node ID"},
                "protocol": {
                    "type": "string",
                    "enum": ["icmp", "udp", "tcp"],
                    "description": "Protocol to rate limit",
                },
                "pps_limit": {"type": "integer", "description": "Max packets per second allowed"},
            },
            "required": ["client_id", "protocol", "pps_limit"],
        },
        "_meta": {"applicable_threats": ["ICMP_Flood", "UDP_Flood"], "severity_threshold": "medium"},
    },
    {
        "name": "block_ip",
        "description": (
            "Block a batch of source IP addresses; entries are automatically "
            "released after duration_minutes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string", "description": "Target node ID"},
                "ip_list": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Source IPs to block",
                },
                "duration_minutes": {
                    "type": "integer",
                    "description": "Auto-unblock after this many minutes",
                    "default": 30,
                },
            },
            "required": ["client_id", "ip_list"],
        },
        "_meta": {
            "applicable_threats": ["HTTP_Flood", "SYN_Scan", "TCP_Connect_Scan", "UDP_Scan"],
            "severity_threshold": "medium",
        },
    },
    {
        "name": "set_connection_timeout",
        "description": (
            "Shorten the connection idle timeout to evict slow-rate connections "
            "that hold resources hostage."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string", "description": "Target node ID"},
                "timeout_seconds": {
                    "type": "integer",
                    "description": "New connection idle timeout in seconds",
                },
            },
            "required": ["client_id", "timeout_seconds"],
        },
        "_meta": {"applicable_threats": ["Slowrate_DoS"], "severity_threshold": "medium"},
    },
    {
        "name": "close_unnecessary_ports",
        "description": (
            "Close unnecessary open ports to reduce the attack surface exposed "
            "to scanners."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string", "description": "Target node ID"},
                "port_list": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Ports to close",
                },
            },
            "required": ["client_id", "port_list"],
        },
        "_meta": {
            "applicable_threats": ["SYN_Scan", "TCP_Connect_Scan", "UDP_Scan"],
            "severity_threshold": "low",
        },
    },
    {
        "name": "enable_http_rate_limit",
        "description": (
            "Rate limit HTTP requests at the WAF / reverse-proxy layer to "
            "absorb application-layer floods."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string", "description": "Target node ID"},
                "requests_per_minute": {
                    "type": "integer",
                    "description": "Allowed requests per minute",
                },
                "per_ip": {
                    "type": "boolean",
                    "description": "Apply the limit per source IP",
                    "default": True,
                },
            },
            "required": ["client_id", "requests_per_minute"],
        },
        "_meta": {"applicable_threats": ["HTTP_Flood"], "severity_threshold": "medium"},
    },
    {
        "name": "alert_operator",
        "description": (
            "Notify on-call operations staff. MANDATORY when severity is high "
            "or critical."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "The incident this alert refers to"},
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Severity to report",
                },
                "message": {"type": "string", "description": "Human-readable alert message"},
                "channel": {
                    "type": "string",
                    "enum": ["email", "sms", "slack", "pagerduty"],
                    "description": "Notification channel",
                    "default": "email",
                },
            },
            "required": ["incident_id", "severity", "message"],
        },
        "_meta": {"applicable_threats": ALL_THREATS, "severity_threshold": "high"},
    },
    {
        "name": "log_incident",
        "description": (
            "Write a complete audit log entry for the incident. MANDATORY on "
            "every response for traceability."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "The incident being logged"},
                "action_taken": {"type": "string", "description": "Summary of the actions taken"},
                "notes": {"type": "string", "description": "Optional additional notes", "default": ""},
            },
            "required": ["incident_id", "action_taken"],
        },
        "_meta": {"applicable_threats": ALL_THREATS, "severity_threshold": "low"},
    },
    {
        "name": "share_threat_intel",
        "description": (
            "Broadcast threat intelligence to peer nodes to trigger a federated "
            "early-warning. Use when multiple nodes report the same threat."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "attack_type": {"type": "string", "description": "The threat class being shared"},
                "source_pattern": {
                    "type": "string",
                    "description": "Observed source pattern / signature",
                },
                "affected_nodes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Nodes known to be affected",
                },
            },
            "required": ["attack_type", "source_pattern", "affected_nodes"],
        },
        "_meta": {"applicable_threats": ALL_THREATS, "severity_threshold": "low"},
    },
]


def get_anthropic_tools() -> list[dict[str, Any]]:
    """Return the tool list in the exact shape Claude's API expects.

    Strips the RA3-only `_meta` key that the API does not understand.
    """
    return [
        {
            "name": a["name"],
            "description": a["description"],
            "input_schema": a["input_schema"],
        }
        for a in ACTION_DEFINITIONS
    ]


def get_openai_tools() -> list[dict[str, Any]]:
    """Return the tool list in the shape the OpenAI Responses API expects.

    In the Responses API a function tool is a flat object:
        {"type": "function", "name": ..., "description": ..., "parameters": ...}
    (Note: unlike Chat Completions, there is no nested "function" key.)
    """
    return [
        {
            "type": "function",
            "name": a["name"],
            "description": a["description"],
            "parameters": a["input_schema"],
        }
        for a in ACTION_DEFINITIONS
    ]


def action_names() -> set[str]:
    """Set of all valid action names (used to validate LLM tool calls)."""
    return {a["name"] for a in ACTION_DEFINITIONS}
