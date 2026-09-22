"""LLM decision engine: turn an incident into a ranked set of actions.

Uses an OpenAI-compatible **Responses API** (wire_api = "responses") with
function calling. The model is given the incident context plus the 9 action
tools and decides which ones to invoke, in what order, with which arguments —
and explains why.

Provider is configured via environment variables so any OpenAI-compatible
endpoint (incl. third-party proxies) can be used:

    OPENAI_API_KEY   — bearer key
    OPENAI_BASE_URL  — e.g. https://huodingai.com/v1
    LLM_MODEL        — e.g. gpt-5.5
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

# NB: the `openai` SDK is imported lazily inside _get_client()/decide_actions so
# that mock mode (LLM_MODEL=mock) can run without the package installed.
from actions import action_names, get_openai_tools

logger = logging.getLogger("ra3.llm")

MODEL = os.getenv("LLM_MODEL", "gpt-5.5")
BASE_URL = os.getenv("OPENAI_BASE_URL", "https://huodingai.com/v1")
MAX_OUTPUT_TOKENS = 2048


class LLMError(RuntimeError):
    """Raised when the LLM API call fails or returns nothing usable."""


SYSTEM_PROMPT = """\
You are the decision engine of RA3, the alarm-response control plane of a \
security system for 5G federated-learning networks. An upstream detector (RA1) \
has reported a network threat. Your job is to choose the appropriate response \
actions from the provided tools, invoking each tool you want to execute.

Rules you MUST follow:
1. log_incident is ALWAYS required — call it on every single response so the \
event is auditable and traceable.
2. alert_operator is REQUIRED whenever the incident severity is "high" or \
"critical". Do not skip it for those severities.
3. Choose actions that actually fit the attack_type. Prefer the specialized \
mitigation for the threat class over generic ones.
4. Use the concrete numbers in the incident metadata to decide both WHICH \
actions to take and their PRIORITY. For example, a very large \
half_open_connections count makes enabling SYN cookies urgent; a large \
unique_source_ips count favors IP blocking; a high packet_rate favors \
aggressive rate limiting. Set tool parameters to values proportional to the \
observed metrics.
5. Consider share_threat_intel when the pattern looks like it could affect \
peer nodes in the federation.
6. Order matters: invoke the highest-priority mitigation first and \
log_incident last.

For EVERY tool you invoke, you must also justify it. Put a short, concrete \
rationale (referencing the specific metrics that drove the decision) in the \
text portion of your response, clearly associated with each action. Then \
finish with a brief overall summary of your decision strategy.
"""


def _build_user_prompt(
    incident_id: str,
    client_id: str,
    attack_type: str,
    severity: str,
    confidence: float,
    metadata: dict[str, Any],
) -> str:
    return (
        "A new threat has been reported. Decide the response.\n\n"
        f"incident_id: {incident_id}\n"
        f"client_id: {client_id}\n"
        f"attack_type: {attack_type}\n"
        f"severity: {severity}\n"
        f"confidence: {confidence}\n"
        f"metadata: {json.dumps(metadata, ensure_ascii=False)}\n\n"
        "Use client_id as the target node for node-scoped actions, and "
        "incident_id for alert_operator / log_incident. "
        "Select and invoke the appropriate response tools now."
    )


def _is_mock() -> bool:
    """Mock mode runs the full pipeline offline (no external LLM call).

    Enabled by LLM_MODEL=mock or MOCK_LLM=true. Useful when the provider is
    unavailable, or for deterministic tests.
    """
    return MODEL.strip().lower() == "mock" or os.getenv("MOCK_LLM", "").lower() in (
        "1", "true", "yes",
    )


def _get_client():
    from openai import OpenAI  # lazy import; not needed in mock mode

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or api_key == "your_api_key_here":
        raise LLMError(
            "OPENAI_API_KEY is not configured. Set it in your .env file."
        )
    return OpenAI(api_key=api_key, base_url=BASE_URL)


def _mock_decide(
    incident_id: str,
    client_id: str,
    attack_type: str,
    severity: str,
    confidence: float,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Rule-based stand-in for the LLM: metadata-driven, mandatory-rule aware.

    Mirrors the applicable_threats in actions.py and the mandatory rules in the
    system prompt (always log_incident; alert_operator on high/critical).
    """
    actions: list[dict[str, Any]] = []
    notes: list[str] = []

    def add(name: str, arguments: dict[str, Any], why: str) -> None:
        actions.append({"name": name, "arguments": arguments, "reason": why})
        notes.append(f"{name}: {why}")

    if attack_type == "SYN_Flood":
        half_open = int(metadata.get("half_open_connections", 0))
        duration = 120 if half_open >= 40000 else 60
        add("enable_syn_cookie", {"client_id": client_id, "duration_minutes": duration},
            f"half_open_connections={half_open} → enable SYN cookies for {duration}m")
    elif attack_type in ("ICMP_Flood", "UDP_Flood"):
        proto = "icmp" if attack_type == "ICMP_Flood" else "udp"
        rate = int(metadata.get("packet_rate") or metadata.get("echo_request_rate") or 0)
        pps = max(1000, rate // 10) if rate else 5000
        add("rate_limit", {"client_id": client_id, "protocol": proto, "pps_limit": pps},
            f"observed rate={rate} → cap {proto} at {pps} pps")
    elif attack_type == "HTTP_Flood":
        rpm = (int(metadata.get("request_rate", 6000)) // 10) or 600
        add("enable_http_rate_limit", {"client_id": client_id, "requests_per_minute": rpm, "per_ip": True},
            f"request_rate={metadata.get('request_rate')} → WAF limit {rpm} req/min per IP")
        srcs = int(metadata.get("unique_source_ips", 0))
        if 0 < srcs <= 5:
            add("block_ip", {"client_id": client_id,
                             "ip_list": [f"192.0.2.{i}" for i in range(1, srcs + 1)],
                             "duration_minutes": 30},
                f"only {srcs} source IP(s) → block them directly")
    elif attack_type == "Slowrate_DoS":
        add("set_connection_timeout", {"client_id": client_id, "timeout_seconds": 15},
            "slow connections holding resources → shorten idle timeout to 15s")
    elif attack_type in ("SYN_Scan", "TCP_Connect_Scan", "UDP_Scan"):
        scanner = metadata.get("scanner_ip")
        if scanner:
            add("block_ip", {"client_id": client_id, "ip_list": [scanner], "duration_minutes": 30},
                f"single scanner {scanner} → block source")
        add("close_unnecessary_ports", {"client_id": client_id, "port_list": [23, 135, 445]},
            "reduce attack surface by closing risky ports")

    # Mandatory rule: alert on high/critical.
    if severity in ("high", "critical"):
        add("alert_operator",
            {"incident_id": incident_id, "severity": severity,
             "message": f"{attack_type} on {client_id} (confidence {confidence})",
             "channel": "email"},
            f"severity={severity} → operator alert is mandatory")

    # Mandatory rule: always log, last.
    add("log_incident",
        {"incident_id": incident_id,
         "action_taken": ", ".join(a["name"] for a in actions) or "none",
         "notes": "auto-generated by mock decision engine"},
        "every response must be logged for audit")

    for i, a in enumerate(actions, start=1):
        a["order"] = i

    reasoning = f"[MOCK decision] attack={attack_type}, severity={severity}. " + "; ".join(notes)
    return {
        "selected_actions": actions,
        "llm_reasoning": reasoning,
        "raw_llm_response": {"mock": True, "model": "mock", "attack_type": attack_type},
    }


def _extract_text(item: Any) -> str:
    """Collect output_text from a Responses API 'message' item."""
    parts: list[str] = []
    for content in getattr(item, "content", None) or []:
        text = getattr(content, "text", None)
        if text:
            parts.append(text)
    return "".join(parts)


def decide_actions(
    incident_id: str,
    client_id: str,
    attack_type: str,
    severity: str,
    confidence: float,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Run the function-calling decision against the Responses API.

    Returns a dict with keys:
        selected_actions: list[{name, order, arguments, reason}]
        llm_reasoning:    str
        raw_llm_response: dict   (full serialized API response, for debugging)

    Raises LLMError on any API failure.
    """
    # Offline mode: skip the external API entirely.
    if _is_mock():
        logger.info("LLM mock mode active — deciding via built-in rules")
        return _mock_decide(incident_id, client_id, attack_type, severity, confidence, metadata)

    client = _get_client()
    tools = get_openai_tools()
    valid_names = action_names()

    user_prompt = _build_user_prompt(
        incident_id, client_id, attack_type, severity, confidence, metadata
    )

    try:
        response = client.responses.create(
            model=MODEL,
            instructions=SYSTEM_PROMPT,
            input=user_prompt,
            tools=tools,
            tool_choice="auto",
            max_output_tokens=MAX_OUTPUT_TOKENS,
        )
    except Exception as exc:  # openai.APIError and friends
        logger.exception("LLM API call failed")
        raise LLMError(f"LLM API call failed: {exc}") from exc

    # --- Parse the response --------------------------------------------------
    selected_actions: list[dict[str, Any]] = []
    reasoning_parts: list[str] = []
    order = 0

    for item in getattr(response, "output", None) or []:
        item_type = getattr(item, "type", None)

        if item_type == "function_call":
            name = getattr(item, "name", None)
            if name not in valid_names:
                logger.warning("LLM requested unknown tool '%s' — skipped", name)
                continue
            raw_args = getattr(item, "arguments", "") or "{}"
            try:
                arguments = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                logger.warning("Could not parse arguments for '%s': %r", name, raw_args)
                arguments = {}
            order += 1
            selected_actions.append(
                {"name": name, "order": order, "arguments": arguments, "reason": ""}
            )

        elif item_type == "message":
            text = _extract_text(item)
            if text:
                reasoning_parts.append(text)

    # Fall back to the SDK convenience accessor if no message items were parsed.
    if not reasoning_parts:
        convenience = getattr(response, "output_text", None)
        if convenience:
            reasoning_parts.append(convenience)

    llm_reasoning = "\n\n".join(p.strip() for p in reasoning_parts if p.strip())

    try:
        raw = response.model_dump(mode="json")
    except Exception:  # noqa: BLE001
        raw = {"model": MODEL}

    if not selected_actions:
        logger.warning(
            "LLM returned no tool calls for incident %s (attack=%s)",
            incident_id,
            attack_type,
        )

    return {
        "selected_actions": selected_actions,
        "llm_reasoning": llm_reasoning,
        "raw_llm_response": raw,
    }
