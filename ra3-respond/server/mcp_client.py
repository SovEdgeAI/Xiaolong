"""MCP client: executes LLM-selected actions against the RA3 MCP server.

After llm.py decides *which* actions to take, this module actually invokes
them by calling the matching MCP tools over streamable HTTP. Each tool call
causes the MCP server to spin up an ephemeral executor container. Results are
collected per action (preserving the LLM's ordering) and returned for storage.

Execution is best-effort: a failure of one action, or of the MCP connection as
a whole, is recorded in the per-action result rather than aborting the request
(the decision itself has already been made and persisted).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

logger = logging.getLogger("ra3.mcp.client")

MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://mcp:9000/mcp")
EXECUTION_ENABLED = os.getenv("EXECUTION_ENABLED", "true").lower() in ("1", "true", "yes")


def _extract_payload(call_result: Any) -> dict:
    """Pull the structured JSON result out of an MCP CallToolResult."""
    structured = getattr(call_result, "structuredContent", None)
    if isinstance(structured, dict):
        # FastMCP may wrap a bare return under a "result" key.
        return structured.get("result", structured)

    for block in getattr(call_result, "content", None) or []:
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"status": "success", "raw": text}
    return {"status": "unknown", "error": "no content returned"}


async def execute_actions(actions: list[dict]) -> list[dict]:
    """Execute each selected action via MCP; return per-action outcomes.

    Each outcome: {name, order, arguments, execution: {...}}
    """
    if not EXECUTION_ENABLED:
        return [
            {
                "name": a["name"],
                "order": a.get("order"),
                "arguments": a.get("arguments", {}),
                "execution": {"status": "skipped", "reason": "EXECUTION_ENABLED=false"},
            }
            for a in actions
        ]

    if not actions:
        return []

    ordered = sorted(actions, key=lambda x: x.get("order", 0))
    results: list[dict] = []

    try:
        async with streamablehttp_client(MCP_SERVER_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for a in ordered:
                    name = a["name"]
                    args = a.get("arguments", {})
                    try:
                        call_result = await session.call_tool(name, args)
                        execution = _extract_payload(call_result)
                    except Exception as exc:  # noqa: BLE001
                        logger.exception("MCP tool call failed: %s", name)
                        execution = {"status": "error", "error": str(exc)}
                    results.append(
                        {"name": name, "order": a.get("order"), "arguments": args, "execution": execution}
                    )
    except Exception as exc:  # noqa: BLE001 — MCP server unreachable, etc.
        logger.error("MCP connection failed (%s): %s", MCP_SERVER_URL, exc)
        return [
            {
                "name": a["name"],
                "order": a.get("order"),
                "arguments": a.get("arguments", {}),
                "execution": {"status": "error", "error": f"MCP unreachable: {exc}"},
            }
            for a in ordered
        ]

    return results


async def call_tool(name: str, arguments: dict) -> dict:
    """Call one MCP tool and return its JSON payload (used by the training API).
    Raises on connection failure; the caller records the error."""
    async with streamablehttp_client(MCP_SERVER_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return _extract_payload(await session.call_tool(name, arguments))
