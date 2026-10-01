#!/usr/bin/env python3
"""Ephemeral executor entrypoint.

Runs exactly one action and exits. Invoked by the MCP server as:

    docker run --rm --network none ra3-executor:latest
        (with env ACTION_NAME=<name> ACTION_ARGS=<json>)

Reads the action name and JSON arguments from the environment, dispatches to
the matching handler, prints a single-line JSON result to stdout, and exits 0
on success / 1 on failure.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

# EXECUTOR_MODE=testbed swaps the mock handlers for ones that enforce on the
# 5G testbed via the testbed-agent; default stays mock (simulate + isolated).
if os.environ.get("EXECUTOR_MODE") == "testbed":
    from testbed import HANDLERS
else:
    from handlers import HANDLERS

STARTED = time.time()


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _runtime(started: float) -> dict:
    """Evidence of where the action ran: Docker sets the hostname to the short
    container id; with --network none only the loopback interface exists; the
    cgroup file shows the memory cap applied by the runner."""
    return {
        "container_hostname": socket.gethostname(),
        "pid": os.getpid(),
        "network_interfaces": sorted(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else None,
        "memory_limit_bytes": _read("/sys/fs/cgroup/memory.max"),
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


def _emit(payload: dict) -> None:
    # A single JSON line on stdout is what the MCP runner parses.
    payload["runtime"] = _runtime(STARTED)
    print(json.dumps(payload))


def main() -> int:
    name = os.environ.get("ACTION_NAME", "").strip()
    raw_args = os.environ.get("ACTION_ARGS", "{}")

    try:
        arguments = json.loads(raw_args)
        if not isinstance(arguments, dict):
            raise ValueError("ACTION_ARGS must be a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        _emit({"status": "error", "action": name, "error": f"invalid ACTION_ARGS: {exc}"})
        return 1

    handler = HANDLERS.get(name)
    if handler is None:
        _emit({"status": "error", "action": name, "error": f"unknown action '{name}'"})
        return 1

    try:
        result = handler(**arguments)
    except TypeError as exc:
        _emit({"status": "error", "action": name, "arguments": arguments,
               "error": f"invalid arguments: {exc}"})
        return 1
    except Exception as exc:  # noqa: BLE001
        _emit({"status": "error", "action": name, "arguments": arguments, "error": str(exc)})
        return 1

    _emit({"status": "success", "action": name, "arguments": arguments, "result": result})
    return 0


if __name__ == "__main__":
    sys.exit(main())
