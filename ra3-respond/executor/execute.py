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
import sys

from handlers import HANDLERS


def _emit(payload: dict) -> None:
    # A single JSON line on stdout is what the MCP runner parses.
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
