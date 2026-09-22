"""Ephemeral-container runner used by the MCP server.

For every action invocation we launch a fresh, one-shot Docker container from
the `ra3-executor` image, hand it the action name + JSON arguments via the
environment, capture its single-line JSON result from stdout, then let it be
removed (`--rm`). The container is network-isolated and memory-capped.

This talks to the host Docker daemon via the mounted /var/run/docker.sock, so
the ephemeral containers are *siblings* of the MCP server container, not nested.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import docker

logger = logging.getLogger("ra3.mcp.runner")

EXECUTOR_IMAGE = os.getenv("EXECUTOR_IMAGE", "ra3-executor:latest")
MEM_LIMIT = os.getenv("EXECUTOR_MEM_LIMIT", "128m")

_client: docker.DockerClient | None = None


def _docker() -> docker.DockerClient:
    global _client
    if _client is None:
        _client = docker.from_env()
    return _client


def run_in_container(action: str, arguments: dict[str, Any]) -> dict:
    """Execute one action in a throw-away container; return its JSON result."""
    try:
        raw = _docker().containers.run(
            EXECUTOR_IMAGE,
            environment={
                "ACTION_NAME": action,
                "ACTION_ARGS": json.dumps(arguments),
            },
            network_disabled=True,   # no network access for the executor
            mem_limit=MEM_LIMIT,      # cap memory
            remove=True,              # --rm: destroy container when done
            stdout=True,
            stderr=False,
        )
    except docker.errors.ImageNotFound:
        logger.error("Executor image '%s' not found", EXECUTOR_IMAGE)
        return {
            "status": "error",
            "action": action,
            "error": f"executor image '{EXECUTOR_IMAGE}' not found — run `docker compose build`",
        }
    except docker.errors.ContainerError as exc:
        stderr = exc.stderr.decode() if getattr(exc, "stderr", None) else str(exc)
        logger.error("Executor container failed for %s: %s", action, stderr)
        return {"status": "error", "action": action, "error": f"container failed: {stderr}"}
    except docker.errors.DockerException as exc:
        logger.error("Docker error running %s: %s", action, exc)
        return {"status": "error", "action": action, "error": f"docker error: {exc}"}

    text = raw.decode().strip() if raw else ""
    last_line = text.splitlines()[-1] if text else ""
    try:
        return json.loads(last_line)
    except json.JSONDecodeError:
        return {"status": "error", "action": action, "error": f"unparseable executor output: {text!r}"}
