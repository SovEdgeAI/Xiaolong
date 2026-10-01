"""Fine-tuning jobs for the MCP server: one long-running trainer container per job.

Unlike response actions (runner.py: one short-lived container per call, waited
on), a training job is started detached and returns immediately; its progress
lives in <training volume>/<job_id>/status.json, written by the trainer and read
back by `get_job`. Alert handling never waits on a job.

The trainer is a sibling container on the host Docker daemon, so its bind
mounts need host paths (TRAINER_DATA_HOST_DIR, TRAINER_HF_HOST_DIR); job
directories live on the named volume TRAINING_VOLUME, which this server also
mounts at TRAINING_DIR.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import docker
from docker.types import DeviceRequest

from runner import _docker

logger = logging.getLogger("ra3.mcp.training")

TRAINER_IMAGE = os.getenv("TRAINER_IMAGE", "ra3-trainer:latest")
TRAINER_MEM_LIMIT = os.getenv("TRAINER_MEM_LIMIT", "2g")
TRAINER_GPU = os.getenv("TRAINER_GPU", "false").lower() in ("1", "true", "yes")
TRAINING_VOLUME = os.getenv("TRAINING_VOLUME", "ra3-training")
TRAINING_DIR = os.getenv("TRAINING_DIR", "/training")      # where this server mounts that volume
DATA_HOST_DIR = os.getenv("TRAINER_DATA_HOST_DIR", "")      # host dir with labeled data
HF_HOST_DIR = os.getenv("TRAINER_HF_HOST_DIR", "")          # host Hugging Face cache

MODES = ("dry_run", "train")
_JOB_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _container_name(job_id: str) -> str:
    return f"ra3-train-{job_id[:8]}"


def _status_path(job_id: str) -> str:
    return os.path.join(TRAINING_DIR, job_id, "status.json")


def start_job(job_id: str, spec: dict[str, Any]) -> dict:
    """Launch the trainer container detached; returns without waiting."""
    if not _JOB_ID.match(job_id):
        return {"state": "failed", "error": "job_id must be a UUID"}
    if spec.get("mode") not in MODES:
        return {"state": "failed", "error": f"mode must be one of {MODES}"}
    os.makedirs(os.path.join(TRAINING_DIR, job_id), exist_ok=True)

    volumes = {TRAINING_VOLUME: {"bind": "/jobs", "mode": "rw"}}
    if DATA_HOST_DIR:
        volumes[DATA_HOST_DIR] = {"bind": "/data", "mode": "ro"}
    if HF_HOST_DIR:
        volumes[HF_HOST_DIR] = {"bind": "/hf", "mode": "ro"}
    try:
        c = _docker().containers.run(
            TRAINER_IMAGE,
            name=_container_name(job_id),
            environment={"JOB_SPEC": json.dumps({**spec, "job_id": job_id}), "JOB_DIR": f"/jobs/{job_id}"},
            volumes=volumes,
            network_disabled=True,   # data and weights come from mounts, results go to the volume
            mem_limit=TRAINER_MEM_LIMIT,
            device_requests=[DeviceRequest(count=-1, capabilities=[["gpu"]])] if TRAINER_GPU else None,
            labels={"ra3.role": "trainer", "ra3.job_id": job_id},
            detach=True,
        )
    except docker.errors.ImageNotFound:
        return {"state": "failed", "error": f"trainer image '{TRAINER_IMAGE}' not found — run `docker compose build trainer`"}
    except docker.errors.APIError as exc:
        return {"state": "failed", "error": f"docker error: {exc.explanation or exc}"}
    logger.info("training job %s started in container %s", job_id, c.short_id)
    return {"state": "running", "container_id": c.short_id,
            "mounts": {"data": bool(DATA_HOST_DIR), "hf_cache": bool(HF_HOST_DIR), "gpu": TRAINER_GPU}}


def get_job(job_id: str) -> dict:
    """Current state: the trainer's status.json plus the container's own state.
    A finished container is removed once its exit code has been read."""
    if not _JOB_ID.match(job_id):
        return {"state": "failed", "error": "job_id must be a UUID"}
    status = None
    try:
        with open(_status_path(job_id)) as f:
            status = json.load(f)
    except (OSError, json.JSONDecodeError):
        pass

    container = {"state": "missing"}
    try:
        c = _docker().containers.get(_container_name(job_id))
        container = {"state": c.status, "id": c.short_id,
                     "exit_code": c.attrs.get("State", {}).get("ExitCode")}
        if c.status in ("exited", "dead"):
            c.remove()
    except docker.errors.NotFound:
        pass

    state = (status or {}).get("state", "running" if container["state"] in ("created", "running") else "lost")
    if state == "running" and container["state"] not in ("created", "running"):
        state = "lost"  # the container ended without writing a final status
    return {"state": state, "container": container, "status": status}
