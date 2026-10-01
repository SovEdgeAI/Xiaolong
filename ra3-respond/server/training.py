"""Fine-tuning jobs for the local decision model: trigger, launch, track.

A job is model maintenance, not an incident response: it is not in the action
catalog, the decision engine never sees it, and it runs beside alert handling.

  trigger   POST /training/jobs (manual), or the automatic rule below
  launch    MCP tool `training_start_job` -> detached trainer container
  track     MCP tool `training_get_job`   -> trainer's status.json, stored in DB

Automatic trigger: with FINETUNE_TRIGGER_EVERY=N (> 0), a job is started once N
incidents have been reported since the previous job. It runs as a background
task after /report has committed, so the report never waits on it.

Environment:
    FINETUNE_ENABLED        true | false                  (true)
    FINETUNE_BASE_MODEL     model to fine-tune            (JEV_MODEL or Qwen/Qwen3-4B)
    FINETUNE_DATASET        file under ./artifacts        (teacher_labels.jsonl)
    FINETUNE_TRIGGER_EVERY  N incidents, 0 = manual only  (0)
    FINETUNE_AUTO_MODE      mode of auto jobs             (dry_run)
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import mcp_client
from database import AsyncSessionLocal
from models import Incident, TrainingJob

logger = logging.getLogger("ra3.training")

ENABLED = (os.getenv("FINETUNE_ENABLED") or "true").lower() in ("1", "true", "yes")
BASE_MODEL = os.getenv("FINETUNE_BASE_MODEL") or os.getenv("JEV_MODEL") or "Qwen/Qwen3-4B"
DATASET = os.getenv("FINETUNE_DATASET") or "teacher_labels.jsonl"
TRIGGER_EVERY = int(os.getenv("FINETUNE_TRIGGER_EVERY") or 0)
AUTO_MODE = os.getenv("FINETUNE_AUTO_MODE") or "dry_run"

ACTIVE = ("queued", "running")
TERMINAL = ("succeeded", "failed", "lost")


class TrainingDisabled(RuntimeError):
    pass


class JobConflict(RuntimeError):
    """Another job is still queued or running (one job at a time)."""


async def active_job(session: AsyncSession) -> TrainingJob | None:
    return (await session.execute(
        select(TrainingJob).where(TrainingJob.status.in_(ACTIVE))
        .order_by(TrainingJob.created_at.desc()).limit(1)
    )).scalar_one_or_none()


_start_lock = asyncio.Lock()        # check-then-insert of the one-job-at-a-time rule


async def start_job(session: AsyncSession, trigger: str, mode: str, base_model: str | None = None,
                    dataset: str | None = None, method: str = "lora",
                    hyperparams: dict[str, Any] | None = None, simulate_seconds: float = 0) -> TrainingJob:
    if not ENABLED:
        raise TrainingDisabled("fine-tuning is disabled (FINETUNE_ENABLED=false)")
    spec = {"base_model": base_model or BASE_MODEL, "dataset": dataset or DATASET, "mode": mode,
            "method": method, "hyperparams": hyperparams or {}, "simulate_seconds": simulate_seconds}
    async with _start_lock:
        running = await active_job(session)
        if running is not None:
            raise JobConflict(f"job {running.id} is still {running.status}")
        job = TrainingJob(status="queued", trigger=trigger, mode=mode, spec=spec)
        session.add(job)
        await session.commit()  # the job exists even if launching fails
        await session.refresh(job)

    try:
        out = await mcp_client.call_tool("training_start_job", {"job_id": str(job.id), **spec})
    except Exception as exc:  # noqa: BLE001 — MCP unreachable, etc.
        out = {"state": "failed", "error": f"MCP call failed: {exc}"}
    job.status = "running" if out.get("state") == "running" else "failed"
    job.error = out.get("error")
    job.result = {"launch": out}
    await session.commit()
    await session.refresh(job)  # commit expires attributes; reload before they are read
    logger.info("training job %s (%s, %s) -> %s", job.id, trigger, mode, job.status)
    return job


async def refresh(session: AsyncSession, job: TrainingJob) -> TrainingJob:
    """Pull the latest state of a job that has not finished yet."""
    if job.status not in ACTIVE:
        return job
    try:
        out = await mcp_client.call_tool("training_get_job", {"job_id": str(job.id)})
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not refresh training job %s: %s", job.id, exc)
        return job
    state = out.get("state", "running")
    job.status = state if state in ACTIVE + TERMINAL else "running"
    job.result = {**(job.result or {}), "container": out.get("container"), "status": out.get("status")}
    problems = (out.get("status") or {}).get("problems") or []
    job.error = "; ".join(problems) or out.get("error") or job.error
    await session.commit()
    await session.refresh(job)
    return job


# ---------------------------------------------------------------------------
# Automatic trigger
# ---------------------------------------------------------------------------
_tasks: set[asyncio.Task] = set()   # keep references so background tasks are not collected


async def _auto_trigger() -> None:
    async with AsyncSessionLocal() as session:
        last = (await session.execute(
            select(TrainingJob.created_at).order_by(TrainingJob.created_at.desc()).limit(1)
        )).scalar_one_or_none()
        q = select(func.count()).select_from(Incident)
        if last is not None:
            q = q.where(Incident.created_at > last)
        new_incidents = (await session.execute(q)).scalar_one()
        if new_incidents < TRIGGER_EVERY or await active_job(session) is not None:
            return
        await start_job(session, trigger=f"auto:every_{TRIGGER_EVERY}_incidents", mode=AUTO_MODE)


def schedule_auto_trigger() -> None:
    """Called after an incident is committed. Returns at once; never raises."""
    if not (ENABLED and TRIGGER_EVERY > 0):
        return

    async def run() -> None:
        try:
            await _auto_trigger()
        except Exception:  # noqa: BLE001 — a trigger failure must not affect alert handling
            logger.exception("automatic training trigger failed")

    task = asyncio.create_task(run())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
