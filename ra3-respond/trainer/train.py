#!/usr/bin/env python3
"""Fine-tuning job entrypoint (one container per job, launched by the MCP server).

Reads the job spec from $JOB_SPEC (JSON), writes progress and the final result
to /job/status.json, and exits. The MCP server reads that file to report the
job's status, so the RA3 server never waits on a running job.

Modes:
  dry_run  validate the dataset and the environment, write the training plan,
           train nothing. Works without a GPU; the default.
  train    run the fine-tune. Not implemented in this image: it needs a GPU
           image with torch + transformers + peft (see TRAIN_BACKEND below).
           The job fails with an explicit reason instead of pretending.

Mounts (set up by the MCP runner):
  $JOB_DIR read-write, this job's directory on the shared training volume
  /data    read-only, labeled data (host ./artifacts)
  /hf      read-only, Hugging Face cache with the base model
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import time
from datetime import datetime, timezone

JOB_DIR = os.environ.get("JOB_DIR", "/job")  # this job's directory on the shared training volume
DATA_DIR = "/data"
HF_DIR = "/hf"
TRAIN_BACKEND = None  # e.g. a LoRA trainer built on peft; plugged in once a GPU image exists


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_status(status: dict) -> None:
    status["updated_at"] = now()
    tmp = os.path.join(JOB_DIR, "status.json.tmp")
    with open(tmp, "w") as f:
        json.dump(status, f, indent=1)
    os.replace(tmp, os.path.join(JOB_DIR, "status.json"))  # atomic for readers


def inspect_dataset(name: str) -> dict:
    path = os.path.join(DATA_DIR, os.path.basename(name))
    info = {"path": path, "exists": os.path.isfile(path)}
    if not info["exists"]:
        return info
    alerts = labels = yes = 0
    per_split: dict[str, int] = {}
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            alerts += 1
            for lab in (rec.get("labels") or {}).values():
                if lab is None:
                    continue
                labels += 1
                yes += lab == "yes"
                per_split[rec.get("split", "train")] = per_split.get(rec.get("split", "train"), 0) + 1
    info.update(alerts=alerts, usable_labels=labels, yes=yes, no=labels - yes, labels_per_split=per_split)
    return info


def inspect_env(base_model: str) -> dict:
    model_dir = os.path.join(HF_DIR, "hub", "models--" + base_model.replace("/", "--"))
    return {
        "hostname": socket.gethostname(),
        "gpu_visible": bool(os.environ.get("NVIDIA_VISIBLE_DEVICES")) or shutil.which("nvidia-smi") is not None,
        "base_model_cached": os.path.isdir(model_dir),
        "training_backend": TRAIN_BACKEND or "none (dry-run image)",
        "network_interfaces": sorted(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else None,
    }


def plan(spec: dict, data: dict) -> dict:
    hp = {"lora_r": 16, "lora_alpha": 32, "lora_dropout": 0.05, "learning_rate": 2e-4,
          "epochs": 3, "batch_size": 8, "max_seq_len": 1024, **(spec.get("hyperparams") or {})}
    return {
        "method": spec.get("method", "lora"),
        "base_model": spec["base_model"],
        "train_examples": (data.get("labels_per_split") or {}).get("train", 0),
        "eval_examples": (data.get("labels_per_split") or {}).get("test", 0),
        "hyperparams": hp,
        "output": os.path.join(JOB_DIR, "adapter"),
        # a fine-tuned model has new logits and hidden states: every AnyJev
        # artifact (L1 temperatures, L2 heads) is tied to the old weights
        "post_steps": ["evaluate the adapter on the held-out test split against the current model",
                       "refit L1/L2 artifacts on the fine-tuned model (scripts/jev_fit.py)",
                       "promote only if it beats the current model; the server keeps serving meanwhile"],
    }


def main() -> int:
    spec = json.loads(os.environ.get("JOB_SPEC", "{}"))
    status = {"job_id": spec.get("job_id"), "mode": spec.get("mode", "dry_run"),
              "state": "running", "started_at": now(), "spec": spec}
    write_status(status)
    try:
        data = inspect_dataset(spec.get("dataset", "teacher_labels.jsonl"))
        env = inspect_env(spec.get("base_model", "Qwen/Qwen3-4B"))
        status.update(dataset=data, environment=env, plan=plan(spec, data))
        problems = []
        if not data["exists"]:
            problems.append(f"dataset not found: {data['path']}")
        elif data.get("usable_labels", 0) == 0:
            problems.append("dataset has no usable labels")
        if not env["base_model_cached"]:
            problems.append(f"base model {spec.get('base_model')} not in the mounted HF cache")

        if status["mode"] == "dry_run":
            time.sleep(float(spec.get("simulate_seconds", 0)))  # lets callers watch a running job
            status.update(state="failed" if problems else "succeeded", trained=False,
                          problems=problems, finished_at=now())
        else:
            if TRAIN_BACKEND is None:
                problems.append("no training backend in this image: build a GPU trainer image "
                                "(torch + transformers + peft) and run with a GPU")
            if not env["gpu_visible"]:
                problems.append("no GPU visible to the container")
            status.update(state="failed", trained=False, problems=problems, finished_at=now())
    except Exception as exc:  # noqa: BLE001
        status.update(state="failed", trained=False, problems=[f"{type(exc).__name__}: {exc}"], finished_at=now())
    write_status(status)
    print(json.dumps({"job_id": status["job_id"], "state": status["state"], "problems": status.get("problems")}))
    return 0 if status["state"] == "succeeded" else 1


if __name__ == "__main__":
    sys.exit(main())
