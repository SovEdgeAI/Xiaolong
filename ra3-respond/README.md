# RA3 Threat Response System

Control / alarm-response plane (RA3) for a security system protecting **5G
federated-learning networks**. It ingests threats detected upstream by RA1,
uses **Anthropic Claude** function calling to select and rank mitigation
actions from a predefined catalog, persists the decision, and returns it to the
caller.

```
RA1 (detection) ──JSON──▶ RA3 /report ──▶ Claude (tool_use) ──▶ ranked actions
                              │                                       │
                              │                          (RA3 = MCP client)
                              │                                       ▼
                              │                     MCP server ──▶ ephemeral
                              │                     (9 tools)      executor
                              │                                    container
                              │                                    (per action,
                              │                                     --rm, no net)
                              ▼                                       │
                     PostgreSQL (incidents + responses + execution_results) ◀┘
```

The system has two planes:

* **Decision plane** — Claude function-calling picks *which* actions to run,
  in what order, with what parameters, and explains why.
* **Execution plane** — RA3 acts as an **MCP client** and invokes the matching
  tools on a standalone **MCP server**, which runs each action inside a fresh,
  network-isolated, memory-capped **ephemeral Docker container** (one per
  action). In this build the executor *simulates* the mitigation (mock mode)
  and returns a structured result; swapping in real enforcement only means
  editing `executor/handlers.py`.

## Threat classes (5G-NIDD)

| Category | Attack types |
|----------|--------------|
| Volumetric DoS | `ICMP_Flood`, `UDP_Flood` |
| Protocol DoS | `SYN_Flood` |
| Application DoS | `HTTP_Flood`, `Slowrate_DoS` (Slowloris / Torshammer) |
| Port scan | `SYN_Scan`, `TCP_Connect_Scan`, `UDP_Scan` |
| — | `Normal` (no response) |

## Tech stack

Python 3.11 · FastAPI · SQLAlchemy 2.0 (async) · PostgreSQL 16 · Alembic ·
OpenAI-compatible Responses API (default model `gpt-5.5`, configurable) ·
MCP (Model Context Protocol) · Docker Compose.

The decision engine uses any OpenAI-compatible endpoint, configured via
`OPENAI_API_KEY`, `OPENAI_BASE_URL`, and `LLM_MODEL` in `.env`.

## Quick start (3 steps)

```bash
# 1. Clone
git clone <your-repo-url> ra3-respond && cd ra3-respond

# 2. Configure — copy the template and set your LLM provider credentials
cp .env.example .env
#   then edit .env: OPENAI_API_KEY, OPENAI_BASE_URL (e.g. https://huodingai.com/v1),
#   and LLM_MODEL (e.g. gpt-5.5)
#   Tip: verify the provider is reachable first with ./scripts/probe_api.sh

# 3. Launch everything (db + server + client simulator)
docker compose up --build
```

The server comes up on **http://localhost:8000** (interactive docs at
`/docs`). Postgres auto-runs `db/init.sql` on first boot, creating the schema
and seeding all 9 response actions.

## Running the first test

Once `docker compose up` reports the server is healthy:

```bash
# Health check (should report database: connected)
curl http://localhost:8000/health

# Report a single SYN_Flood and see Claude's decision
docker compose run --rm client python simulate.py --once --attack SYN_Flood

# Or run the simulator in a continuous loop (random threats every 5s)
docker compose run --rm client python simulate.py --loop --interval 5

# Inspect stored incidents
curl "http://localhost:8000/incidents?limit=10"
curl "http://localhost:8000/incidents?attack_type=SYN_Flood&severity=critical"

# View the action catalog
curl http://localhost:8000/actions
```

> The `client` service also runs automatically in loop mode when you
> `docker compose up`. Use `docker compose run --rm client ...` for one-off
> manual tests.

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/report` | Ingest a threat, run the LLM decision, return ranked actions |
| `GET`  | `/incidents` | List incidents; filter by `attack_type`, `severity`, `status`; paginate with `limit`/`offset` |
| `GET`  | `/incidents/{id}` | Full incident detail incl. the LLM decision |
| `GET`  | `/actions` | The response-action catalog |
| `GET`  | `/health` | Service + database connectivity probe |

The `POST /report` response now includes an `execution_results` array — the
actual per-action outcome from the executor containers — in addition to the
`selected_actions` decision.

### `POST /report` example

```json
{
  "client_id": "bs_node_01",
  "attack_type": "SYN_Flood",
  "severity": "critical",
  "confidence": 0.98,
  "metadata": { "half_open_connections": 48000, "syn_rate": 15000 }
}
```

Response:

```json
{
  "incident_id": "…",
  "attack_type": "SYN_Flood",
  "severity": "critical",
  "selected_actions": [
    { "name": "enable_syn_cookie", "order": 1, "arguments": {"client_id": "bs_node_01", "duration_minutes": 120}, "reason": "" },
    { "name": "alert_operator",   "order": 2, "arguments": {"...": "..."} },
    { "name": "log_incident",     "order": 3, "arguments": {"...": "..."} }
  ],
  "execution_results": [
    { "name": "enable_syn_cookie", "order": 1, "execution": {"status": "success", "result": {"effect": "SYN cookies enabled on bs_node_01", "duration_minutes": 120}} },
    { "name": "alert_operator",   "order": 2, "execution": {"status": "success", "result": {"effect": "Operator alerted via email"}} },
    { "name": "log_incident",     "order": 3, "execution": {"status": "success", "result": {"effect": "Incident logged for audit"}} }
  ],
  "llm_reasoning": "…"
}
```

### Verifying that actions actually executed

Each entry in `execution_results` is produced by a **real, separate container**
that the MCP server started and destroyed for that one action. To watch it live:

```bash
# In one terminal, tail the MCP server logs
docker compose logs -f mcp

# In another, trigger a report — you'll see ephemeral executor containers
# appear and disappear:
docker compose run --rm client python simulate.py --once --attack SYN_Flood
docker ps -a | grep executor      # short-lived; --rm removes them after exit

# Confirm results were persisted alongside the decision
curl http://localhost:8000/incidents/<incident_id>   # see execution_results[]
```

To run **decision-only** (skip execution entirely), set `EXECUTION_ENABLED=false`
in `.env` and restart — `execution_results` will report `status: "skipped"`.

### Offline / mock mode (no LLM, no API key)

Set `LLM_MODEL=mock` in `.env` to replace the external LLM with a built-in,
rule-based decision engine. The rest of the pipeline (MCP → ephemeral executor
containers → DB) runs unchanged. Useful when the provider is unavailable or for
deterministic tests. Switch back by setting `LLM_MODEL=gpt-5.5`.

You can also exercise the core decision + execution logic **without Docker** via
a standalone demo (only needs Python 3.11+):

```bash
LLM_MODEL=mock python3 scripts/demo_offline.py            # all sample attacks
LLM_MODEL=mock python3 scripts/demo_offline.py SYN_Flood  # one attack type
```

It prints, for each alert: the incoming report → the chosen actions (with
metadata-driven parameters and reasons) → the simulated execution result → a
PASS/FAIL verdict against the mandatory rules.

### Local open-source decision model (AnyJev, no API key)

Set `LLM_MODEL=anyjev` to decide with a local Hugging Face model (default
`Qwen/Qwen3-4B`, runs on CPU) through [AnyJev](https://github.com/nokia-applied-research/AnyJev)
logit readout instead of function calling:

* every candidate action is one yes/no question; its `P(yes)` is read from the
  next-token logits (no generation) and debiased across both phrasing orders;
* actions with `P(yes) >= JEV_THRESHOLD` are selected, so each alert gets
  **1..N actions**. Execution order (the MCP client runs them sequentially by
  `order`): mitigations by model certainty (log-odds, ties by catalog order),
  then `share_threat_intel`, then `alert_operator`, then `log_incident`;
* hard rules stay in code: `log_incident` always (last), `alert_operator` on
  high/critical, at least one mitigation (the most likely one, flagged
  low-confidence, if none clears the threshold);
* numeric parameters use the metadata-proportional formulas of the mock engine;
* once the decision is fixed, the same model writes English rationales as
  JSON. The response gets a structured `explanation` object; `llm_reasoning`
  holds its `overall_assessment`:

```json
{
  "overall_assessment": "High-severity HTTP flood from 2 sources; ...",
  "selected_actions": [
    {"order": 1, "name": "enable_http_rate_limit", "decision_basis": "model",
     "confidence": 1.0, "p_necessary": 1.0, "calibration": "L0",
     "arguments": {"...": "..."}, "parameter_basis": "request_rate=50000 -> 5000 req/min per IP",
     "rationale": "The attack has a request rate of 50000, so ..."}
  ],
  "rejected_actions": [
    {"name": "share_threat_intel", "decision_basis": "model", "confidence": 1.0,
     "p_necessary": 0.0, "calibration": "L0", "rationale": "..."}
  ],
  "explanation_source": "llm"
}
```

  `confidence` is the model's probability for the chosen side (P(necessary)
  for selected actions, 1 − P for rejected ones, 1.0 for mandatory rules); it is
  computed by code, never generated. Each `selected_actions[]` entry also carries
  `confidence` and uses the rationale as `reason`. If generation fails or
  `JEV_EXPLAIN=false`, rationales fall back to templates
  (`explanation_source: "template"`).

```bash
python3 -m venv .venv
.venv/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch
.venv/bin/pip install -r server/requirements-jev.txt
LLM_MODEL=anyjev .venv/bin/python scripts/demo_offline.py HTTP_Flood

# Optional L1 / L2 (per-action temperature / hidden-state head), needs anyjev >= 0.2.
# 1) labels: Claude Opus + Sonnet (`claude -p`, minimal context) label synthetic
#    alerts under docs/response_policy.md; a label is kept only where both agree;
#    20% of alerts are a fixed test split
.venv/bin/python scripts/jev_teacher_labels.py -n 320 --max-cost 30 --out artifacts/teacher_labels.jsonl
# 2) fit on the train split, evaluate L0 vs L1 vs L2 on the test split
LLM_MODEL=anyjev .venv/bin/python scripts/jev_fit.py --labels artifacts/teacher_labels.jsonl \
    --levels L1,L2 --out artifacts/jev_artifacts.json
# 3) serve: each question uses its own L2 head, else its L1 temperature, else L0
LLM_MODEL=anyjev JEV_ARTIFACTS=artifacts/jev_artifacts.json .venv/bin/python scripts/demo_offline.py
```

Qwen3-4B in bf16 needs ~8 GB of RAM. To run it inside the `server` container,
build the image with torch + AnyJev and mount the host Hugging Face cache
(download the weights once on the host first):

```bash
WITH_JEV=true LLM_MODEL=anyjev docker compose up -d --build db mcp executor server
```

`./artifacts` is mounted read-only into the container and
`artifacts/jev_artifacts.json` is loaded at startup. Choose the level with
`JEV_MAX_LEVEL` (set in `.env`, or override per run) and restart the server —
no rebuild or refit needed:

```bash
JEV_MAX_LEVEL=L2 docker compose up -d server   # L2 head where fitted, else L1, else L0
JEV_MAX_LEVEL=L1 docker compose up -d server   # temperature-calibrated L0 probabilities
JEV_MAX_LEVEL=L0 docker compose up -d server   # zero-label baseline
```

The `calibration` field of each action in the response's `explanation` shows
the level that answered it. After refitting on the host, restart the server to
load the new artifacts.

The container is capped by `SERVER_MEM_LIMIT` (default `12g`). With Docker
Desktop's WSL2 backend all containers share the WSL VM's memory (default: half
of host RAM); raise it with `memory=` in `%UserProfile%\.wslconfig`, then
`wsl --shutdown`.

### Fine-tuning jobs for the local model (interface; dry run for now)

Fine-tuning Qwen3 is **model maintenance, not an incident response**, so it is
not in the action catalog: the decision engine never sees it and cannot pick it
while handling an alert. It has its own API and its own MCP tools
(`training_start_job`, `training_get_job`). Each job runs in a **detached**
trainer container beside alert handling, so `/report` never waits on it.

```
POST /training/jobs ─▶ training_jobs row ─▶ MCP training_start_job ─▶ trainer container (detached)
GET  /training/jobs/{id} ◀── MCP training_get_job ◀── /jobs/<id>/status.json (shared volume)
```

```bash
docker compose build trainer            # ra3-trainer:latest
curl -X POST localhost:8000/training/jobs -H 'Content-Type: application/json' \
     -d '{"mode": "dry_run"}'            # 202, runs in the background
curl localhost:8000/training/jobs        # list and status
```

* `dry_run` (default) validates the dataset (`artifacts/teacher_labels.jsonl`)
  and the environment, and writes the training plan (LoRA settings, train/eval
  split, post-steps). It trains nothing and needs no GPU.
* `train` fails with an explicit reason until a GPU trainer image exists
  (torch + transformers + peft; set `TRAINER_GPU=true`). A fine-tuned model has
  new weights, so the L1/L2 artifacts must be refit (`scripts/jev_fit.py`) and
  the new model evaluated before it replaces the current one.
* One job at a time (a second one gets 409). Trigger manually, or automatically
  every `FINETUNE_TRIGGER_EVERY` reported incidents (0 = manual only).
* The trainer container has no network and a memory cap (`TRAINER_MEM_LIMIT`);
  data (`./artifacts`) and the Hugging Face cache are mounted read-only.
* Run `docker compose` from the project directory: the trainer's host mounts
  are derived from `$PWD` and `$HOME`.

## Project layout

```
ra3-respond/
├── docker-compose.yml        # db + server + mcp + executor + client
├── .env.example              # environment template
├── db/init.sql               # schema + seeded action catalog
├── server/                   # FastAPI app (decision plane + MCP client)
│   ├── main.py               # app entrypoint
│   ├── router.py             # /report /incidents /actions /health
│   ├── llm.py                # Claude function-calling decision engine
│   ├── jev_decider.py        # local-model decision engine (AnyJev, LLM_MODEL=anyjev)
│   ├── mcp_client.py         # executes selected actions via the MCP server
│   ├── actions.py            # 9 action tool schemas + metadata
│   ├── models.py             # SQLAlchemy models (3 tables)
│   ├── schemas.py            # Pydantic request/response schemas
│   ├── database.py           # async engine + session
│   └── alembic/              # migrations
├── mcp_server/               # MCP server (execution plane)
│   ├── server.py             # FastMCP: 9 actions + 2 training tools as MCP tools
│   ├── training.py           # launches / tracks detached trainer containers
│   └── runner.py             # launches one ephemeral executor container/action
├── trainer/                  # fine-tuning job image (detached, one per job; dry run for now)
├── executor/                 # ephemeral executor image (one-shot per action)
│   ├── execute.py            # entrypoint: run one action, emit JSON, exit
│   └── handlers.py           # the 9 mock action implementations
└── client/
    └── simulate.py           # 5G-NIDD threat report simulator
```

## Notes

- All DB access is `async` (asyncpg + SQLAlchemy async session); all routes are
  `async def`.
- Errors handled explicitly: DB connectivity (`/health`, 500 on persist
  failure), LLM API failure (502 with rollback), invalid/`Normal` attack types
  (400/422).
- `db/init.sql` seeds the catalog for a fresh deployment. Alembic
  (`server/alembic`) provides the equivalent schema for environments that
  prefer migration-driven setup: `alembic upgrade head`.
- **MCP + execution:** the `mcp` service mounts the host Docker socket
  (`/var/run/docker.sock`) so it can launch sibling executor containers. Those
  run with `--network none` and a memory cap. The `executor` compose service is
  a *build target* for the `ra3-executor:latest` image — it exits immediately on
  `up` (that's expected), and the image is what gets run ephemerally per action.
- **Mock vs real enforcement:** actions currently *simulate* their effect in
  `executor/handlers.py`. To perform real mitigations, replace those handler
  bodies (and give the executor container the necessary privileges/network).
```
