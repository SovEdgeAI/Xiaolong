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
│   ├── mcp_client.py         # executes selected actions via the MCP server
│   ├── actions.py            # 9 action tool schemas + metadata
│   ├── models.py             # SQLAlchemy models (3 tables)
│   ├── schemas.py            # Pydantic request/response schemas
│   ├── database.py           # async engine + session
│   └── alembic/              # migrations
├── mcp_server/               # MCP server (execution plane)
│   ├── server.py             # FastMCP: 9 actions exposed as MCP tools
│   └── runner.py             # launches one ephemeral executor container/action
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
