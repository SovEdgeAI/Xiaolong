# RA3 × 5G DDoS Testbed

An end-to-end 5G threat-**response** control plane (RA3) wired to a live
5G-SDN-DDoS testbed. A detector sends RA3 an alert; RA3 decides which mitigations
to take (local Qwen3-4B + AnyJev + graduated rules) and **actually enforces them
on the network** — the SDN switch, the victim server, and the 5G core.

This repository bundles **two projects** that are coupled by an interface (not
merged):

```
  ra3-respond/   = Project A — RA3 response control plane (decide + enforce + audit)
  5g-testbed/    = Project B — 5G SDN DDoS testbed (Open5GS + UERANSIM + ONOS + P4)
                   + the integration additions (testbed-agent, victim, 2nd UE)
```

---

## Architecture

```
            ┌──────── RA3 (Project A) ────────┐        ┌──────── 5G testbed (Project B) ────────┐
 detector → │ ra3-server :8000  (POST /report)│        │ Open5GS core (cp/up) · gNB · UE(s)      │
            │  Qwen3-4B + AnyJev + rules      │        │ ONOS + P4 switch (stratum-bmv2)         │
            │ ra3-mcp → ra3-executor          │        │ victim server · mongo                   │
            │ ra3-db (audit)                  │        │                                         │
            └───────────────┬─────────────────┘        └───────────────────┬─────────────────────┘
                            │  EXECUTOR_MODE=testbed                        │
                            │  AGENT_URL=http://172.17.0.1:8090             │
                            └────────────► testbed-agent :8090 ────────────┘
                                           (RA3's single enforcement interface
                                            onto the underlying controllers)
```

RA3 never touches the network directly — it drives one **agent** that speaks to
the underlying controllers. To target a different network/controller, implement
the same agent contract (or edit `ra3-respond/executor/testbed.py`); RA3's
decision core does not change.

---

## What RA3 enforces (verified to really activate, not just a success flag)

| Action | Underlying controller | Concrete effect |
|---|---|---|
| `enable_syn_cookie` | victim kernel | `sysctl net.ipv4.tcp_syncookies=1` (kernel issues SYN cookies) |
| `set_connection_timeout` | victim nginx | shortens idle timeouts |
| `enable_http_rate_limit` | victim nginx | adds `limit_req` |
| `close_unnecessary_ports` | victim firewall | iptables DROP on the ports |
| `block_ip` | SDN controller (ONOS→P4) | drop rule on the source inner-IP |
| `rate_limit` | SDN controller (ONOS→P4) | per-flow meter |
| `throttle_ue_bandwidth` | P4 meter + 5G core | per-UE meter + lowers subscriber AMBR |
| `quarantine_ue` | P4 + 5G core + gNB | isolate + bar subscriber + gNB force-detach |
| `alert_operator`, `log_incident`, `share_threat_intel` | local | notify / audit / federate |

---

## Prerequisites

- **Docker** + Docker Compose.
- The testbed was built and tuned on **Docker Desktop on WSL2** (it uses the
  Docker-VM network namespace, an `a2-host` helper container, and needs the
  **SCTP** kernel module for AMF↔gNB). On plain Linux you may need to adjust
  networking; see `5g-testbed/` scripts.
- **RAM:** ≥ 16 GB recommended (5G core + ONOS + a local 4B model).
- **Decision model:** `Qwen/Qwen3-4B` is downloaded from Hugging Face on first
  run (~8 GB, cached in a volume). A CPU decision takes ~2–3 min. To validate
  the pipeline without the model, set `LLM_MODEL=mock`.

The model weights are **not** in this repo (they download at runtime).

---

## Quick start

```bash
# 1) bring up the 5G testbed (Project B)   — environment-sensitive, see notes
cd 5g-testbed
./approach2/docker_scripts/00_prereqs.sh
# ... run 01..09 in order (01_create_network ... 09_start_services)
./victim/start_victim.sh          # victim server + metrics
./victim/start_good_ue.sh         # a second, legitimate UE (collateral baseline)
./agent/start_agent.sh            # the enforcement interface RA3 drives (:8090)
./tools/testbed_autonomy.sh off   # disable the testbed's own detector (RA3 decides)

# 2) bring up RA3 (Project A), wired to the testbed
cd ../ra3-respond
cp .env.example .env              # then edit as needed (see below)
EXECUTOR_MODE=testbed AGENT_URL=http://172.17.0.1:8090 TESTBED_UE_IP=10.45.0.3 \
  WITH_JEV=true LLM_MODEL=anyjev JEV_MODEL=Qwen/Qwen3-4B \
  docker compose up -d --build

# 3) send an alert and watch RA3 decide + enforce
curl -s -X POST http://localhost:8000/report -H 'Content-Type: application/json' -d '{
  "client_id":"bs_node_01","attack_type":"SYN_Flood","severity":"critical",
  "confidence":0.95,"metadata":{"half_open_connections":512,"source_ips":1}}'
```

`../deploy_all.sh` runs the whole sequence; `../teardown.sh` stops everything.

### The RA3 API (how others call it)
- `POST /report` — submit an alert (JSON above); returns the chosen actions,
  their confidences, the real execution results, and an English explanation.
  Unknown attack types are accepted (classified by behaviour).
- `GET /incidents`, `GET /actions`, `GET /health`, `POST /training/jobs`.

---

## Evaluation

`ra3-respond/scripts/testbed_eval.py` runs the full before/after loop on the
testbed for each attack class (launch attack → RA3 decides + enforces → measure
whether the attack cleared and the legitimate UE was unharmed).

---

## Honest status / known limitations

- **Data-plane attacks** (floods, scans) are handled end-to-end and verified.
- **Control-plane attacks** (signaling storm, auth flood, slice exhaustion):
  RA3 **decides** correctly (`quarantine_ue`), and `quarantine_ue` now includes
  a real gNB force-detach. But fully *resolving* a persistent control-plane
  attack is **work in progress** — it needs (a) more robust UE identification for
  force-detach and (b) a RAN-level admission-control action for attackers that
  keep re-attempting. These are not yet proven resolved.
- The testbed's amplification/reflection attacks are simulated with equivalent
  direct-flood traffic (no real reflector topology).

See `ra3-respond/docs/` for the response policy and evaluation notes.
