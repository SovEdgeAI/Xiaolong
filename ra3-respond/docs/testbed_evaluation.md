# Stage 4: evaluating RA3 against the live 5G testbed

Does an RA3 decision actually resolve the alert when its actions are really
enforced? This connects RA3 to the
[5G-SDN-DDoS testbed](https://github.com/SovEdgeAI/5G-SDN-DDoS-Detection-Mitigation)
and measures the effect end to end.

## Roles

| Piece | Where | Role |
|---|---|---|
| Compromised UE (`ue-2`) | testbed | generates one 5G-NIDD attack at the victim |
| P4 switch / core | testbed | carries traffic; RA3's `block_ip` / `rate_limit` act here |
| Victim (`victim`) | testbed | target; exposes `/metrics` (the symptom of being attacked) |
| testbed-agent | testbed | the bounded control surface RA3 drives |
| RA3 (`ra3-server`) | RA3 | decides actions from the alert, executes them via the agent |
| harness (`scripts/testbed_eval.py`) | RA3 | runs the loop, measures, and judges |

**RA3 is the sole decider.** The testbed's own ML detector is turned off
(`tools/testbed_autonomy.sh off`), so nothing auto-blocks; the testbed is a pure
network + enforcement substrate. `MitigationModule` still reconciles the switch
against `/blocked-ips`, which is the path the agent drives for `block_ip`.

## The loop, per attack

1. **reset** — clear blocks, restore the victim to baseline, re-pin the UE→victim
   route, and (if the user plane wedged) restart the RAN.
2. **baseline / under-attack** — read the victim's metrics with no attack, then
   during the bounded attack. The under-attack numbers become the RA3 alert's
   `metadata` (the attack *type* is given; RA3 is not asked to classify).
3. **decide + enforce** — POST the alert to `/report`; RA3 picks actions and the
   executor enforces them on the testbed through the agent.
4. **measure again** — read the metrics under mitigation.
5. **verdict** — mechanism-aware (see below).

## Mechanism-aware verdict

A single "did the number drop" test misjudges server-side actions, so the
verdict depends on what RA3 did:

- **`enable_syn_cookie`** — resolved if the victim is *issuing SYN cookies*
  under the flood (`TcpExtSyncookiesSent` grows). The half-open count stays high
  (the flood continues), but the server keeps serving — which is the point.
- **`block_ip`** — resolved if attack traffic at the victim drops to ~0 (the UE
  is cut off at the switch).
- **`rate_limit` / `enable_http_rate_limit`** — resolved if attack traffic at the
  victim drops materially.

## Results (representative run)

| Attack | RA3 actions | Verdict | Note |
|---|---|---|---|
| SYN_Flood | enable_syn_cookie | RESOLVED | +24 827 SYN cookies issued under flood |
| HTTP_Flood | enable_http_rate_limit + block_ip | RESOLVED | 149 → 0.3 req/s at the victim |
| ICMP_Flood | rate_limit | **NOT RESOLVED** | see finding below |
| SYN_Scan | block_ip | RESOLVED | UE cut off at the switch |

**Finding — ICMP_Flood + `rate_limit` is ineffective here.** The P4 per-flow
meter is *byte*-rate; a small-packet ICMP flood is high in packets but low in
bandwidth, so it stays under the meter and is not dropped. This is a genuine
result about the mitigation, not a harness bug: for a packet-rate flood,
`block_ip` (or a packet-rate meter) is the effective action. It is exactly the
kind of gap the evaluation exists to surface.

## Known limitations

- **UDP** now traverses the testbed after two fixes (see docs/udp_fix.md):
  the P4 pipeline dropped inner-UDP flows, and the victim under-counted UDP.
  UDP_Flood is now measurable (~1800 pkt/s). UDP_Scan still reads a low symptom
  because nmap spreads probes across many ports and scans are inherently
  low-rate.
- **Single UE** — the attacker and any legitimate client are the same address,
  so `block_ip` is all-or-nothing and a separate benign-client probe is not
  possible without a second UE.
- **Small scale** — attacks are bounded (the datapath is a ~50 Mbit/s software
  switch); this tests whether an action *works*, not its performance.

## Running it

```bash
# once: make RA3 the sole decider
5G-SDN-DDoS-Detection-Mitigation/tools/testbed_autonomy.sh off

# faster decisions during eval (skip the prose explanation)
EXECUTOR_MODE=testbed JEV_EXPLAIN=false docker compose up -d server

python3 scripts/testbed_eval.py SYN_Flood HTTP_Flood ICMP_Flood SYN_Scan \
    --duration 80 --out eval.json
```
