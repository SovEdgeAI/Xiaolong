# pcap-replay — evaluating the approach-2 defense against real DDoS captures

Replays captures from the StopDDoS collection through the approach-2 5G path and measures
how the detection/mitigation pipeline responds. Defensive evaluation only: it drives
recorded attack traffic at the defender to see whether it detects, blocks, and stops it.

```bash
tools/fetch_stopddos.sh                       # download the 6 captures (git-ignored)
experiments/pcap-replay/run_all.sh            # 6 captures x 2 modes -> results/replay.csv
experiments/pcap-replay/run_capture.sh amp.UDP.DNSANY.pcap ue    # a single run
```

## What each run does

1. Clean slate: clear `/blocked-ips`, wipe the flow DB, rebuild the pipeline (clears
   `gtp_flows`), re-register the UE.
2. Start a benign control source (`10.45.200.1`, ICMP ~3 pps) that should *not* be flagged.
3. `tools/replay_pcap.sh` adapts and injects the capture into `uesimtun0`; it becomes real
   GTP-U through the gNB, switch and UPF.
4. Watch `/blocked-ips` and the switch drop rules; record when an attacker is blocked.
5. Mitigation proof on the wire: for a blocked source, count GTP-U packets **entering** the
   switch (`veth6`, gNB side) vs **reaching** the UPF (`veth4`). `out/in ≈ 0/N` = mitigated.
6. Append one row to `results/replay.csv`.

## Reading `results/replay.csv`

| column | meaning |
|---|---|
| `mode` | `ue` = malicious-UE threat model; `spoof` = keep original sources |
| `first_block_s` | seconds to first attacker block. **Cold-start only** (~45 s); back-to-back runs share warm in-memory state and block sooner — not a per-run latency number |
| `blocked_attackers` | distinct attacker addresses blocked (excludes the benign control) |
| `gtp_flows_peak` | `gtp_flows` entries at end; the P4 table defaults to **1024**, so spoof floods saturate it |
| `leak_out_in` | GTP-U packets reaching the UPF / entering the switch, for a blocked source. `1/13731` ≈ fully mitigated |
| `benign_flagged` | did the benign control get auto-blocked? (`yes` = a false positive) |
| `onos_ok` / `detector_ok` | did the controller and detector survive the run? |

## What "working well" looks like

- **`ue` mode (the design target):** attacker blocked, `leak_out_in` ≈ `small/large`, benign
  not flagged, ONOS + detector still up. This is the case the system was built for.
- **`spoof` mode (stress):** most sources send ~1 packet, and per-source detection needs 5
  consecutive samples from the same source, so few or none get blocked and `gtp_flows`
  saturates at 1024. "Working well" here means the testbed stays up and reports honest
  numbers — it characterises the design's limit against high-cardinality spoofed floods,
  which is a control-plane/P4 problem, not a bug in this code.

Detection latency is only meaningful on a cold start; see `first_block_s` above.
