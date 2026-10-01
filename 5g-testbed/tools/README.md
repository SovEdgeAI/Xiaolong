# tools/

## `enforce.py` — block or rate-limit, with the mechanism chosen for you

The testbed has five enforcement mechanisms with five different control surfaces.
`enforce.py` picks one from *what you target*, applies it, and prints which one and why.

| Target | Approach 2 (P4/ONOS) | Approach 1 (OVS/Ryu) |
|---|---|---|
| `block --ue IP` | P4 `dropped_inner_ipv4` — this UE only, in the switch | UPF iptables after decapsulation (OVS can't single out a UE) |
| `limit --flow S,D,P` | P4 per-flow meter cell | refused — OVS can't see inside GTP-U |
| `limit --ue IP` | P4 meter on every flow of that UE | refused — use `--imsi` |
| `limit --tunnel` | — | OVS `linux-htb` queue via OpenFlow `set_queue` |
| `limit --imsi IMSI` | core Session-AMBR | core Session-AMBR |

```bash
tools/enforce.py block  --ue 10.45.0.3
tools/enforce.py limit  --flow 10.45.0.3,192.168.230.1,6 --rate 10000     # kbps
tools/enforce.py limit  --tunnel --rate 20000
tools/enforce.py limit  --imsi 001010000000001 --rate 50000 --approach 1 --reregister
tools/enforce.py clear  --ue 10.45.0.3            # also --flow / --tunnel / --imsi
tools/enforce.py status
tools/enforce.py <anything> --dry-run             # show the decision only
```

Both deployments hand out `10.45.0.0/16`, so a bare UE address is resolved by which UE
container actually holds it; addresses on no interface (spoofed/replayed sources) go to
approach 2. Force it with `--approach`.

Verified live (before → during → after):

| Backend | Result |
|---|---|
| P4 block | 0% → 100% → 0% loss |
| UPF iptables block | 0% → 100% → 0% loss |
| P4 per-flow meter @10 Mbit/s | 69.5 → 7.9 → 69.5 Mbit/s |
| OVS HTB @20 Mbit/s | 1182 → 19.2 → 1205 Mbit/s, detection punt kept |
| Core AMBR @50 Mbit/s | 1192 → 58.7 → 1205 Mbit/s |

Notes:
- **`clear --ue` resets the IP's switch counters and flow history *before* releasing the
  block.** The detector's features are lifetime counters, so a host that attacked once
  looks like an attacker forever unless its `gtp_flows` entries are deleted; doing the
  release first let stale votes re-flag it within one cycle.
- OVS shaping rewrites approach 1's detection punt rule to `controller,set_queue:1,normal`
  rather than adding a separate rule (which the priority-1000 punt would shadow), so
  detection keeps running while shaped. `clear --tunnel` restores `controller,normal`.
- Needs the `ovs-tools` helper container for OVS operations.

## `replay_pcap.sh` / `pcap_adapt.py` — feed a capture through the 5G path (approach 2)

```bash
tools/replay_pcap.sh datasets/samples/synthetic_syn_flood_ethernet.pcap --loop 40
tools/replay_pcap.sh attack.pcap --pps 2000 --proto tcp --max-packets 50000
```

`pcap_adapt.py` turns a dataset capture into something a UE can send: raw-IP link type,
each original source mapped to its own `10.45.x.y` (keeps the multi-attacker structure),
destination pinned to a DN the UE routes through the tunnel, packets over the 1400-byte
tunnel MTU trimmed, checksums recomputed. `tcpreplay` then injects it into `uesimtun0`,
UERANSIM encapsulates it as GTP-U, and it reaches the P4 switch like real UE traffic.
Spoofed sources survive the tunnel, and each becomes its own flow in the pipeline.

Sources are mapped into the UE pool on purpose: `MitigationModule` picks the address to
block as `src.startsWith("10.45.0") ? src : dst`, and the flow API refuses to auto-flag a
non-UE source — a foreign attacker address would otherwise get the DN blocked.

The detector needs ~5 consecutive attack votes at 5 s polling, so an attack must last
**more than ~40 s**; loop short captures (`--loop`) or pace them (`--pps`).

Verified with the bundled sample (5 SYN-flood sources at ~1000 pps + 1 benign host):
all five attackers blocked within 48 s; a blocked source measured **408 GTP-U packets
entering the switch, 1 leaving toward the UPF**, versus 11/11 for an unblocked UE.
