# datasets/

Captures to replay through the testbed with `tools/replay_pcap.sh`.

`samples/synthetic_syn_flood_ethernet.pcap` (212 KB, committed) is built to look like a
downloaded dataset file: Ethernet link type, five foreign attacker addresses
(`172.16.0.11–15`) SYN-flooding one victim at ~1000 pps for 3 s, plus one benign host
pinging at 20 pps. It exists to exercise the adapter end to end.

## StopDDoS collection (used by the pcap-replay experiment)

`tools/fetch_stopddos.sh` downloads real-world attack captures from
[StopDDoS/packet-captures](https://github.com/StopDDoS/packet-captures) into
`datasets/stopddos/` (git-ignored). The licence permits free use for building DDoS
protection but does not grant redistribution, so the repo keeps the fetch script, not the
captures. Cite as: **L.F. Haaijer, *DDoS Packet Capture Collection* (2022)**.

The six representative captures the experiment uses (one per attack family, spanning
source-cardinality — which is what decides whether the per-source detector can act):

| Capture | pkts | sources | shape |
|---|---|---|---|
| `pkt.TCP.synflood.spoofed` | 37,841 | 37,623 | SYN, ~1 pkt/source |
| `pkt.ICMP.largeempty` | 9,999 | 9,891 | 755 B ICMP |
| `pkt.UDP.rdm.fixedlength` | 4,968 | 11 | 1321 B UDP, few sources |
| `amp.UDP.DNSANY` | 11,998 | 79 | DNS amplification, 35% fragmented |
| `amp.UDP.memcached.ntp.cldap` | 29,462 | 1,992 | multi-protocol amp, 24% fragmented |
| `pkt.UDP.fragmented` | 19,774 | 41 | 100% fragmented |

All are Ethernet link type and one-way (anonymised to a single destination), so
`pcap_adapt.py` handles them directly. Run the evaluation with
`experiments/pcap-replay/run_all.sh`.

**Two threat models, because source-cardinality is the whole story here** (see
`experiments/pcap-replay/`):
- **`ue` (malicious UE)** — the paper's model: all traffic from the compromised UE's own
  address. Every capture collapses to one flow the detector can flag and block.
- **`spoof`** — keep each original source; a stress test. Most StopDDoS captures are
  ~1 packet per source, and per-source detection needs 5 consecutive samples from the same
  source, so this exposes the design's limit rather than a clean block.

## Other public sources

Any pcap/pcapng works — link type, addressing and checksums are rewritten on the way in.

- **CIC-DDoS2019** (Canadian Institute for Cybersecurity) — labelled reflection and
  exploitation attacks, with per-flow CSV labels alongside the pcaps.
- **CAIDA DDoS Attack 2007** — one hour of anonymised attack traffic (access request).

Practical guidance:
- Dataset pcaps are tens of GB. Slice before replaying:
  `editcap -A "<start>" -B "<end>" big.pcap slice.pcap`, or pass `--max-packets`.
- Large files are git-ignored here (`datasets/*.pcap*` except `samples/`); keep a
  download script or checksum in the repo instead of the capture.
- Replay rate is bounded by the approach 2 path (`stratum_bmv2` is a software switch,
  ~50–70 Mbit/s) and UERANSIM's userspace tunnel, not by the capture's original rate.
- The shipped models were trained on unknown data with a 10-feature flow vector. Expect
  their verdicts on a new dataset to need validation — see "Detector accuracy" in
  `CLAUDE.md`.
