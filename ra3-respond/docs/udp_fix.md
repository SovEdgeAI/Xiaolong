# Fixing UDP on the 5G SDN testbed

UDP_Flood / UDP_Scan alerts could not be evaluated: a UDP flood registered as
0 pkt/s at the victim while TCP and ICMP worked. Two independent bugs, both now
fixed.

## Bug 1 — the P4 pipeline dropped inner-UDP flows

`approach2/p4-code/onos-p4-gtp.p4` parsed an extra `inner_udp` header **only**
for inner protocol 17 (UDP); TCP and ICMP fell through to `accept`. No table or
action ever read an `inner_udp` field — it was dead code, and the only
protocol-specific branch in the pipeline. It made inner-UDP packets take a
different path through `stratum_bmv2` and they never reached the UPF.

Traced with interface counters (tcpdump was unreliable in these containers):
the switch's `gtp_flows` counter incremented for UDP (packets matched) but the
UPF's `veth5` never received them — the packet was lost inside the switch.

**Fix:** remove the `inner_udp` parse so every inner protocol takes the same
path. After recompiling (p4c container) + p4info downgrade + redeploy, UDP
reaches the victim (verified: ~1800 pkt/s).

## Bug 2 — the victim under-counted UDP

`victim/metrics.py` read UDP via `/proc/net/snmp` `Udp.InDatagrams`, which only
counts datagrams a socket actually consumes. The `ncat` UDP listeners did not
drain, so floods read as 0 even though the packets arrived (confirmed: a raw
`AF_PACKET` sniff and a plain Python UDP socket both saw all packets).

**Fix:** `victim/udp_sink.py` binds the flood/scan ports and drains them,
exposing a reliable per-port received count. The evaluation reads
`rates.udp_sink_per_s` for UDP symptoms.

## Result

UDP_Flood is now measured at ~1800 pkt/s. RA3's `rate_limit` reduces it only
partially (the P4 meter is byte-rate, weak against small-packet floods — the
same genuine finding as ICMP_Flood), so the verdict is an honest NOT RESOLVED
rather than an un-measurable 0.
