#!/usr/bin/env python3
"""Adapt an arbitrary pcap so it can be replayed from a UERANSIM UE into the 5G core.

A pcap downloaded from a DDoS dataset (CIC-DDoS2019, CAIDA, ...) cannot be fed to
`uesimtun0` as-is:

  * link type   - datasets are Ethernet (or Linux SLL); the UE's TUN wants raw IP.
  * sources     - attacker addresses come from the capture's network. They are
                  mapped into 10.45.0.0/16 (the UE pool) because approach2's
                  MitigationModule picks the address to block with
                  `src.startsWith("10.45.0") ? src : dst` - a foreign source would
                  make it block the *destination* instead.
  * destination - must be an address ue-2 routes through the tunnel, otherwise the
                  traffic leaves via Docker's eth0 and never reaches the switch.
  * size        - the tunnel MTU is 1400; larger packets are truncated so the
                  replayed packet *rate* keeps the capture's shape.
  * checksums   - recomputed after every rewrite.

Spoofed sources are carried through: UERANSIM encapsulates whatever the TUN
hands it, and the P4 pipeline tracks each inner source as its own flow.

Usage (inside a container with scapy, e.g. ue-2):
  pcap_adapt.py IN OUT [--dst 192.168.230.1] [--src-mode spoof|ue] [--ue-ip IP]
                [--proto tcp|udp|icmp] [--max-packets N] [--mtu 1400]
"""
import argparse
import ipaddress
import sys

from scapy.all import IP, TCP, UDP, ICMP, Raw, PcapReader, PcapWriter  # noqa: E402

DLT_RAW = 101
PROTO = {"tcp": 6, "udp": 17, "icmp": 1}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inp")
    ap.add_argument("out")
    ap.add_argument("--dst", default="192.168.230.1",
                    help="destination the UE routes via uesimtun0 (default: %(default)s)")
    ap.add_argument("--src-mode", choices=["spoof", "ue"], default="spoof",
                    help="spoof: each original source -> its own 10.45.x.y (keeps the multi-attacker "
                         "structure); ue: every packet from the UE's real tunnel address")
    ap.add_argument("--ue-ip", help="UE tunnel address, required for --src-mode ue")
    ap.add_argument("--spoof-base", default="10.45.100.1",
                    help="first address handed out in spoof mode (default: %(default)s)")
    ap.add_argument("--proto", choices=sorted(PROTO), help="keep only this protocol")
    ap.add_argument("--max-packets", type=int, default=0, help="stop after N output packets (0 = all)")
    ap.add_argument("--mtu", type=int, default=1400, help="tunnel MTU (default: %(default)s)")
    a = ap.parse_args()

    if a.src_mode == "ue" and not a.ue_ip:
        sys.exit("--src-mode ue needs --ue-ip")
    pool = ipaddress.ip_network("10.45.0.0/16")
    next_spoof = ipaddress.ip_address(a.spoof_base)
    if next_spoof not in pool:
        sys.exit("--spoof-base must be inside 10.45.0.0/16")

    mapping, seen, written, skipped, truncated, fragments = {}, 0, 0, 0, 0, 0
    first_ts = last_ts = None
    writer = PcapWriter(a.out, linktype=DLT_RAW, sync=False)

    for pkt in PcapReader(a.inp):
        seen += 1
        ip = pkt.getlayer(IP)
        if ip is None:
            skipped += 1              # ARP, IPv6, LLDP, ...: nothing to replay over the IPv4 PDU session
            continue
        if a.proto and ip.proto != PROTO[a.proto]:
            skipped += 1
            continue

        ip = ip.copy()
        orig = ip.src
        if a.src_mode == "ue":
            ip.src = a.ue_ip
        else:
            if orig not in mapping:
                if next_spoof not in pool:
                    sys.exit("ran out of 10.45.0.0/16 addresses for distinct sources")
                mapping[orig] = str(next_spoof)
                next_spoof += 1
            ip.src = mapping[orig]
        ip.dst = a.dst

        # Keep the rate shape: trim oversized packets instead of dropping them.
        if len(ip) > a.mtu:
            keep = a.mtu - (len(ip) - len(ip[Raw].load)) if ip.haslayer(Raw) else None
            if keep is None or keep < 0:
                skipped += 1
                continue
            ip[Raw].load = ip[Raw].load[:keep]
            truncated += 1

        # Force scapy to recompute the lengths and checksums the rewrite broke.
        del ip.len, ip.chksum
        is_fragment = bool(ip.flags.MF) or ip.frag > 0
        if is_fragment:
            # A fragment's L4 header (first fragment) or payload (the rest) describes
            # the whole datagram, not this piece, so recomputing it would corrupt it.
            # Only the IP header is rebuilt; the L4 checksum is left stale, which the
            # pipeline never checks. Real captures here are up to 100% fragments.
            fragments += 1
        else:
            for layer in (TCP, UDP, ICMP):
                if ip.haslayer(layer):
                    del ip[layer].chksum
            if ip.haslayer(UDP):
                del ip[UDP].len

        out = IP(bytes(ip))
        out.time = pkt.time
        writer.write(out)
        written += 1
        first_ts = pkt.time if first_ts is None else first_ts
        last_ts = pkt.time
        if a.max_packets and written >= a.max_packets:
            break

    writer.close()
    dur = float(last_ts - first_ts) if written > 1 else 0.0
    print(f"read {seen} packets, wrote {written} (skipped {skipped} non-IPv4/filtered, "
          f"truncated {truncated}, fragments {fragments})")
    print(f"capture span {dur:.2f}s -> {written / dur:.0f} pps at original timing" if dur else "capture span 0s")
    if a.src_mode == "spoof":
        print(f"{len(mapping)} distinct sources mapped:")
        for k, v in list(mapping.items())[:12]:
            print(f"  {k:>15} -> {v}")
        if len(mapping) > 12:
            print(f"  ... {len(mapping) - 12} more")
    else:
        print(f"all packets sent from UE address {a.ue_ip}")
    print(f"destination rewritten to {a.dst}")


if __name__ == "__main__":
    main()
