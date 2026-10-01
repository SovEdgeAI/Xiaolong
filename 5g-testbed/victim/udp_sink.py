#!/usr/bin/env python3
"""UDP sinks for the victim: bind the flood/scan ports and drain them.

A UDP datagram is only counted by the kernel (/proc/net/snmp Udp InDatagrams,
which victim/metrics.py reads) when a socket actually consumes it. The ncat
listeners this replaces did not drain reliably, so a UDP flood registered as 0
even though the packets arrived. These sockets drain continuously and keep a
per-port received count, exposed via a tiny status file the metrics service
reads as a reliable fallback.

Binds every port in UDP_SINK_PORTS (default 53,5060,161,123) on 0.0.0.0.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time

PORTS = [int(p) for p in os.environ.get("UDP_SINK_PORTS", "53,5060,161,123").split(",")]
STATE = os.environ.get("UDP_SINK_STATE", "/tmp/udp_sink.json")
_counts: dict[int, int] = {p: 0 for p in PORTS}
_lock = threading.Lock()


def _sink(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    except OSError:
        pass
    s.bind(("0.0.0.0", port))
    while True:
        try:
            s.recvmsg(2048)
        except OSError:
            continue
        with _lock:
            _counts[port] += 1


def _dump() -> None:
    while True:
        time.sleep(1)
        with _lock:
            snap = dict(_counts)
        tmp = STATE + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump({"ts": time.time(), "received": snap, "total": sum(snap.values())}, f)
            os.replace(tmp, STATE)
        except OSError:
            pass


def main() -> None:
    for p in PORTS:
        threading.Thread(target=_sink, args=(p,), daemon=True).start()
    print(f"udp sink draining ports {PORTS}", flush=True)
    _dump()


if __name__ == "__main__":
    main()
