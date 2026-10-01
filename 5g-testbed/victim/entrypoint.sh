#!/bin/sh
# Start the victim's listeners, then the metrics service in the foreground.
#
# Extra ports exist so a scan has something to find and close-port actions have
# something to close. They are simple echo/accept listeners, not real services.
set -e

nginx   # web service on :80 (stub_status on /nginx_status for metrics)

# Idle TCP listeners for scan tests (echo on accept).
for port in 53 23 3306; do
    ncat -k -l -p "$port" --sh-exec 'echo service' >/dev/null 2>&1 &
done

# UDP sinks: a proper receiver that DRAINS the flood/scan ports. A UDP datagram
# only counts in /proc/net/snmp (which metrics.py reads) when a socket consumes
# it, so ncat's non-draining UDP listeners made floods read as 0. See udp_sink.py.
UDP_SINK_PORTS="${UDP_SINK_PORTS:-53,5060,161,123}" python3 /opt/victim/udp_sink.py >/dev/null 2>&1 &

echo "victim: nginx :80, listeners $(echo 53 23 3306 'udp/53' 'udp/5060'), metrics :${METRICS_PORT:-9100}"
exec python3 /opt/victim/metrics.py
