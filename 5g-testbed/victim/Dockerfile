# victim: the target the compromised UE's traffic is aimed at.
#
# Runs a web service (nginx), opens a few TCP/UDP ports for scan tests, and
# serves victim/metrics.py so the harness can read the symptoms of load and
# check whether an RA3 action resolved them. It receives traffic; it never
# generates or forwards any.
FROM python:3.11-slim

RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      nginx procps iproute2 iptables ncat \
 && rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx/nginx.conf
COPY metrics.py /opt/victim/metrics.py
COPY udp_sink.py /opt/victim/udp_sink.py
COPY entrypoint.sh /opt/victim/entrypoint.sh
RUN chmod +x /opt/victim/entrypoint.sh

# 80 web · 9100 metrics · 53/23/3306 extra listeners for scan tests
EXPOSE 80 9100 53 23 3306

ENTRYPOINT ["/opt/victim/entrypoint.sh"]
