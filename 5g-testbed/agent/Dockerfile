# testbed-agent: bounded control surface RA3 drives (docker CLI + python stdlib).
FROM python:3.11-slim
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker
COPY agent.py /opt/agent/agent.py
ENV PYTHONUNBUFFERED=1
EXPOSE 8090
ENTRYPOINT ["python3", "/opt/agent/agent.py"]
