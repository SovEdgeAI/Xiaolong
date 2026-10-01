# a2-host: the "host" for approach2 on Docker Desktop (WSL2, macOS).
#
# On Docker Desktop, `--network=host` is the Docker VM's network namespace,
# not the machine you type commands on: the veth fabric, br-p4-onos, ONOS's
# REST port and the stratum port all live there and are invisible to the
# desktop shell. The deploy scripts assume they run in that namespace, and
# 09 starts the flow API / ML services there. This image is that host: the
# scripts run inside it (see ../wsl_run.sh), unchanged.
FROM python:3.11-slim

RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      bash curl ca-certificates iproute2 procps nodejs npm \
 && rm -rf /var/lib/apt/lists/*

# Docker CLI only; the daemon is the host's, reached through the mounted socket.
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker

# The shipped LogisticRegression / GaussianNB / scaler pickles load under
# scikit-learn 1.6.1 (RandomForestClassifier.joblib does not, and is unused).
RUN pip install --no-cache-dir scikit-learn==1.6.1 joblib numpy requests

ENV PYTHONUNBUFFERED=1
