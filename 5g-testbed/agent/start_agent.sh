#!/bin/bash
# start_agent.sh - the testbed-agent RA3 drives to enforce actions.
#
# Runs on the docker default bridge (so it reaches the flow API at
# 172.17.0.1:23500 and the victim), with the docker socket mounted so it can
# exec into the victim / a2-host. RA3's executor reaches it at
# http://172.17.0.1:8090 (the bridge gateway) or by container IP.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/.." && pwd)"
NAME=testbed-agent
IMAGE=testbed-agent:local
PORT="${AGENT_PORT:-8090}"

docker build -q -t "$IMAGE" "$DIR" >/dev/null

SOCK_GID=$(docker run --rm --entrypoint stat -v /var/run/docker.sock:/var/run/docker.sock "$IMAGE" \
           -c %g /var/run/docker.sock)

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --restart unless-stopped \
  -p "${PORT}:${PORT}" \
  --group-add "$SOCK_GID" \
  -e AGENT_PORT="$PORT" -e REPO_DIR="$REPO" \
  -e FLOW_API="${FLOW_API:-http://172.17.0.1:23500}" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$REPO:$REPO:ro" \
  "$IMAGE" >/dev/null

for i in $(seq 1 20); do
  if curl -sf -m 2 "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    echo "[agent] up at http://127.0.0.1:${PORT} (RA3 reaches it at http://172.17.0.1:${PORT})"
    exit 0
  fi
  sleep 0.5
done
echo "[agent] did not become healthy; docker logs $NAME" >&2
docker logs --tail 20 "$NAME" >&2 || true
exit 1
