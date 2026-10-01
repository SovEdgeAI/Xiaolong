#!/bin/bash
# wsl_run.sh - run approach2 scripts on Docker Desktop (WSL2), inside a2-host.
#
#   ./wsl_run.sh                 # whole stack: 00 + run_all.sh
#   ./wsl_run.sh ./08_start_ran.sh
#   ./wsl_run.sh bash            # a shell in the "host" namespace
#
# Docker Desktop's --network=host is the Docker VM's namespace, not WSL's, so
# the scripts (which create veths and bridges there and talk to ONOS on
# localhost) must run in a container on that namespace. a2-host is that
# container: long-lived, because 09 leaves the flow API and ML services
# running in it. It runs as your user, so files it writes stay yours.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
NAME=a2-host
IMAGE=a2-host:local

docker build -q -t "$IMAGE" "$DIR/host" >/dev/null

if [[ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]]; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  SOCK_GID=$(docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$IMAGE" \
             stat -c %g /var/run/docker.sock)
  # Same absolute repo path inside, so bind mounts the scripts pass to
  # `docker run` resolve on the daemon side exactly as they would natively.
  docker run -d --name "$NAME" --network=host --restart unless-stopped \
    --user "$(id -u):$(id -g)" --group-add "$SOCK_GID" -e HOME=/tmp \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$REPO:$REPO" -w "$DIR" \
    "$IMAGE" sleep infinity >/dev/null
  echo "[wsl] started $NAME (Docker VM host namespace)"
fi

if [[ $# -eq 0 ]]; then
  set -- ./run_all.sh
fi
TTY=(); [[ -t 0 && -t 1 ]] && TTY=(-it)
exec docker exec "${TTY[@]}" -w "$DIR" "$NAME" "$@"
