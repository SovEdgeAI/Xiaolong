#!/bin/bash
# 00_prereqs.sh - things run_all.sh assumes the host already has. Idempotent.
#
# On the original host these came from approach1 and a local toolchain; on a
# fresh machine (e.g. Docker Desktop on WSL2, via ./wsl_run.sh) they do not
# exist, so this step provides them:
#
#   1. the SCTP kernel module   AMF <-> gNB NGAP runs over SCTP; WSL2 ships it
#                               as a module that is not loaded by default
#   2. mongo-container          subscriber DB (open5gs_a2) + flow DB; approach1
#                               used to create it
#   3. a UERANSIM build         08 copied it from approach1's gnb-1 container;
#                               here it is built from UERANSIM.zip into run/
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
MONGO_IMAGE="${MONGO_IMAGE:-mongo:6.0}"
UERANSIM_DIR="${UERANSIM_DIR:-$DIR/run/ueransim}"

# --- 1. SCTP --------------------------------------------------------------
if docker run --rm alpine test -e /proc/net/sctp; then
  echo "[00] SCTP module already loaded"
else
  echo "[00] Loading the SCTP kernel module..."
  docker run --rm --privileged -v /lib/modules:/lib/modules:ro alpine \
    sh -c 'apk add -q kmod >/dev/null && modprobe sctp' \
    || { echo "Error: could not load sctp; run 'sudo modprobe sctp' on the host." >&2; exit 1; }
  docker run --rm alpine test -e /proc/net/sctp && echo "[00] SCTP loaded"
fi

# --- 2. MongoDB -----------------------------------------------------------
if [[ "$(docker inspect -f '{{.State.Running}}' mongo-container 2>/dev/null)" == "true" ]]; then
  echo "[00] mongo-container already running"
else
  docker rm -f mongo-container >/dev/null 2>&1 || true
  # Published on 0.0.0.0:27017 of the host namespace, so it is reachable as
  # 192.168.235.1:27017 from the fabric (02/07) and 127.0.0.1:27017 from 09.
  docker run -d --name mongo-container --restart unless-stopped \
    -p 27017:27017 "$MONGO_IMAGE" >/dev/null
  echo "[00] started mongo-container ($MONGO_IMAGE)"
fi
for i in $(seq 1 30); do
  docker exec mongo-container mongosh --quiet --eval 'db.runCommand({ping:1}).ok' 2>/dev/null \
    | grep -q 1 && { echo "[00] MongoDB is answering"; break; }
  [[ $i -eq 30 ]] && { echo "Error: MongoDB did not come up" >&2; exit 1; }
  sleep 1
done

# --- 3. UERANSIM ----------------------------------------------------------
if [[ -x "$UERANSIM_DIR/nr-gnb" && -x "$UERANSIM_DIR/nr-ue" ]]; then
  echo "[00] UERANSIM already built in $UERANSIM_DIR"
else
  echo "[00] Building UERANSIM from UERANSIM.zip (several minutes)..."
  # Same base image as gnb-2 / ue-2 (03), so the binaries' glibc matches.
  docker build -q -t ueransim-builder:local - >/dev/null <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      make gcc g++ cmake libsctp-dev lksctp-tools unzip >/dev/null \
 && rm -rf /var/lib/apt/lists/*
EOF
  mkdir -p "$UERANSIM_DIR"
  docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$REPO/UERANSIM.zip:/src.zip:ro" -v "$UERANSIM_DIR:/out" ueransim-builder:local \
    sh -c 'set -e; cd /tmp && unzip -q /src.zip && cd UERANSIM \
           && make -j"$(nproc)" >/tmp/build.log 2>&1 || { tail -30 /tmp/build.log; exit 1; }; \
           cp build/nr-gnb build/nr-ue build/nr-cli build/nr-binder build/libdevbnd.so /out/ \
           && cp -r config /out/'
  echo "[00] UERANSIM built: $(ls "$UERANSIM_DIR" | tr '\n' ' ')"
fi
