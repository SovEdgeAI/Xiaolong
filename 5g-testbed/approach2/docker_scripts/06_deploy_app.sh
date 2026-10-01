#!/bin/bash
# 06_deploy_app.sh
#
# Docker-based replacement for bash_scripts/generate_netcfg.sh + upload_onos.sh.
#
# Differences from upstream:
#   * Maven runs in a container (no host mvn), as the invoking user so the build
#     output does not end up root-owned.
#   * The REST endpoint is localhost rather than `hostname -I`, because ONOS runs
#     with --network=host.
#   * The .oar is addressed by artifact name; target/ also holds the committed
#     approach4 artifacts from the previous iteration, so a bare *.oar glob is
#     ambiguous.
#   * The build runs against an out-of-tree copy of the module. `mvn clean` is
#     required (stale approach4 @Component classes would otherwise be bundled
#     into the .oar and ONOS would try to activate them against a missing
#     /approach4.json), but target/ is committed to git - so cleaning in place
#     would delete tracked files on every deploy. Building in run/build/ keeps
#     both properties.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPROACH2="$(cd "$DIR/.." && pwd)"
APP_DIR="$APPROACH2/onos_app/approach2"
P4_DIR="$APPROACH2/p4-code"
P4_PROGRAM="${1:-onos-p4-gtp}"

PIPECONF="us.fiu.adwise.approach2"
ARTIFACT="approach2-1.0-SNAPSHOT"
ONOS_URL="http://localhost:8181"
AUTH="onos:rocks"
CURL=(curl -sS --noproxy localhost --user "$AUTH")

echo "[06] Pipeconf: $PIPECONF"

# Out-of-tree build sandbox: sources + pom only, never the committed target/.
BUILD="$DIR/run/build"
rm -rf "$BUILD"
mkdir -p "$BUILD"
cp "$APP_DIR/pom.xml" "$BUILD/"
cp -r "$APP_DIR/src" "$BUILD/"

# The pipeconf loads /onos-p4-gtp.{p4info.txt,json} off the bundle classpath.
mkdir -p "$BUILD/src/main/resources"
cp "$P4_DIR/$P4_PROGRAM.json" "$P4_DIR/$P4_PROGRAM.p4info.txt" "$BUILD/src/main/resources/"
echo "[06] Staged P4 artifacts into the build sandbox"

echo "[06] Building $ARTIFACT.oar..."
docker run --rm -v "$BUILD":/app -v a2-m2:/root/.m2 -w /app \
  --user "$(id -u):$(id -g)" -e MAVEN_CONFIG=/tmp/.m2 \
  maven:3.8-openjdk-11 mvn -B -q -Duser.home=/tmp clean package -DskipTests

OAR="$BUILD/target/$ARTIFACT.oar"
[[ -f "$OAR" ]] || { echo "Error: $OAR not produced." >&2; exit 1; }
echo "[06] Built $(basename "$OAR") ($(stat -c%s "$OAR") bytes)"

# Remove any previous copy; absent app is not an error.
"${CURL[@]}" -X DELETE "$ONOS_URL/onos/v1/applications/$PIPECONF" >/dev/null 2>&1 || true
sleep 3

echo "[06] Uploading and activating the app..."
"${CURL[@]}" --fail -X POST -H "Content-Type: application/octet-stream" \
  --data-binary "@$OAR" "$ONOS_URL/onos/v1/applications?activate=true" >/dev/null
echo "[06] App activated."

# netcfg.json ships with a <REPLACE_WITH_PIPECONF> placeholder.
NETCFG="$DIR/run/netcfg.json"
mkdir -p "$DIR/run"
sed "s|<REPLACE_WITH_PIPECONF>|\"$PIPECONF\"|g" "$APPROACH2/bash_scripts/netcfg.json" > "$NETCFG"
cp "$NETCFG" "$APP_DIR/netcfg.json"

echo "[06] Pushing network configuration..."
"${CURL[@]}" --fail -X POST -H 'Content-Type:application/json' \
  -d "@$NETCFG" "$ONOS_URL/onos/v1/network/configuration" >/dev/null
echo "[06] Network configuration pushed."

echo "[06] Waiting for device:s1 to come up..."
for i in $(seq 1 60); do
  state=$("${CURL[@]}" "$ONOS_URL/onos/v1/devices/device:s1" 2>/dev/null \
          | grep -o '"available":[a-z]*' | cut -d: -f2 || true)
  if [[ "$state" == "true" ]]; then
    echo "[06] device:s1 is AVAILABLE after ${i}s."
    exit 0
  fi
  sleep 1
done

echo "[06] WARNING: device:s1 did not become available; check 'docker logs onos'." >&2
"${CURL[@]}" "$ONOS_URL/onos/v1/devices" || true
exit 1
