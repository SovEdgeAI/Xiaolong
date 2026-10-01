#!/bin/bash
# 09_start_services.sh
#
# README steps 9, 10 and 15: the ONOS log server, the flow REST API backed by
# MongoDB, and the two ML processes.
#
# Ports: 7000 log server, 23500 flow API, ${PREDICT_PORT} prediction service.
# PREDICT_PORT defaults to 5501 rather than the upstream 5500 because the
# approach1 deployment on this host is already bound to 5500; nothing in
# approach2 dials the prediction service, so moving it is safe.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPROACH2="$(cd "$DIR/.." && pwd)"
LOGDIR="$DIR/run/logs"
mkdir -p "$LOGDIR"

# ryu-env is the interpreter approach1 already uses; it carries joblib/sklearn.
PY="${PY:-/home/herman/miniconda3/envs/ryu-env/bin/python}"
# Elsewhere (e.g. inside a2-host, which ships sklearn 1.6.1) use python3.
[[ -x "$PY" ]] || PY="$(command -v python3 || true)"
# Without this the Python services buffer stdout into their log files and the
# logs stay empty for minutes, which looks indistinguishable from a hang.
export PYTHONUNBUFFERED=1
export PREDICT_PORT="${PREDICT_PORT:-5501}"
export MONGO_URI="${MONGO_URI:-mongodb://127.0.0.1:27017/onos-p4-flows}"
export FLOW_API="${FLOW_API:-http://127.0.0.1:23500}"

[[ -x "$PY" ]] || { echo "Error: python not found at $PY" >&2; exit 1; }

start() {  # name, workdir, logfile, command...
  local name="$1" wd="$2" log="$3"; shift 3
  pkill -f "$name" >/dev/null 2>&1 || true
  sleep 0.5
  # setsid + </dev/null so the service does not keep this script's stdout pipe
  # open; otherwise anything reading our output blocks until the service exits.
  ( cd "$wd" && setsid nohup "$@" >"$log" 2>&1 </dev/null & )
  sleep 3
  if pgrep -f "$name" >/dev/null; then
    echo "  started $name  (log: $log)"
  else
    echo "  FAILED to start $name:" >&2; tail -15 "$log" >&2; return 1
  fi
}

echo "[09] Installing Node dependencies..."
cd "$APPROACH2/mongodb-app"
if [[ ! -d node_modules ]]; then
  npm install --silent --no-fund --no-audit express mongoose cors body-parser >/dev/null 2>&1
fi
echo "  node_modules ready"

echo "[09] Starting services..."
start logserver.py            "$APPROACH2/python_scripts" "$LOGDIR/logserver.log"  "$PY" logserver.py
start onos-p4-gtp-app.js      "$APPROACH2/mongodb-app"    "$LOGDIR/flowapi.log"    node onos-p4-gtp-app.js
start GetPredictionModule.py  "$APPROACH2/ML"             "$LOGDIR/predict.log"    "$PY" GetPredictionModule.py
start getDBData.py            "$APPROACH2/ML"             "$LOGDIR/getdbdata.log"  "$PY" getDBData.py

echo "[09] Listening ports:"
ss -ltn 2>/dev/null | grep -E ":(7000|23500|$PREDICT_PORT)\b" | awk '{print "  "$4}'
echo "[09] Flow API check:"
curl -sf --noproxy 127.0.0.1 "$FLOW_API/flows" >/dev/null && echo "  GET /flows OK" || echo "  GET /flows not responding yet"
