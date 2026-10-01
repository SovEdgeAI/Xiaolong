#!/bin/bash
# start_ddos_detection.sh - Start the DDoS detection pipeline
# Run with: sudo bash start_ddos_detection.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RYU_PYTHON="/home/herman/miniconda3/envs/ryu-env/bin/python"
RYU_MANAGER="/home/herman/miniconda3/envs/ryu-env/bin/ryu-manager"

echo "============================================"
echo " Starting DDoS Detection Pipeline"
echo "============================================"

# Step 1: Set OVS controller
echo ""
echo "[1] Setting OVS controller to RYU (127.0.0.1:6633)..."
ovs-vsctl set-controller br-ovs-ryu tcp:127.0.0.1:6633
ovs-vsctl set bridge br-ovs-ryu protocols=OpenFlow13
echo "  ✓ OVS controller configured"

# Step 2: Start Node.js Flow API (port 23000)
echo ""
echo "[2] Starting Node.js Flow API (port 23000)..."
pkill -f "node.*ovs-ryu-app.js" 2>/dev/null || true
sleep 1
cd "${SCRIPT_DIR}/approach1/mongodb-app"
nohup node ovs-ryu-app.js > /tmp/nodejs-flow-api.log 2>&1 &
NODEJS_PID=$!
sleep 2
if kill -0 $NODEJS_PID 2>/dev/null; then
    echo "  ✓ Node.js Flow API started (PID: $NODEJS_PID)"
    echo "    Log: /tmp/nodejs-flow-api.log"
else
    echo "  ✗ Node.js Flow API failed to start!"
    cat /tmp/nodejs-flow-api.log
    exit 1
fi

# Step 3: Start ML Module (port 5500)
echo ""
echo "[3] Starting ML Module (port 5500)..."
pkill -f "MLmodule.py" 2>/dev/null || true
sleep 1
cd "${SCRIPT_DIR}/approach1/ML"
nohup $RYU_PYTHON MLmodule.py > /tmp/ml-module.log 2>&1 &
ML_PID=$!
sleep 2
if kill -0 $ML_PID 2>/dev/null; then
    echo "  ✓ ML Module started (PID: $ML_PID)"
    echo "    Log: /tmp/ml-module.log"
else
    echo "  ✗ ML Module failed to start!"
    cat /tmp/ml-module.log
    exit 1
fi

# Step 4: Start RYU Controller
echo ""
echo "[4] Starting RYU Controller (port 6633)..."
pkill -f "ryu-manager" 2>/dev/null || true
sleep 1
cd "${SCRIPT_DIR}/approach1/ryu_app"
nohup $RYU_MANAGER ovs-ryu-app.py > /tmp/ryu-controller.log 2>&1 &
RYU_PID=$!
sleep 3
if kill -0 $RYU_PID 2>/dev/null; then
    echo "  ✓ RYU Controller started (PID: $RYU_PID)"
    echo "    Log: /tmp/ryu-controller.log"
else
    echo "  ✗ RYU Controller failed to start!"
    cat /tmp/ryu-controller.log
    exit 1
fi

# Step 5: Start Stats Module
echo ""
echo "[5] Starting Stats Module..."
pkill -f "stats.py" 2>/dev/null || true
sleep 1
cd "${SCRIPT_DIR}/approach1/ML"
nohup $RYU_PYTHON stats.py > /tmp/stats-module.log 2>&1 &
STATS_PID=$!
sleep 2
if kill -0 $STATS_PID 2>/dev/null; then
    echo "  ✓ Stats Module started (PID: $STATS_PID)"
    echo "    Log: /tmp/stats-module.log"
else
    echo "  ✗ Stats Module failed to start!"
    cat /tmp/stats-module.log
fi

# Step 6: Start Detection Module
echo ""
echo "[6] Starting Detection Module..."
pkill -f "detection.py" 2>/dev/null || true
sleep 1
cd "${SCRIPT_DIR}/approach1/ML"
nohup $RYU_PYTHON detection.py > /tmp/detection-module.log 2>&1 &
DETECT_PID=$!
sleep 2
if kill -0 $DETECT_PID 2>/dev/null; then
    echo "  ✓ Detection Module started (PID: $DETECT_PID)"
    echo "    Log: /tmp/detection-module.log"
else
    echo "  ✗ Detection Module failed to start!"
    cat /tmp/detection-module.log
fi

echo ""
echo "============================================"
echo " DDoS Detection Pipeline Running!"
echo "============================================"
echo ""
echo " Components:"
echo "   Node.js Flow API : port 23000 (PID: $NODEJS_PID)"
echo "   ML Module        : port 5500  (PID: $ML_PID)"
echo "   RYU Controller   : port 6633  (PID: $RYU_PID)"
echo "   Stats Module     : polling    (PID: $STATS_PID)"
echo "   Detection Module : polling    (PID: $DETECT_PID)"
echo ""
echo " Logs:"
echo "   tail -f /tmp/ryu-controller.log"
echo "   tail -f /tmp/nodejs-flow-api.log"
echo "   tail -f /tmp/ml-module.log"
echo "   tail -f /tmp/stats-module.log"
echo "   tail -f /tmp/detection-module.log"
echo ""
echo " Test DDoS detection:"
echo "   docker exec ue-1 ping -I uesimtun0 -c 10000 -i 0.000001 8.8.8.8"
echo ""
