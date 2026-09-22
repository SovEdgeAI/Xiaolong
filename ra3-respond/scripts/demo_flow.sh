#!/usr/bin/env bash
# =====================================================================
# RA3 live end-to-end demo: push ONE alert through the whole pipeline
# and show the evidence at every stage — decision, MCP calls, Docker
# execution, and DB persistence. Meant to be run in front of an audience.
#
#   Usage:  ./scripts/demo_flow.sh [ATTACK_TYPE]
#   e.g.    ./scripts/demo_flow.sh SYN_Flood
# Requires the stack to be up:  docker compose up -d db mcp server
# =====================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

ATTACK="${1:-SYN_Flood}"
line() { printf '%s\n' "------------------------------------------------------------"; }
strip() { sed 's/[^[:print:]\t]//g'; }

echo "############################################################"
echo "#  RA3 Threat Response — end-to-end demo"
echo "#  one alert:  attack_type = $ATTACK"
echo "############################################################"

# Baselines so we only show NEW activity from this one alert.
MCP_BEFORE=$(docker compose logs mcp 2>/dev/null | wc -l)
EVLOG=$(mktemp)
docker events --filter type=container --filter image=ra3-executor:latest \
  --format '{{.Action}}  {{.Actor.Attributes.name}}' > "$EVLOG" 2>&1 &
EVPID=$!
sleep 1

echo
echo ">> STEP 1  An alert arrives — client reports it to  POST /report"
line
docker compose run --rm client python simulate.py --once --attack "$ATTACK" 2>&1 \
  | grep -vE "Container (ra3|Network|Volume)|^\s*$" | strip
line

sleep 2
kill "$EVPID" 2>/dev/null

echo
echo ">> STEP 2  RA3 server calls the MCP server (function calling over MCP)"
echo "   Each 'CallToolRequest' = one action the decision engine chose."
line
docker compose logs mcp 2>/dev/null | tail -n +"$((MCP_BEFORE+1))" \
  | grep -E "CallToolRequest|POST /mcp/ HTTP" | strip
line

echo
echo ">> STEP 3  The MCP server ran each action in a throwaway Docker container"
echo "   Lifecycle per action:  create -> start -> die -> destroy  (--rm)."
line
cat "$EVLOG"
rm -f "$EVLOG"
line

echo
echo ">> STEP 4  The decision + execution result was persisted in PostgreSQL"
line
docker compose exec -T db psql -U ra3 -d ra3db -c \
"SELECT i.attack_type, i.severity, i.status,
        jsonb_array_length(r.selected_actions)  AS actions_chosen,
        jsonb_array_length(r.execution_results) AS actions_executed
 FROM incidents i JOIN responses r ON r.incident_id = i.id
 ORDER BY i.created_at DESC LIMIT 1;"
line

echo
echo ">> VERDICT — the pipeline is healthy if:"
echo "   [STEP 1] actions were chosen AND every execution status = success"
echo "   [STEP 2] one CallToolRequest appears per chosen action"
echo "   [STEP 3] one create->start->die->destroy set appears per action"
echo "   [STEP 4] status = resolved AND actions_chosen == actions_executed"
