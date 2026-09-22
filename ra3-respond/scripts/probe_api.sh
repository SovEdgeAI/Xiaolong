#!/usr/bin/env bash
# Quick health probe for the configured OpenAI-compatible LLM provider.
# Usage:
#   OPENAI_API_KEY=sk-... ./scripts/probe_api.sh
# or it will read OPENAI_API_KEY / OPENAI_BASE_URL / LLM_MODEL from ../.env
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$HERE/../.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source "$HERE/../.env"; set +a
fi

: "${OPENAI_API_KEY:?set OPENAI_API_KEY (in .env or env)}"
BASE_URL="${OPENAI_BASE_URL:-https://huodingai.com/v1}"
MODEL="${LLM_MODEL:-gpt-5.5}"

echo "Provider : $BASE_URL"
echo "Model    : $MODEL"
echo

echo "[1/3] GET /models ..."
curl -s -m 20 -o /dev/null -w "  HTTP %{http_code}\n" \
  "$BASE_URL/models" -H "Authorization: Bearer $OPENAI_API_KEY"

echo "[2/3] POST /responses (plain) ..."
curl -s -m 90 -w "\n  HTTP %{http_code}  time=%{time_total}s\n" \
  "$BASE_URL/responses" \
  -H "Authorization: Bearer $OPENAI_API_KEY" -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"input\":\"Reply with the single word OK.\"}" | head -c 600
echo

echo "[3/3] POST /responses (with a function tool) ..."
curl -s -m 120 -w "\n  HTTP %{http_code}  time=%{time_total}s\n" \
  "$BASE_URL/responses" \
  -H "Authorization: Bearer $OPENAI_API_KEY" -H "Content-Type: application/json" \
  -d "{
    \"model\": \"$MODEL\",
    \"instructions\": \"You are a security engine. Always call log_incident.\",
    \"input\": \"SYN_Flood on bs_node_01, severity critical, half_open_connections=48000, incident_id=abc.\",
    \"tools\": [
      {\"type\":\"function\",\"name\":\"enable_syn_cookie\",\"description\":\"Enable SYN cookie\",\"parameters\":{\"type\":\"object\",\"properties\":{\"client_id\":{\"type\":\"string\"}},\"required\":[\"client_id\"]}},
      {\"type\":\"function\",\"name\":\"log_incident\",\"description\":\"Log incident\",\"parameters\":{\"type\":\"object\",\"properties\":{\"incident_id\":{\"type\":\"string\"},\"action_taken\":{\"type\":\"string\"}},\"required\":[\"incident_id\",\"action_taken\"]}}
    ],
    \"tool_choice\": \"auto\"
  }" | head -c 1500
echo
echo
echo "Success looks like: all three return HTTP 200, and step [3] output contains"
echo "one or more items with \"type\":\"function_call\" (e.g. enable_syn_cookie, log_incident)."
