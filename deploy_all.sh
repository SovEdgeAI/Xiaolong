#!/usr/bin/env bash
# deploy_all.sh — bring up the 5G testbed, then RA3 wired to it.
#
# NOTE: the testbed bring-up is environment-sensitive (built on Docker Desktop /
# WSL2, needs the SCTP kernel module and the Docker-VM network namespace). Review
# the 5g-testbed/ scripts before running on a different host. This script is a
# best-effort orchestration; run the steps individually if one fails.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TB="$HERE/5g-testbed"
RA3="$HERE/ra3-respond"

echo "==> [1/4] 5G testbed: core + RAN + SDN"
cd "$TB"
for s in 00_prereqs 01_create_network 02_gen_configs 03_start_containers \
         04_start_stratum 05_start_onos 06_deploy_app 07_start_core \
         08_start_ran 09_start_services; do
  f="approach2/docker_scripts/${s}.sh"
  [ -x "$f" ] && { echo "   -> $f"; "./$f" || echo "   (step $s returned non-zero; continuing)"; }
done

echo "==> [2/4] victim + second (legitimate) UE + enforcement agent"
[ -x victim/start_victim.sh ]   && ./victim/start_victim.sh
[ -x victim/start_good_ue.sh ]  && ./victim/start_good_ue.sh
[ -x agent/start_agent.sh ]     && ./agent/start_agent.sh
[ -x tools/testbed_autonomy.sh ] && ./tools/testbed_autonomy.sh off   # RA3 is sole decider

echo "==> [3/4] RA3 (decide + enforce), wired to the testbed agent"
cd "$RA3"
[ -f .env ] || cp .env.example .env 2>/dev/null || true
EXECUTOR_MODE=testbed AGENT_URL=http://172.17.0.1:8090 TESTBED_UE_IP=10.45.0.3 \
  WITH_JEV=true LLM_MODEL=anyjev JEV_MODEL=Qwen/Qwen3-4B JEV_EXPLAIN=false \
  docker compose up -d --build

echo "==> [4/4] health"
sleep 4
curl -s -m 5 http://localhost:8000/health || echo "(RA3 not ready yet)"
echo
echo "Done. Submit an alert:  curl -X POST http://localhost:8000/report -d '{...}'"
