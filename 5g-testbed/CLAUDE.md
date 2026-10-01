# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A research testbed (IEEE paper 10639648) comparing two SDN approaches to detecting and
mitigating GTP-U flooding from a malicious UE in a 5G network. Both approaches run a real
5G stack — Open5GS core, UERANSIM gNB/UE, MongoDB subscriber DB — and differ only in the
switch and controller:

| | Approach 1 (baseline) | Approach 2 (optimized) |
|---|---|---|
| Switch / controller | OVS + RYU | P4 `stratum_bmv2` + ONOS |
| Subnet / bridge | 192.168.230.0/24, `br-ovs-ryu` | 192.168.235.0/24, `br-p4-onos` |
| Flow REST API | 23000 | 23500 |
| Prediction service | 5500 | 5501 here (upstream 5500) |
| Mongo flow DB | `ovs-ryu-flows` | `onos-p4-flows` |

**Both run concurrently on this host.** They are isolated by subnet, container name suffix
(`-1` vs `-2`), Mongo database, and port. Do not "clean up" one while working on the other.

## This host differs from the upstream README

The READMEs assume libvirt VMs (`virsh`), host-installed `p4c` / `stratum_bmv2` / `mvn` /
ONOS-built-from-bazel, and passwordless `sudo`. **None of that exists here.** `sudo` requires
a password, but Docker works without it, so everything runs in containers — privileged
`--network=host` containers stand in for host root when creating veths, bridges, netns moves
and iptables rules.

Treat `approach2/docker_scripts/` (and `start_ddos_detection.sh` for approach1) as the real
entrypoints; `approach2/bash_scripts/` is upstream reference that will not run as written.
`approach2/docker_scripts/README.md` maps each upstream README step to its replacement.

The P4 program **is** recompiled, in the `p4lang/p4c` container (no host `p4c`):

```bash
docker run --rm -v "$PWD":/src:ro -v /tmp/out:/out p4lang/p4c:latest sh -c \
  'p4c -b bmv2 --p4runtime-files /out/onos-p4-gtp.p4info.txt -o /out /src/onos-p4-gtp.p4'
cp /tmp/out/onos-p4-gtp.json approach2/p4-code/onos-p4-gtp.json          # bmv2 JSON, copied as-is
python3 approach2/docker_scripts/p4info_downgrade.py /tmp/out/onos-p4-gtp.p4info.txt \
  approach2/p4-code/onos-p4-gtp.p4info.txt      # p4info, MUST go through this
```

Then `04_start_stratum.sh` (reloads the pipeline), `05_start_onos.sh`, `06_deploy_app.sh`,
and re-register the UE. The bmv2 JSON format version is unchanged (`[2, 23]`), so only the
p4info needs the treatment below.

Do not pass `--user` to that container; p4c reads `/root/.local/bin` and fails.

**The downgrade step is not optional.** A current `p4c` emits `initial_default_action`,
`has_initial_entries` and a `# proto-file:` header that ONOS 2.2.2's P4Info protobuf does
not know. Text-format parsing is strict, so the pipeconf silently fails to register and the
only symptom is `pipeconf us.fiu.adwise.approach2 not registered` with `device:s1` stuck in
CONNECTION_SETUP. `p4info_downgrade.py` strips exactly those; it is validated by the fact
that it reproduces the committed P4Info byte-for-byte from an unmodified recompile.

## Commands

```bash
# Approach 2 — full stack, dependency-ordered, idempotent
cd approach2/docker_scripts && ./run_all.sh

# Approach 1
sudo bash start_ddos_detection.sh

# Validate the data path (both)
docker exec ue-2 ping -I uesimtun0 -c 4 8.8.8.8

# DDoS test
docker exec ue-2 ping -I uesimtun0 -c 10000 -i 0.000001 -q 8.8.8.8

# Detection / mitigation state
tail -f approach2/docker_scripts/run/logs/getdbdata.log     # LR/NB predictions
curl -s --noproxy '*' http://127.0.0.1:23500/blocked-ips
curl -s -u onos:rocks --noproxy localhost http://localhost:8181/onos/v1/flows/device:s1

# Block / rate-limit through one control point (picks the mechanism; see tools/README.md)
tools/enforce.py block --ue 10.45.0.3          # also: limit --flow/--ue/--tunnel/--imsi, clear, status
tools/enforce.py status

# Replay any pcap (e.g. a downloaded DDoS dataset) through the approach2 5G path
tools/replay_pcap.sh datasets/samples/synthetic_syn_flood_ethernet.pcap --loop 40

# Bandwidth-control experiments (see "QoS / bandwidth control" below)
cd experiments/bandwidth-control
./expA_sdn_meter.sh      # OpenFlow meter from the Ryu app, approach1
./expB_core_ambr.sh      # Session-AMBR in MongoDB, no SDN involvement
./expC_p4_per_flow.sh    # per-flow meter in the P4 pipeline, approach2
./expD_core_pcc.sh       # per-flow PCC rule via the core: provisioned, transported, NOT enforced (2.4.0)
./expE_ovs_shaping.sh    # OVS tc ingress policing vs HTB queue + set_queue, approach1
```

There is no test suite, linter, or CI. Verification is behavioural: ping through the tunnel,
then inspect flow tables and the blocked-IP list.

The Python services need `joblib`/`sklearn`, which only exist in the
`/home/herman/miniconda3/envs/ryu-env` interpreter — not the default `python3`.

Individual approach2 steps can be re-run standalone (`./04_start_stratum.sh`, etc.), but
mind the ordering constraints documented at the top of `run_all.sh`: removing a container
destroys the veth pair whose peer it holds, so `01` must precede `03`, and `03` must precede
`04` (stratum binds the host-side veths at startup).

## Architecture: the detection loop (approach2)

Understanding this requires reading `onos-p4-gtp.p4` alongside the ONOS app, so it is
summarized here.

`IngressPipeImpl.apply` only acts when `hdr.ipv4` is valid, with initial flags
`pass=true, acl=false`:

1. `gtp_check` — const-matches UDP 2152↔2152, sets `gtp=true, acl=true, pass=false`.
2. `dropped_inner_ipv4` — exact match on **inner** source IP → `drop`. This is the
   mitigation table.
3. `gtp_flows` — exact match on inner (src, dst, proto); `track_gtp_flows(index)` sets
   `pass=true`, releasing the packet to forwarding, and executes this flow's cell of the
   `gtp_flow_meter` indirect meter. A RED colour drops the packet — see QoS below.
4. `ipv4_check` — forwards on outer destination IP.
5. `acl_table` — default `send_to_cpu`, so an *unknown* GTP flow is punted to ONOS.

So a new GTP flow hits the CPU, `CreateGTPFlows` installs a `gtp_flows` entry plus a
record in the flow REST API, and subsequent packets forward in the data plane.
`UpdateFlowStats` pushes each entry's lifetime counters to the API every tick.
`getDBData.py` polls `/unidirectionalFlows`, scores each with LogisticRegression +
GaussianNB, and writes predictions back; the API flags a source after **5 consecutive**
attack votes from **both** models; `DetectionModule` polls `/flaggedIps/top` every 5 s and
POSTs it to `/blocked-ips`. Measured detection-to-drop: ~40 s.

**`/blocked-ips` is the source of truth for blocking.** `MitigationModule` reconciles the
switch against it every 5 s — installing missing `dropped_inner_ipv4` rules and removing
stale ones — comparing against what ONOS actually holds (`getFlowEntriesById`), not what it
remembers sending. So a manual `POST /blocked-ip/<ip>` blocks, `DELETE /blocked-ips/<ip>`
unblocks, and blocks survive an ONOS restart. Unblocking cleanly needs more than the
DELETE (see gotchas) — use `tools/enforce.py clear --ue`.

**Forward = uplink (UE → DN), always.** Flow records are oriented by the UE pool
(`10.45.0.0/16`, `UE_POOL_PREFIX` in the flow API), and only a UE address can be
auto-flagged: the drop rule matches the inner *source*, so flagging a DN address would cut
its downlink to every UE. Manual blocks of a non-UE address are still allowed.

**Consequences worth knowing:**

- **`ipv4_check` has `const entries`** mapping `192.168.235.2–.6` to ports 0–4, default
  port 5. The addresses in `chassis-config.txt`, the Open5GS configs and the container
  wiring are therefore fixed by the P4 source — changing an IP means editing the `.p4`
  and recompiling.
- **ARP is dropped** (never valid IPv4), so every node needs pinned neighbour entries —
  including the *host* on `br-p4-onos`, without which the core cannot reach MongoDB.
  Handled in `01_create_network.sh` and `03_start_containers.sh`.
- **GTP-U will not flow until ONOS is up with the app active**, because unknown flows
  are punted, not forwarded. The core must start after the controller.

## QoS / bandwidth control

Separate from DDoS detection, the repo now carries three *measured* ways to cap a UE's
throughput. They are not interchangeable — they differ in granularity, and that is the
point of having all three:

| | Where the logic lives | Kind | Granularity | Measured ratio |
|---|---|---|---|---|
| A | `approach1/ryu_app/ovs-ryu-app.py` (OpenFlow meter) | policer | the whole gNB↔UPF tunnel | **0.47×** of setpoint |
| E1 | OVS `Interface.ingress_policing_rate` (tc policer) | policer | the whole tunnel | **0.48–0.55×** |
| E2 | OVS `QoS linux-htb` + `Queue max-rate`, steered by OpenFlow `set_queue` | shaper | the whole tunnel | **0.93–1.02×** |
| B | MongoDB subscriber record → UDM → SMF → UPF (PFCP QER) | shaper | one PDU session / subscriber | **1.09–1.17×** |
| C | `onos-p4-gtp.p4` + `QoSMeterModule.java` | policer | one GTP inner-IP flow | **0.59–0.81×** |
| D | subscriber `pcc_rule` → PCF → SMF → UPF | — | one SDF (5-tuple) | **no effect** in Open5GS 2.4.0 |

The ratio follows the *kind*, not the layer: both policers land at half the setpoint, both
shapers on it. "OpenFlow can't enforce accurately" is therefore false — use a queue, not a
meter, when accuracy matters (E2 is still SDN-driven: the controller picks the queue).

**D is a version finding, established by capture, not a 3GPP limit.** The N7
`SmPolicyDecision` (`results/expD_n7.pcap`) carries the rule correctly — `pccRules`,
`flowInfos`, `qosDecs` with `maxbrUl/Dl` — but the PFCP Session Establishment the SMF then
sends (`expD_pfcp.pcap`, decoded in `expD_pfcp_summary.txt`) contains only the default
PDRs and the single session-AMBR QER. The SMF drops the rule at session creation, so
neither MBR nor `flow_status=DISABLED` (gate closed) reaches the UPF. Check newer Open5GS
releases before asserting either "the core can" or "the core cannot" do per-flow control.

**Do not repeat the claim that bandwidth control isn't an AMF/SMF function.** Open5GS
compiles QER support, the subscriber records carry AMBR, and B tracks its setpoint *more*
accurately than the SDN meter — it needs no new code at all, only a field change plus a UE
re-registration (AMBR is applied at session establishment, never renegotiated mid-session).

**A is tunnel-wide, not per-flow.** OVS has no GTP parser: `gtp_teid` is not a match field
(`ovs-ofctl: unknown keyword gtp_teid`) and the inner IP is opaque payload. The outer
5-tuple is identical for every UE and session. With a single UE it merely *looks* per-flow.

**C is the only per-flow mechanism that works on this testbed** (D shows why the core's
own per-flow path does not, here). `gtp_flows` already keys on inner (src, dst, proto),
so an indirect meter attached to it gives one cell per flow. `CreateGTPFlows` allocates a
cell per direction and logs `QoS: flow <src>-<dst>-<proto> -> meter cell N`;
`QoSMeterModule` writes the rate over P4Runtime. Control surface is two files inside the
ONOS container, polled once a second:

```bash
docker exec onos sh -c 'echo 4 > /tmp/qos_meter_index; echo 10000 > /tmp/qos_rate_kbps'
docker exec onos sh -c 'echo all > /tmp/qos_meter_index; echo 0 > /tmp/qos_rate_kbps'  # clear
```

A drop-band meter is a *policer*, not a shaper: it discards instead of queueing, so TCP
backs off and achieved throughput sits below the setpoint. That is expected, not a bug —
the A and C ratios above are this effect, and B tracks better because the UPF shapes.

Approach1's Ryu app also exposes the meter over REST (`PUT /qos/meter/<kbps>`,
`DELETE /qos/meter` on :8080) and honours `RYU_BOOTSTRAP_FLOWS=0` to skip the `sudo`
flow-install block when running unprivileged.

**`expA_sdn_meter.sh` has a setup step it does not perform itself.** The packaged Ryu runs
as root on 6633 and cannot be killed without `sudo`, so run a second, unprivileged instance
and point OVS at it. Restore 6633 and `cookie=0x1` afterwards, or approach1's detection
stays disabled:

```bash
cd approach1/ryu_app
RYU_BOOTSTRAP_FLOWS=0 PYTHONUNBUFFERED=1 setsid nohup \
  ~/miniconda3/envs/ryu-env/bin/ryu-manager \
  --ofp-tcp-listen-port 6634 --wsapi-port 8080 ovs-ryu-app.py >/tmp/ryu-qos.log 2>&1 </dev/null &

# in a privileged container with /var/run/openvswitch mounted:
ovs-vsctl set-fail-mode br-ovs-ryu secure     # BEFORE repointing; see gotchas
ovs-vsctl set-controller br-ovs-ryu tcp:127.0.0.1:6634
ovs-ofctl -O OpenFlow13 del-flows br-ovs-ryu "cookie=0x1/-1"   # drop the CONTROLLER punt
```

To stop that instance, match a pattern that does not also match your own command line —
`pkill -f 'ryu-manager.*66[3]4'`, in a call that contains no literal `6634`.

### Measuring throughput

- The iperf3 server is the `dn-iperf` container on `--network=host`, port 5201.
- **Pick a DN address the UE routes through the tunnel.** `ue-1` has
  `0.0.0.0/1 dev uesimtun0` so most destinations tunnel, but `192.168.230.0/24` does not —
  use `172.17.0.1`. `ue-2` has *no* tunnel routes at all and a direct `172.17.0.0/16` on
  eth0, so pin the DN explicitly: `ip route replace 192.168.230.1/32 dev uesimtun0`.
  Get this wrong and traffic never reaches the switch, silently.
- **Never hardcode the UE tunnel IP** — it changes on every re-registration. Read it from
  `uesimtun0`.
- Approach1 (~1.1 Gbit/s, OVS kernel datapath) and approach2 (~52 Mbit/s, `stratum_bmv2`
  software switch) are **not comparable in absolute terms** — only their tracking behaviour is.
- iperf3's UDP mode fails over this tunnel (`unable to read from stream socket`) even at
  2 Mbit/s, while raw UDP via netcat passes. Use TCP.
- **pcap replay works** through the tunnel: capture on `uesimtun0` (link-type RAW), filter
  to the direction you want, rewrite the source to the UE's *current* tunnel IP, and
  `tcpreplay -i uesimtun0` it. 50 replayed packets produced 51 uplink GTP-U packets on the
  switch port. `ue-2` has `tcpdump tcpreplay python3-scapy` installed; the UE images ship
  none of them. Multi-UE: `nr-ue -n <count>` plus one subscriber record per IMSI. Adding a
  *node* in approach2 means a veth pair, a chassis entry, and a P4 recompile, because
  `ipv4_check` is `const entries`.
- Two privileged helper containers exist so nothing needs host sudo: `ovs-tools` (OVS CLI +
  tcpdump on the host netns) and the `nettools:local` image for `--net container:<x>`
  captures inside a container's namespace (used for the N7/PFCP captures).

## Evaluating against real DDoS captures (`experiments/pcap-replay/`)

`tools/fetch_stopddos.sh` pulls six real attack captures (StopDDoS collection, git-ignored,
cite Haaijer 2022); `experiments/pcap-replay/run_all.sh` replays each through approach 2 in
two threat models and writes `results/replay.csv`. See that directory's README for the
column meanings. Defensive evaluation — recorded attack traffic driven at the defender to
measure detect/block/mitigate.

Two modes, because source-cardinality decides everything: **`ue`** (all traffic from the
compromised UE's address — the paper's model; every capture becomes one flow that is
detected, blocked, and mitigated, `veth6`-in vs `veth4`-out ≈ N/1) and **`spoof`** (keep
each original source — a stress test).

**The 5G user plane wedges under sustained replay, and it fails silently.** After a
high-cardinality spoofed run, the UE keeps reporting a healthy session — `CM-CONNECTED`,
`MM-REGISTERED/NORMAL-SERVICE`, `PS-ACTIVE`, `uesimtun0` up — while `nr-ue` accepts packets
on the TUN and transmits **nothing**: no RLS on the UE's switch port, no GTP-U at the gNB.
Restarting `nr-ue`, `nr-gnb`, `open5gs-smfd` and `open5gs-upfd` individually does *not* fix
it (in one instance `open5gs-amfd` had also died and needed restarting first). What fixes it
is a full rebuild — `07_start_core.sh` then `08_start_ran.sh`, or `run_all.sh`.

This matters because it *looks* like a detection failure: the harness records
`gtp_flows=0, blocked=0` for every capture and the defense appears to miss everything. It
invalidated 10 of 12 rows in the first suite. `run_capture.sh` now preflights the data path
with a test ping and aborts (exit 2) rather than recording zeros. **Any row with
`gtp_flows_peak=0` and `leak=n/a` is a broken-testbed artefact, not a result.**

Findings that corrected read-only assumptions:
- **`gtp_flows` does not cap at 1024.** A 37,623-source spoofed flood grew it to ~58k
  entries; `stratum_bmv2` expands the table rather than rejecting inserts. So the limit is
  memory/packet-in load, not a fixed table size — and ONOS *survived* the flood (still
  `available`, detector still up). The design's real weakness against high-cardinality
  spoofed floods is that per-source detection needs 5 consecutive samples from one source,
  so ~1-packet-per-source attacks are never flagged — not a crash.
- `first_block_s` in the CSV is only meaningful cold: back-to-back runs share ONOS's
  in-memory `flaggedIps`/block state and block within one poll. Cold-start latency is ~45 s.

## Detector accuracy — known false positives

The shipped models flag more than floods. Observed on this testbed: a 20-pps benign ICMP
host, a 5-packet flow idle for an hour, and a legitimate iperf3 TCP transfer were each
auto-blocked. Likely causes: the features are *lifetime* counters rather than windowed
rates, and the models' training data is unknown (no script or dataset in the repo; the
approach1 and approach2 models are the same files). Treat detections as candidates, not
ground truth, and exclude measurement traffic (e.g. unblock `ue-2` after iperf3 runs). A
retrain on windowed features against a labelled dataset is the real fix.

## Gotchas that have already cost time

- **Unblock order matters.** Reset first, release last: delete the IP's flags, its
  `gtp_flows` entries (their counters are lifetime totals) and its flow records *while the
  drop rule still holds*, then DELETE the block. Releasing first let stale 5-of-5 votes
  re-flag the idle host within one cycle; keeping the switch entries let `UpdateFlowStats`
  rebuild a "new" flow already carrying the whole attack. `enforce.py clear --ue` does it
  in the right order.
- **Periodic tasks must survive a failed call.** `getDBData.py` did one bare
  `requests.get` and died on the first refused connection (i.e. any flow-API restart),
  while its log still looked normal. It now retries. Java `ScheduledExecutorService` tasks
  are cancelled permanently by one uncaught exception — same risk in the ONOS modules.
- **Flow-record orientation used to be arrival order.** When records are recreated from
  existing switch rules (after a DB wipe/loss) `UpdateFlowStats` walks `gtp_flows` in
  arbitrary order, and ~half came back inverted: the detector scored the silent reply leg
  and the flag landed on the DN. Fixed in `PUT /flow/:id`; do not revert to "first seen =
  forward".
- **GTP-U here carries the PDU Session Container extension** (flag `E=1`), so the inner IP
  starts at byte 58 of the frame and the inner source is at **byte 70**, not 62. BPF on a
  switch port: `udp port 2152 and ether[70:4]=0x0a2d0003` matches inner src 10.45.0.3.
- **`dropped_inner_ipv4` has no counter** in the P4 program, so ONOS reports 0 packets for
  every drop rule. Measure drops on the wire (packets from the source on `veth6`, gNB side,
  versus `veth4`, UPF side).
- **`05_start_onos.sh` waits for `drivers.stratum` ACTIVE**, not just :8181. The REST API
  answers well before the drivers load, and deploying into that window loses the app
  silently — the device then never appears.
- **Express matches the first registered route.** The flow API had both
  `DELETE /unidirectionalFlows/:id` and `/:ip`; the second was unreachable and the first
  hung the client on a miss. Now one handler accepting either. Keep route params distinct.
- **approach1's ML server read requests before the body arrived** (stopped at the header
  terminator; `requests` sends the body separately), so every prediction returned 500.
  Fixed in `MLmodule.py` and `GetPredictionModule.py` by honouring `Content-Length`. The
  packaged root-owned instance on :5500 still runs the old code (needs sudo to restart);
  a fixed instance runs on **:5502** with `stats.py` pointed at it via `ML_URL`.

- **The `track_gtp_flows` index parameter must stay `bit<8>`.** ONOS 2.2.2 stores action
  parameters padded to their declared width; Stratum reads them back in P4Runtime canonical
  (minimal) form; ONOS compares the two byte-for-byte when reconciling. With `bit<32>` every
  `gtp_flows` entry sat in `PENDING_ADD` forever, its counters read zero, the flow API
  computed NaN rates, and `getDBData.py` crashed on the first `sklearn` call — the whole
  detection loop dead, with traffic still forwarding normally. At 8 bits the padded and
  canonical forms coincide for every value. Symptom to grep for in `docker logs onos`:
  `is different from one in in translation store`. Client-side re-encoding does not fix it.
- **MongoDB's `192.168.230.2` address is gone.** approach1 was built against Mongo on the
  docker `5g-network` bridge, but its containers are actually wired into OVS, and after the
  Mongo container crashed (SIGSEGV in its ftdc thread, 2026-09-23) and restarted only the
  published port remains reachable: `192.168.230.1:27017` from containers, `127.0.0.1:27017`
  from the host. `udrd`/`pcfd`/`bsfd` in cp-1 were restarted with `DB_URI` pointing there and
  `ovs-ryu-app.js` now takes `MONGO_URI`; the user's original `start_ddos_detection.sh` path
  would regress this. Do **not** re-attach Mongo to `5g-network` to "fix" it — that gives the
  host a second `192.168.230.0/24` segment and breaks return routing for approach1.
  `mongo-container` now has `--restart unless-stopped`.
- **`approach2/onos_app/approach2/target/` is committed to git.** `mvn clean` there deletes
  23 tracked files. `06_deploy_app.sh` builds out-of-tree in `run/build/` for this reason;
  keep it that way. `clean` itself is necessary — stale `approach4`-package `@Component`
  classes would otherwise be bundled into the `.oar` and ONOS would try to activate them.
- **ONOS caches OSGi bundles by version**, and the version string never changes. After
  editing Java, run `05_start_onos.sh` (recreates the container) *before* `06_deploy_app.sh`,
  or the old code stays live while the deploy reports success. The same staleness applies to
  reading `docker logs onos` — a pipeconf error only appears after a *clean* restart, so
  don't conclude a recompile is compatible from a log written by the previous instance.
- **`br-ovs-ryu` must stay `fail-mode=secure`.** With fail-mode unset (OVS default,
  standalone) OVS flushes the flow table when a controller connects. Pointing a new
  controller at the bridge therefore blackholes approach1 — and a sustained blackhole then
  kills `open5gs-amfd` and `nr-gnb`, which do **not** come back on their own. If approach1's
  tunnel is down, check those two processes before hunting a data-plane bug:
  `docker exec cp-1 sh -c "ps -eo comm | grep open5gs"` and `docker exec gnb-1 pgrep -x nr-gnb`.
- **Approach1's IP blocking does not actually block.** `ovs-ryu-app.py` installs
  `OFPMatch(in_port=...)` — whole-port, not per-IP — at priority 1, beneath the
  `priority=100 actions=NORMAL` catch-all that matches every packet, so it is unreachable;
  and the live GTP rule is `actions=CONTROLLER:65535,NORMAL`, so packets forward regardless
  of what the controller decides. Any new enforcement rule must sit **above priority 100**.
- **The `CONTROLLER:65535` punt ruins throughput measurements.** It copies every GTP packet
  to Ryu, which does a synchronous HTTP request per packet. Drop it to plain `NORMAL` while
  measuring, then restore `cookie=0x1`.
- **matplotlib is not installed** in any interpreter here, including `ryu-env`. Plot by
  publishing an Artifact with inline SVG/JS rather than generating a PNG.
- **Run Maven containers with `--user $(id -u):$(id -g)`**, or build output becomes
  root-owned and unfixable without sudo.
- **`open5gs-*d -D` daemonizes but keeps its stdout.** If that stdout is a pipe, the daemon
  dies of SIGPIPE when the reader exits. Always redirect to a file inside the container.
- **`pkill -f 'open5gs-'` / `pkill -f <script name>` matches the invoking shell** and kills
  it. Use `pkill -x <exact process name>`.
- **Open5GS honours the `DB_URI` environment variable over `db_uri` in the YAML**, and the
  `openverso/open5gs` image ships `DB_URI=mongodb://mongo/open5gs`. Override it per exec.
- **Python services buffer stdout into log files**; `PYTHONUNBUFFERED=1` is set in
  `09_start_services.sh` so an empty log does not look like a hang.
- `RandomForestClassifier.joblib` cannot be unpickled under sklearn 1.6.1 (stale format).
  Nothing loads it — only LogisticRegression, GaussianNB and the scaler are used.
- ONOS logs continuous `Unable to translate flow rule ... ICMPV6_TYPE` warnings from
  `hostprovider` installing IPv6 NDP rules the pipeline cannot express. Expected noise;
  upstream's `start_onos.sh` greps out exactly this message.

## Conventions

Service endpoints were originally hardcoded to the lab host `10.102.196.198`. They are now
configurable and default to localhost — keep new code configurable rather than reintroducing
literals:

- Java: `AppConstants.APP_HOST`, override with `-Dapproach2.host=<addr>`
- Node: `MONGO_URI`
- Python: `FLOW_API`, `PREDICT_PORT`, `ML_URL` (approach1 `stats.py`)
- Node: `UE_POOL_PREFIX` (default `10.45.`) — which addresses count as UEs
- Ryu: `RYU_BOOTSTRAP_FLOWS=0` to skip the `sudo ovs-ofctl` block at import
- Experiments: `UE`, `UE_ADDR`, `DN`, `RATE_KBPS`, `DURATION` on the `exp*.sh` scripts

Ports added alongside the ones in the table above: **8080** Ryu QoS REST (approach1),
**5201** `dn-iperf` measurement server, **6634** the unprivileged Ryu instance used for
QoS experiments (the packaged one from `start_ddos_detection.sh` runs as root on 6633).
