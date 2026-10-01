# approach2 on Docker

The scripts in `../bash_scripts` assume libvirt VMs (`virsh`), host-installed
`p4c` / `stratum_bmv2` / `mvn` / ONOS-from-source, and passwordless `sudo`.
None of that is available on this host, but Docker is usable without `sudo`,
so these scripts run the same topology in containers.

Run everything with:

```bash
./run_all.sh
```

## Mapping to the upstream README

| Upstream step | Here |
|---|---|
| 1-2 `createveth.sh`, 4 `get_arp.sh` | `01_create_network.sh` |
| 3 `start_approach2_vms.sh` (virsh), 6 `arp.sh` | `03_start_containers.sh` |
| 5 `compile_p4.sh` / `generate_pipe.sh` / `run_stratum.sh` | `04_start_stratum.sh` |
| 7 `start_onos.sh` (bazel) | `05_start_onos.sh` |
| 8 `generate_netcfg.sh` + `upload_onos.sh` | `06_deploy_app.sh` |
| 11-12 Open5GS CP + UPF | `02_gen_configs.sh`, `07_start_core.sh` |
| 13 UERANSIM gNB + UE | `08_start_ran.sh` |
| 9, 10, 15 log server / flow API / ML | `09_start_services.sh` |

The P4 program is **not** recompiled: `p4c` is not installed, and the committed
`p4-code/onos-p4-gtp.json` and `.p4info.txt` already match the `.p4` source, so
they are used as-is.

## Topology

`chassis-config.txt` and the `ipv4_check` const entries in `onos-p4-gtp.p4` fix
the port assignment, so these addresses are not free choices:

| s1 port | host veth | peer | container | address |
|---|---|---|---|---|
| 0 | veth0 | veth1 | cp-2 | 192.168.235.2 — SBI/NRF, AMF NGAP |
| 1 | veth2 | veth3 | cp-2 | 192.168.235.3 — SMF PFCP/GTP-C |
| 2 | veth4 | veth5 | up-2 | 192.168.235.4 — UPF PFCP/GTP-U |
| 3 | veth6 | veth7 | gnb-2 | 192.168.235.5 |
| 4 | veth8 | veth9 | ue-2 | 192.168.235.6 |
| 5 | veth10 | veth11 | `br-p4-onos` | 192.168.235.1 — uplink (default) |

GTP-U between gnb-2 and up-2 crosses the switch, which is what the pipeline
parses. Containers also keep a Docker `eth0` for apt and for the UPF's
post-decapsulation egress.

## Notes

* **Static ARP is mandatory.** `onos-p4-gtp.p4` only applies tables when
  `hdr.ipv4` is valid, so ARP frames get no egress port and are dropped. Both
  the containers and the host (`br-p4-onos`) get pinned neighbour entries.
* **Coexists with approach1**, which is running on this host: different subnet
  (235 vs 230), a separate subscriber DB (`open5gs_a2`), and the prediction
  service on 5501 because approach1 holds 5500.
* **ONOS caches bundles by version.** After changing Java, re-run
  `05_start_onos.sh` before `06_deploy_app.sh`, or the old `.oar` stays active.
* **`06` builds out-of-tree** in `run/build/`. `mvn clean` is required, but
  `onos_app/approach2/target/` is committed to git, so cleaning in place would
  delete tracked files on every deploy.

## Ports

| Port | Service |
|---|---|
| 50001 | stratum_bmv2 P4Runtime |
| 8181 / 8101 | ONOS REST+GUI / Karaf SSH (`onos`/`rocks`) |
| 7000 | `logserver.py` |
| 23500 | flow REST API (`mongodb-app`) |
| 5501 | `GetPredictionModule.py` (upstream default 5500) |
| 27017 | MongoDB (`mongo-container`; `open5gs_a2`, `onos-p4-flows`) |
