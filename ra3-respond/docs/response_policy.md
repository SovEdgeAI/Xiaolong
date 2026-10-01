# RA3 response policy (draft v0.3)

Labeling policy for the RA3 action decider: for one alert and one candidate
action, is the action **necessary**? Teacher models label training data with
it, and the rule voter in `scripts/jev_make_labels.py` implements it.

**Status: draft.** It condenses public guidance (sources below) into rules that
use only the fields RA1 sends today. It has not been reviewed by a network
security practitioner. Numbers marked *[assumption]* are placeholders chosen
for this prototype, not values taken from the sources; tune them for the real
network.

## Sources

- IETF RFC 4987, *TCP SYN Flooding Attacks and Common Mitigations*.
- CISA, FBI, MS-ISAC, *Understanding and Responding to Distributed
  Denial-of-Service Attacks*.
- NIST SP 800-61, *Incident Response Recommendations and Considerations for
  Cybersecurity Risk Management*.
- MITRE ATT&CK T1498 *Network Denial of Service*, T1499 *Endpoint Denial of
  Service*, T1046 *Network Service Discovery*, and their listed mitigations
  (e.g. M1037 *Filter Network Traffic*).

## General principles

1. **Proportionality.** Every action has side effects: blocking legitimate
   users, dropping federated-learning traffic, operator fatigue. Choose an
   action only if it directly counters the reported attack mechanism. Most
   alerts need one to three actions.
2. **Specific before generic.** Prefer the mitigation made for the attack
   class (SYN cookies for SYN floods, HTTP rate limiting for HTTP floods) over
   generic ones (CISA; RFC 4987).
3. **Blocking needs real, few sources.** Source-IP blocking only works when
   the sources are genuine and few. Spoofable or very numerous sources make
   block lists ineffective and risky (CISA; RFC 4987 on spoofed SYNs).
4. **Detection confidence matters.** At `detector_confidence < 0.6`
   *[assumption]* the alert may be a false positive: prefer the least
   disruptive action and do not escalate.
5. **Record and notify** (NIST SP 800-61). Every alert is logged; high and
   critical alerts reach an operator. These are code rules, not labels.

## Mandatory (not labeled)

| Action | Rule |
|---|---|
| `log_incident` | Always, executed last. |
| `alert_operator` | Always when severity is `high` or `critical`. |

## Per-action rules

Each rule states when the action is **necessary (Yes)**; otherwise the answer
is **No**. Fields refer to the alert's `metadata` unless named otherwise.

### `enable_syn_cookie` — SYN_Flood

SYN cookies let a server keep accepting connections while the half-open queue
is under attack, at low cost (RFC 4987).

- **Yes** unless the evidence is weak. The action is cheap, so a confirmed
  SYN flood warrants it even at low volume.
- **No** only if `half_open_connections < 1000` *[assumption]* **and**
  `syn_rate < 1000` per second *[assumption]* **and**
  `detector_confidence < 0.6`.

### Volumetric floods — block the source, or rate-limit if distributed

For SYN_Flood, ICMP_Flood, UDP_Flood and HTTP_Flood the decisive question is
**how many sources** the flood comes from:

- **Few identifiable sources** (`source count <= 20` *[assumption]*): **`block_ip`**
  is the effective mitigation — drop the attacker(s) at the switch. This stops
  the flood regardless of packet size.
- **Many / distributed sources** (`> 20`, e.g. a spoofed flood): you cannot
  block them all, so **`rate_limit`** is the best-effort fallback.

Source count comes from `unique_source_ips` / `source_ips` (default 1 when
absent — a single-source flood).

### `rate_limit` — ICMP_Flood, UDP_Flood (distributed only)

`rate_limit` applies an inbound packet-rate cap. **On this testbed it is a P4
byte-rate meter, which does NOT stop a small-packet flood** (high packet rate,
low bandwidth). So it is chosen only when the flood is distributed across too
many sources to block.

- **Yes** only when the flood has more than 20 sources *[assumption]* (cannot
  block them all).
- **No** for a few-source flood — use `block_ip` instead.

### `enable_http_rate_limit` — HTTP_Flood

Application-layer floods are absorbed at the WAF or reverse proxy by limiting
requests per client (CISA).

- **Yes** unless the evidence is weak.
- **No** only if `request_rate < 1000` requests per minute *[assumption]*
  **and** `detector_confidence < 0.6`.

### `set_connection_timeout` — Slowrate_DoS

Slow-rate attacks (Slowloris, Torshammer) hold connections open; shortening
the idle timeout evicts them (CISA, application-layer attacks).

- **Yes** if `avg_request_duration_s >= 30` *[assumption]* and
  `active_connections >= 500` *[assumption]*.
- **No** otherwise.

### `block_ip` — volumetric floods (few sources), and scans

- **HTTP_Flood.** HTTP needs a completed TCP handshake, so its sources are real.
  **Yes** if `unique_source_ips <= 20` *[assumption]*. **No** if more: this is a
  botnet, and rate limiting is the proportionate answer.
- **Scans.** **Yes** if `scanner_ip` is present and the scan comes from at most
  5 sources *[assumption]* (`source_ips <= 5`, or `source_ips` absent). **No**
  if `scanner_ip` is absent, or if the scan comes from more sources (a
  distributed or decoy scan, where blocking one address does little).

### `close_unnecessary_ports` — SYN_Scan, TCP_Connect_Scan, UDP_Scan

Reduce the attack surface once a scan shows it is being mapped (ATT&CK T1046
mitigations: disable unneeded services, filter traffic).

- **Yes** if the scan is broad, `ports_probed >= 1000` *[assumption]*, or if
  it found open services:
  - TCP_Connect_Scan: `completed_handshakes > 0`;
  - UDP_Scan: `ports_probed - icmp_unreachable_received > 0` (ports that did
    not answer "unreachable" may be open).
- **No** for a narrow scan (`ports_probed < 1000`) that found nothing open.

### `share_threat_intel` — all attack types

Share an indicator that peer nodes in the federation can act on.

- **Yes** if the alert carries a concrete, reusable indicator (`scanner_ip`
  is present) and `detector_confidence >= 0.8` *[assumption]*.
- **Yes** if severity is `critical` and `detector_confidence >= 0.9`
  *[assumption]* (likely a campaign that may hit peers).
- **No** otherwise. RA1 does not report whether other nodes see the same
  attack, so single-node alerts without an indicator are not shared.

### `alert_operator` — only asked for `low` / `medium` severity

- **Yes** if severity is `medium` and `detector_confidence >= 0.85`
  *[assumption]*.
- **No** for `low` severity, or `medium` with lower confidence: log only,
  to avoid alert fatigue.

## Known gaps

- RA1 does not send whether sources are spoofed, whether other nodes report
  the same attack, or which ports are open. Rules that need that information
  use proxies (source counts, `scanner_ip`, handshake and ICMP counts).
- Every threshold marked *[assumption]* should be replaced by values measured
  on the real network.
